"""敏感反馈脱敏版本服务。

每次脱敏都生成一条不可变的 RedactionVersion（裁剪文也按 sha256
内容寻址），版本切换只移动 versions.current_redaction_id 指针：

- 授权人（本机构管理员、权威机构、审计、有效分配的评审人）永远看原文，
  与是否存在脱敏版本无关；
- 普通成员（本机构提交人等）按“当前脱敏版本”看裁剪文；
- 评审包封存时把当时的当前脱敏版本固定进条目（pinned_redaction_id），
  此后再脱敏/再切换都不改变历史包里旧反馈的显示；草稿包跟随当前指针。

授权范围（scope）只在 SQLite 留存，身份→内容的选择由 Python 披露策略
完成（见 domain.disclosure）。
"""
from __future__ import annotations

from ..domain.disclosure import REDACTED
from ..domain.enums import MaterialKind, RedactionScope, Role, Sensitivity
from ..domain.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from ..domain.fingerprint import digest_bytes
from ..domain.models import Blob, RedactionVersion, User
from .base import Service, require_roles


class RedactionService(Service):
    # ------------------------------------------------------------ 创建版本
    def create_redaction(
        self,
        actor: User,
        *,
        version_id: str,
        data: bytes,
        media_type: str = "text/plain",
        scope: str = RedactionScope.INSTITUTION.value,
        note: str = "",
        activate: bool = False,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.INSTITUTION_ADMIN)
        if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
            raise ValidationError("脱敏内容不能为空")
        if scope not in {s.value for s in RedactionScope}:
            raise ValidationError("未知授权范围", details={"scope": scope})
        sha = digest_bytes(bytes(data))

        def work() -> dict:
            version = self.repo.get_version(version_id)
            if version is None:
                raise NotFoundError("材料版本不存在", details={"version_id": version_id})
            if version.institution_id != actor.institution_id:
                raise PermissionDeniedError("只能对本机构材料制作脱敏版本")
            material = self.repo.get_material(version.material_id)
            if material is None:
                raise NotFoundError("材料不存在")
            if (
                material.kind != MaterialKind.ENTERPRISE_FEEDBACK.value
                or material.sensitivity != Sensitivity.SENSITIVE.value
            ):
                raise ValidationError("仅敏感企业反馈可制作脱敏版本")
            original = self.repo.get_blob(version.sha256)
            if original is not None and bytes(original.data) == bytes(data):
                raise ValidationError("脱敏内容与原文完全相同，未做任何裁剪")

            # 相同裁剪字节幂等回放既有脱敏版本
            existing = self.repo.find_redaction_by_digest(version_id, sha)
            if existing is not None:
                return self._redaction_dict(existing, replayed=True)

            prior = self.repo.list_redactions(version_id)
            redaction = RedactionVersion(
                redaction_id=self.ids.new_id("rdc"),
                material_id=version.material_id,
                source_version_id=version_id,
                institution_id=version.institution_id,
                redaction_no=len(prior) + 1,
                sha256=sha,
                size=len(data),
                media_type=media_type,
                scope=scope,
                note=note.strip(),
                created_by=actor.user_id,
                created_at=self.clock.now_iso(),
                activated_at=None,
            )
            self.repo.put_blob(
                Blob(
                    sha256=sha,
                    data=bytes(data),
                    media_type=media_type,
                    created_at=self.clock.now_iso(),
                )
            )
            self.repo.insert_redaction(redaction)
            self.audit(
                actor.user_id, "redaction.created",
                institution_id=version.institution_id,
                detail={
                    "version_id": version_id,
                    "redaction_id": redaction.redaction_id,
                    "redaction_no": redaction.redaction_no,
                    "scope": scope,
                },
            )
            if activate:
                self._activate(actor, redaction)
            result = self.repo.get_redaction(redaction.redaction_id)
            return self._redaction_dict(result)

        return self.idempotent(idempotency_key, work)

    # ------------------------------------------------------------ 切换版本
    def activate_redaction(
        self,
        actor: User,
        *,
        redaction_id: str,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.INSTITUTION_ADMIN)

        def work() -> dict:
            redaction = self.repo.get_redaction(redaction_id)
            if redaction is None:
                raise NotFoundError("脱敏版本不存在", details={"redaction_id": redaction_id})
            if redaction.institution_id != actor.institution_id:
                raise PermissionDeniedError("只能切换本机构材料的脱敏版本")
            self._activate(actor, redaction)
            return self._redaction_dict(self.repo.get_redaction(redaction_id))

        return self.idempotent(idempotency_key, work)

    def _activate(self, actor: User, redaction: RedactionVersion) -> None:
        """移动当前脱敏指针；不触碰任何旧脱敏快照与已封存条目。"""
        version = self.repo.get_version(redaction.source_version_id)
        if version is None or version.withdrawn:
            raise ConflictError("原文版本不存在或已撤回，不能切换脱敏版本")
        if version.current_redaction_id != redaction.redaction_id:
            ok = self.repo.set_current_redaction(
                redaction.source_version_id, redaction.redaction_id
            )
            if not ok:
                raise ConflictError("脱敏版本切换失败，请重试")
        self.repo.mark_redaction_activated(
            redaction.redaction_id, self.clock.now_iso()
        )
        self.audit(
            actor.user_id, "redaction.activated",
            institution_id=redaction.institution_id,
            detail={
                "version_id": redaction.source_version_id,
                "redaction_id": redaction.redaction_id,
                "redaction_no": redaction.redaction_no,
            },
        )

    # --------------------------------------------------------------- 查询
    def list_redactions(self, actor: User, version_id: str) -> list[dict]:
        version = self.repo.get_version(version_id)
        if version is None:
            raise NotFoundError("材料版本不存在")
        if (
            actor.institution_id != version.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("不能查看其他机构材料的脱敏版本")
        items = self.repo.list_redactions(version_id)
        return [self._redaction_dict(r) for r in items]

    def get_redaction(self, actor: User, redaction_id: str) -> dict:
        redaction = self.repo.get_redaction(redaction_id)
        if redaction is None:
            raise NotFoundError("脱敏版本不存在")
        if (
            actor.institution_id != redaction.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("不能查看其他机构材料的脱敏版本")
        return self._redaction_dict(redaction)

    def download_redaction(self, actor: User, redaction_id: str) -> tuple[dict, bytes]:
        """直接下载裁剪文：仅脱敏版本授权范围内（本机构成员）可读。

        通过评审包条目下载时由 PackageService 统一做三级选择，
        外机构评审人即使曾被分配也不能经此回落看到裁剪文。
        """
        redaction = self.repo.get_redaction(redaction_id)
        if redaction is None:
            raise NotFoundError("脱敏版本不存在")
        if (
            actor.institution_id != redaction.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("无权下载该脱敏版本（最小披露限制）")
        blob = self.repo.get_blob(redaction.sha256)
        if blob is None:
            raise NotFoundError("脱敏内容缺失")
        return self._redaction_dict(redaction), blob.data

    # ------------------------------------------------------------- 渲染
    @staticmethod
    def _redaction_dict(r: RedactionVersion, *, replayed: bool = False) -> dict:
        return {
            "redaction_id": r.redaction_id,
            "material_id": r.material_id,
            "source_version_id": r.source_version_id,
            "institution_id": r.institution_id,
            "redaction_no": r.redaction_no,
            "sha256": "sha256:" + r.sha256,
            "size": r.size,
            "media_type": r.media_type,
            "scope": r.scope,
            "note": r.note,
            "content_tier": REDACTED,
            "created_by": r.created_by,
            "created_at": r.created_at,
            "activated_at": r.activated_at,
            "replayed": replayed,
        }
