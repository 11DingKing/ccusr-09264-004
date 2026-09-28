"""敏感反馈脱敏版本服务。

每次脱敏都生成一条不可变的 RedactionVersion（版本链 redaction_no 递增、
supersedes_redaction_id 指向上一版），裁剪文按内容寻址存入 blobs；
materials.current_redaction_id 指向当前生效版本。

- 只有本机构管理员/质量权威机构可发起脱敏、切换当前版本；
- 仅敏感企业反馈可脱敏；
- “切换当前版本”只改指针：历史脱敏版本与原文都保留，旧反馈在历史评审包中
  的显示（其封存清单指纹与原文字节）完全不变；
- 授权人看原文、普通成员看裁剪文的按身份选择发生在包视图/下载处。
"""
from __future__ import annotations

from ..domain import redaction as policy
from ..domain.enums import MaterialKind, Role, Sensitivity
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
    # ---------------------------------------------------------- 生成脱敏版本
    def create_redaction(
        self,
        actor: User,
        *,
        material_id: str,
        redacted_content: bytes,
        media_type: str | None = None,
        source_version_id: str | None = None,
        note: str = "",
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.INSTITUTION_ADMIN, Role.QUALITY_AUTHORITY)
        if not isinstance(redacted_content, (bytes, bytearray)) or len(redacted_content) == 0:
            raise ValidationError("裁剪文内容不能为空")

        def work() -> dict:
            material = self.repo.get_material(material_id)
            if material is None:
                raise NotFoundError("材料不存在", details={"material_id": material_id})
            if (
                not actor.has_role(Role.QUALITY_AUTHORITY)
                and material.institution_id != actor.institution_id
            ):
                raise PermissionDeniedError("只能对本机构反馈做脱敏")
            if material.kind != MaterialKind.ENTERPRISE_FEEDBACK.value:
                raise ValidationError("仅企业反馈可脱敏", details={"kind": material.kind})
            if material.sensitivity != Sensitivity.SENSITIVE.value:
                raise ValidationError("仅敏感反馈需要脱敏版本")

            # 默认锚定反馈当前版本；也允许对历史评审包仍引用的旧版本重新裁剪
            target_version_id = source_version_id or material.current_version_id
            if not target_version_id:
                raise ConflictError("反馈尚未上传任何版本，无法脱敏")
            source_version = self.repo.get_version(target_version_id)
            if source_version is None or source_version.material_id != material_id:
                raise NotFoundError(
                    "原反馈版本不存在",
                    details={"source_version_id": target_version_id},
                )

            redacted_bytes = bytes(redacted_content)
            redacted_sha = digest_bytes(redacted_bytes)
            source_sha = source_version.sha256
            if redacted_sha == source_sha:
                raise ValidationError("裁剪文与原文完全相同，未做任何脱敏")

            # 裁剪文内容寻址去重；同一原版本+同一裁剪文重复脱敏时回放既有版本
            prior = self.repo.list_redactions(material_id)
            for existing in prior:
                if (
                    existing.source_version_id == target_version_id
                    and existing.redacted_sha256 == redacted_sha
                ):
                    return self._redaction_dict(existing, replayed=True)

            resolved_media = media_type or source_version.media_type
            blob = Blob(
                sha256=redacted_sha,
                data=redacted_bytes,
                media_type=resolved_media,
                created_at=self.clock.now_iso(),
            )
            self.repo.put_blob(blob)

            previous = prior[-1] if prior else None
            record = RedactionVersion(
                redaction_id=self.ids.new_id("rdx"),
                material_id=material_id,
                institution_id=material.institution_id,
                source_version_id=target_version_id,
                source_sha256=source_sha,
                redacted_sha256=redacted_sha,
                size=len(redacted_bytes),
                media_type=resolved_media,
                redaction_no=len(prior) + 1,
                supersedes_redaction_id=previous.redaction_id if previous else None,
                created_by=actor.user_id,
                created_at=self.clock.now_iso(),
            )
            self.repo.insert_redaction(record)
            # 新生脱敏版本即成为当前生效版本
            self.repo.set_current_redaction(material_id, record.redaction_id)
            self.audit(
                actor.user_id, "redaction.created",
                institution_id=material.institution_id,
                detail={
                    "material_id": material_id,
                    "redaction_id": record.redaction_id,
                    "redaction_no": record.redaction_no,
                    "source_version_id": target_version_id,
                    "redacted_sha256": redacted_sha,
                    "note": note,
                },
            )
            return self._redaction_dict(record, active=True)

        return self.idempotent(idempotency_key, work)

    # ---------------------------------------------------------- 切换当前版本
    def activate_redaction(
        self,
        actor: User,
        *,
        material_id: str,
        redaction_id: str,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.INSTITUTION_ADMIN, Role.QUALITY_AUTHORITY)

        def work() -> dict:
            material = self.repo.get_material(material_id)
            if material is None:
                raise NotFoundError("材料不存在", details={"material_id": material_id})
            if (
                not actor.has_role(Role.QUALITY_AUTHORITY)
                and material.institution_id != actor.institution_id
            ):
                raise PermissionDeniedError("只能切换本机构反馈的脱敏版本")
            target = self.repo.get_redaction(redaction_id)
            if target is None or target.material_id != material_id:
                raise NotFoundError(
                    "脱敏版本不存在或不属于该反馈",
                    details={"redaction_id": redaction_id, "material_id": material_id},
                )

            # 仅移动当前指针；历史版本与原文不动，旧反馈显示不变
            self.repo.set_current_redaction(material_id, redaction_id)
            self.audit(
                actor.user_id, "redaction.activated",
                institution_id=material.institution_id,
                detail={
                    "material_id": material_id,
                    "redaction_id": redaction_id,
                    "redaction_no": target.redaction_no,
                },
            )
            return self._redaction_dict(target, active=True)

        return self.idempotent(idempotency_key, work)

    # ---------------------------------------------------------- 查询
    def list_redactions(self, actor: User, material_id: str) -> dict:
        material = self.repo.get_material(material_id)
        if material is None:
            raise NotFoundError("材料不存在")
        if (
            actor.institution_id != material.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("不能查看其他机构反馈的脱敏版本")
        records = self.repo.list_redactions(material_id)
        current_id = material.current_redaction_id
        return {
            "material_id": material_id,
            "current_redaction_id": current_id,
            "redactions": [
                self._redaction_dict(r, active=(r.redaction_id == current_id))
                for r in records
            ],
        }

    def select_content(
        self,
        actor: User,
        *,
        institution_id: str,
        source_sha256: str,
        redaction,
        active_package_ids: set[str],
        package_id: str | None,
    ) -> tuple[str, str]:
        """按身份为某次查看选择内容摘要。

        redaction 为针对该条固定反馈版本解析出的脱敏版本（由包服务按历史
        固定版本解析，保证切换当前版本不改变旧反馈显示），可为 None。

        返回 (sha256, view)，view 为 "plaintext"/"redacted"。
        无权查看任何层级、或普通成员在脱敏版本生成前访问时抛
        PermissionDeniedError——普通成员永远拿不到原文字节。
        """
        if not policy.can_view_redacted(
            actor,
            institution_id=institution_id,
            active_package_ids=active_package_ids,
            package_id=package_id,
        ):
            raise PermissionDeniedError("无权查看该敏感反馈（最小披露限制）")
        if policy.can_view_plaintext(
            actor,
            institution_id=institution_id,
            active_package_ids=active_package_ids,
            package_id=package_id,
        ):
            return source_sha256, "plaintext"
        if redaction is None:
            raise PermissionDeniedError("该反馈版本尚无脱敏版本，暂不可见")
        return redaction.redacted_sha256, "redacted"

    @staticmethod
    def _redaction_dict(r: RedactionVersion, *, replayed: bool = False,
                        active: bool = False) -> dict:
        return {
            "redaction_id": r.redaction_id,
            "material_id": r.material_id,
            "institution_id": r.institution_id,
            "source_version_id": r.source_version_id,
            "source_sha256": "sha256:" + r.source_sha256,
            "redacted_sha256": "sha256:" + r.redacted_sha256,
            "size": r.size,
            "media_type": r.media_type,
            "redaction_no": r.redaction_no,
            "supersedes_redaction_id": r.supersedes_redaction_id,
            "created_by": r.created_by,
            "created_at": r.created_at,
            "replayed": replayed,
            "active": active,
        }
