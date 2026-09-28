"""敏感材料最小披露策略。

规则（按机构隔离 + 按角色）：
- 非敏感材料：参与该机构评审流程的角色可见；
- 敏感企业反馈：仅本机构管理员、被正式分配到包含该材料评审包的评审人、
  质量权威机构、审计可见原文；本机构普通成员默认不可见；
- 任何外机构用户一律不可见（审计除外，审计可跨机构只读）；
- 评审人若其请求已被取消（重新分配给他人），从取消时刻起失去该包
  敏感材料的访问权（权限变化即时生效）。

脱敏版本把“可见性”细化为三级内容选择（select_content_tier）：
- original：有原文权限者（规则同上），永远看原文，与脱敏版本切换无关；
- redacted：无原文权限但落在脱敏版本授权范围内者（当前仅本机构成员），
  看裁剪文；
- hidden：两者都不满足，仅看到条目的存在。

“授权人看原文、普通人看裁剪文”的选择只在 Python 层按身份完成；
SQLite 仅留存脱敏版本与其授权范围（scope）。
"""
from __future__ import annotations

from .enums import RedactionScope, RequestStatus, Role, Sensitivity
from .models import PackageEntry, RedactionVersion, ReviewPackage, User

ORIGINAL = "original"
REDACTED = "redacted"
HIDDEN = "hidden"


class DisclosureContext:
    """一次访问的权限上下文：用户当前有效的评审分配。

    active_request_package_ids: 该用户作为评审人、状态仍为
    pending/accepted/completed（即未 cancelled/declined）的请求所在包。
    declined 也不应保留访问权——评审人拒绝后即与该包无关。
    """

    ACTIVE_STATUSES = frozenset(
        {
            RequestStatus.PENDING.value,
            RequestStatus.ACCEPTED.value,
            RequestStatus.COMPLETED.value,
        }
    )

    def __init__(self, user: User, active_request_package_ids: set[str]) -> None:
        self.user = user
        self.active_package_ids = active_request_package_ids

    def can_see_entry(
        self,
        entry: PackageEntry,
        package: ReviewPackage | None = None,
    ) -> bool:
        """该身份能否看到【原文】。"""
        user = self.user
        is_auditor = user.has_role(Role.AUDITOR)
        is_authority = user.has_role(Role.QUALITY_AUTHORITY)
        institution = package_institution(entry, package)
        same_institution = (
            user.institution_id is not None and user.institution_id == institution
        )

        # 全局只读角色
        if is_auditor or is_authority:
            return True

        is_sensitive = entry.sensitivity == Sensitivity.SENSITIVE.value

        # 本机构成员视角
        if same_institution:
            if user.has_role(Role.INSTITUTION_ADMIN):
                return True  # 管理员可见本机构全部材料原文
            if user.has_role(Role.INSTITUTION_SUBMITTER):
                return not is_sensitive  # 提交人不见敏感企业反馈原文
            return False

        # 跨机构：只有“仍被有效分配到该包”的评审人可见原文
        if user.has_role(Role.REVIEWER):
            return entry.package_id in self.active_package_ids
        return False

    def can_see_redaction(
        self,
        redaction: RedactionVersion | None,
        package: ReviewPackage | None = None,
    ) -> bool:
        """该身份是否落在给定脱敏版本的授权披露范围内。"""
        if redaction is None or package is None:
            return False
        if redaction.scope != RedactionScope.INSTITUTION.value:
            return False
        # 仅限脱敏版本所属机构的成员；外机构评审人（即使曾被分配、后被取消）
        # 不属于机构范围，不得回落看到裁剪文。
        return self.user.institution_id == package.institution_id

    def select_content_tier(
        self,
        entry: PackageEntry,
        package: ReviewPackage | None,
        redaction: RedactionVersion | None,
    ) -> str:
        """按身份在 原文 / 裁剪文 / 完全遮蔽 三级间选择。"""
        if self.can_see_entry(entry, package):
            return ORIGINAL
        if self.can_see_redaction(redaction, package):
            return REDACTED
        return HIDDEN


def package_institution(entry: PackageEntry, package: ReviewPackage | None) -> str | None:
    if package is not None:
        return package.institution_id
    return None


def render_entry(entry: PackageEntry, tier: str, redaction: RedactionVersion | None = None) -> dict:
    """按内容层级渲染清单条目。

    - original：暴露原文 sha256（内容指纹）；
    - redacted：暴露裁剪文指纹与 redaction_id，原文指纹继续遮蔽；
    - hidden：仅证明材料存在，不泄露任何内容指纹。
    """
    base = {
        "entry_id": entry.entry_id,
        "package_id": entry.package_id,
        "material_id": entry.material_id,
        "version_id": entry.version_id,
        "kind": entry.kind,
        "sensitivity": entry.sensitivity,
        "content_tier": tier,
        "redacted": tier != ORIGINAL,
    }
    if tier == ORIGINAL:
        base["sha256"] = entry.sha256
    elif tier == REDACTED and redaction is not None:
        base["redaction_id"] = redaction.redaction_id
        base["redaction_no"] = redaction.redaction_no
        base["redaction_sha256"] = redaction.sha256
        base["pinned"] = (
            entry.pinned_redaction_id is not None
            and entry.pinned_redaction_id == redaction.redaction_id
        )
    return base

