"""敏感反馈脱敏版本：授权范围判定与按身份选择内容（纯领域逻辑）。

- 授权人（看原文）：质量权威机构、审计；本机构管理员；被【当前仍有效分配】
  到包含该敏感反馈所在评审包的评审人（pending/accepted/completed）。
- 普通成员（看裁剪文）：本机构无原文授权的成员（如提交人）。
- 外机构且无有效分配者：既看不到原文也不提供裁剪文（交由上层按最小披露拒绝）。

每次脱敏生成不可变的 RedactionVersion；切换当前脱敏版本只影响“此后展示
选用哪份裁剪文”，原文与历史脱敏版本均不变——版本切换不改变旧反馈的显示。
"""
from __future__ import annotations

from .enums import Role
from .models import RedactionVersion, User


def can_view_plaintext(
    user: User,
    *,
    institution_id: str,
    active_package_ids: set[str],
    package_id: str | None,
) -> bool:
    """该用户是否在敏感反馈原文的授权范围内。

    package_id 为该反馈当前被查看时所在评审包；评审人凭对该包的有效分配获得
    授权，请求取消/拒绝后即不在 active_package_ids 中，授权即时失效。
    """
    if user.has_role(Role.AUDITOR) or user.has_role(Role.QUALITY_AUTHORITY):
        return True
    if user.institution_id is not None and user.institution_id == institution_id:
        # 本机构：管理员可见原文；提交人等普通成员不可见
        return user.has_role(Role.INSTITUTION_ADMIN)
    if user.has_role(Role.REVIEWER) and package_id is not None:
        return package_id in active_package_ids
    return False


def can_view_redacted(
    user: User,
    *,
    institution_id: str,
    active_package_ids: set[str],
    package_id: str | None,
) -> bool:
    """该用户是否至少可获得裁剪文（普通成员可见层级）。

    授权人当然也可获得裁剪文；本机构普通成员可获得裁剪文；被有效分配到该包
    的跨机构评审人也可获得（其本身已在原文授权范围内）。与该反馈毫无关系的
    外机构用户不可获得。
    """
    if can_view_plaintext(
        user,
        institution_id=institution_id,
        active_package_ids=active_package_ids,
        package_id=package_id,
    ):
        return True
    if user.institution_id is not None and user.institution_id == institution_id:
        return True
    if user.has_role(Role.REVIEWER) and package_id is not None:
        return package_id in active_package_ids
    return False


def resolve_redaction_for_version(
    redactions,
    *,
    source_version_id: str,
    current_redaction_id: str | None,
):
    """为某条【固定到具体反馈版本】的查看选择应展示的脱敏版本。

    redactions 为该材料按 redaction_no 升序的全部脱敏版本。

    只在“锚定到同一原反馈版本”的脱敏版本中选择：当前指针若指向其中之一，
    则尊重当前切换；否则取该原版本最新的脱敏版本。把当前版本切换到锚定
    更新原版本的脱敏版本，不会改变旧反馈（旧版本）在历史包中的显示。
    """
    candidates = [r for r in redactions if r.source_version_id == source_version_id]
    if not candidates:
        return None
    for r in candidates:
        if r.redaction_id == current_redaction_id:
            return r
    return candidates[-1]
