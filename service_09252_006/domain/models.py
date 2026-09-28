"""领域实体（贫血数据载体，业务规则在领域服务/应用服务中）。

时间一律以带时区的 UTC ISO-8601 字符串存储；截止时间同时保存原始
IANA 时区用于展示，比较时统一换化为 UTC 时刻，从而正确处理跨时区截止。
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Optional

from .enums import (
    Decision,
    MaterialKind,
    PackageStatus,
    RequestStatus,
    Role,
    Sensitivity,
    Verdict,
)


@dataclass
class User:
    user_id: str
    institution_id: Optional[str]  # 机构用户非空；权威机构/审计可为空
    roles: tuple[str, ...]
    display_name: str = ""

    def has_role(self, role: Role | str) -> bool:
        wanted = role.value if isinstance(role, Role) else role
        return wanted in self.roles


@dataclass
class Material:
    """逻辑材料（课程大纲、师资、考核、企业反馈中的某一份）。"""

    material_id: str
    institution_id: str
    kind: str                      # MaterialKind
    sensitivity: str               # Sensitivity
    title: str
    current_version_id: Optional[str]
    withdrawn: bool
    created_at: str


@dataclass
class MaterialVersion:
    """材料的一次不可变版本。字节内容按 sha256 内容寻址、去重存储。"""

    version_id: str
    material_id: str
    institution_id: str
    sha256: str
    size: int
    media_type: str
    version_no: int
    supersedes_version_id: Optional[str]
    created_by: str
    created_at: str
    withdrawn: bool                # 该版本是否已撤回
    current_redaction_id: Optional[str] = None  # 面向无原文权限者的当前脱敏版本


@dataclass
class RedactionVersion:
    """某一敏感材料【具体原文版本】的一次不可变脱敏快照。

    每次脱敏都追加新版本（redaction_no 递增），裁剪文同样按 sha256
    内容寻址存入 blobs。版本切换只移动 current_redaction_id 指针，
    旧脱敏快照永不修改、永不删除——“切换版本不改变旧反馈的显示”。
    """

    redaction_id: str
    material_id: str
    source_version_id: str         # 被裁剪的原文版本
    institution_id: str
    redaction_no: int
    sha256: str                    # 裁剪文字节摘要
    size: int
    media_type: str
    scope: str                     # RedactionScope：裁剪文的授权披露范围
    note: str
    created_by: str
    created_at: str
    activated_at: Optional[str] = None  # 非空表示该快照曾被/正被切换启用


@dataclass
class PackageEntry:
    """评审包对材料【具体版本】的固定引用。"""

    entry_id: str
    package_id: str
    material_id: str
    version_id: str
    sha256: str
    kind: str
    sensitivity: str
    added_at: str
    # 封存时固定的脱敏版本：封存后再创建/切换脱敏版本都不改变历史包里
    # 普通成员看到的裁剪文；草稿包为 None，跟随版本当前指针。
    pinned_redaction_id: Optional[str] = None


@dataclass
class ReviewPackage:
    package_id: str
    institution_id: str
    title: str
    status: str                    # PackageStatus
    created_by: str
    created_at: str
    sealed_at: Optional[str]
    manifest_fingerprint: Optional[str]
    decided_at: Optional[str]
    decision: Optional[str]        # Decision
    decision_note: Optional[str]
    review_fingerprint: Optional[str]
    supersedes_package_id: Optional[str]  # 后补材料触发的复审包指向前序包
    entries: list[PackageEntry] = field(default_factory=list)

    def is_mutable(self) -> bool:
        return self.status == PackageStatus.DRAFT.value


@dataclass
class ReviewRequest:
    request_id: str
    package_id: str
    institution_id: str
    reviewer_id: str
    status: str                    # RequestStatus
    assigned_by: str
    assigned_at: str
    responded_at: Optional[str]
    completed_at: Optional[str]
    verdict: Optional[str]         # Verdict
    comment: Optional[str]
    deadline_at_utc: Optional[str]  # 截止时刻（UTC）
    deadline_timezone: Optional[str]  # 原始 IANA 时区，仅展示用


@dataclass
class Objection:
    objection_id: str
    request_id: str
    package_id: str
    institution_id: str
    reviewer_id: str
    category: str
    detail: str
    created_at: str


@dataclass
class Blob:
    sha256: str
    data: bytes
    media_type: str
    created_at: str


@dataclass
class AuditEntry:
    audit_id: str
    package_id: Optional[str]
    institution_id: Optional[str]
    actor_id: str
    action: str
    at: str
    detail: dict = field(default_factory=dict)


def asdict(obj) -> dict:
    return dataclasses.asdict(obj)
