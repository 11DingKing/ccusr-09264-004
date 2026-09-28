"""离线完整性核验。

不依赖时钟/写事务：打开数据库只读连接，重算所有内容字节摘要与每个
已封存包的清单指纹、已签发包的评审记录指纹，任何不一致或“已封存清单
引用了已撤回版本”都会被报告。CLI 命令与（未来的）在线接口共用本模块。
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from ..domain.fingerprint import (
    digest_bytes,
    manifest_fingerprint,
    review_record_fingerprint,
)


@dataclass
class VerificationReport:
    ok: bool = True
    blob_count: int = 0
    package_count: int = 0
    sealed_count: int = 0
    decided_count: int = 0
    withdrawn_in_sealed: list[dict] = field(default_factory=list)
    failures: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)

    def fail(self, kind: str, **detail) -> None:
        self.ok = False
        item = {"kind": kind}
        item.update(detail)
        self.failures.append(item)

    def warn(self, kind: str, **detail) -> None:
        item = {"kind": kind}
        item.update(detail)
        self.warnings.append(item)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "blob_count": self.blob_count,
            "package_count": self.package_count,
            "sealed_count": self.sealed_count,
            "decided_count": self.decided_count,
            "withdrawn_in_sealed": self.withdrawn_in_sealed,
            "failures": self.failures,
            "warnings": self.warnings,
        }


def verify_database(path: str) -> VerificationReport:
    """对数据库文件做完整离线核验。只读打开，绝不写入。"""
    report = VerificationReport()
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        _verify_blobs(conn, report)
        _verify_redactions(conn, report)
        _verify_packages(conn, report)
    finally:
        conn.close()
    return report


def _verify_redactions(conn: sqlite3.Connection, report: VerificationReport) -> None:
    """核验敏感反馈脱敏版本：裁剪文字节可重算、原文摘要存在、版本号连续。

    脱敏版本是追加留存的独立记录，不参与封存清单指纹；这里只核验其自身
    内容寻址完整性与版本链，不影响历史包结论。
    """
    try:
        rows = conn.execute(
            "SELECT * FROM redactions ORDER BY material_id, redaction_no"
        ).fetchall()
    except sqlite3.OperationalError:
        # 旧库尚未迁移出 redactions 表：无脱敏版本可核验
        return

    blob_rows = {r["sha256"]: r for r in conn.execute("SELECT sha256, data FROM blobs")}
    seen_by_material: dict[str, int] = {}
    for row in rows:
        mid = row["material_id"]
        no = row["redaction_no"]
        seen_by_material[mid] = seen_by_material.get(mid, 0) + 1
        if no != seen_by_material[mid]:
            report.fail(
                "redaction_no_gap",
                material_id=mid,
                redaction_id=row["redaction_id"],
                redaction_no=no,
                expected=seen_by_material[mid],
            )
        if row["redacted_sha256"] == row["source_sha256"]:
            report.fail(
                "redaction_equals_source",
                material_id=mid,
                redaction_id=row["redaction_id"],
            )
        for label, sha in (
            ("source", row["source_sha256"]),
            ("redacted", row["redacted_sha256"]),
        ):
            blob = blob_rows.get(sha)
            if blob is None:
                report.fail(
                    "redaction_blob_missing",
                    material_id=mid,
                    redaction_id=row["redaction_id"],
                    which=label,
                    sha256=sha,
                )
            elif digest_bytes(blob["data"]) != sha:
                report.fail(
                    "redaction_blob_tampered",
                    material_id=mid,
                    redaction_id=row["redaction_id"],
                    which=label,
                    sha256=sha,
                )

    # 当前指针（若存在）必须指向本材料的真实脱敏版本
    current_rows = conn.execute(
        "SELECT material_id, current_redaction_id FROM materials"
        " WHERE current_redaction_id IS NOT NULL"
    ).fetchall()
    valid = {r["redaction_id"]: r["material_id"] for r in rows}
    for row in current_rows:
        owner = valid.get(row["current_redaction_id"])
        if owner is None or owner != row["material_id"]:
            report.fail(
                "current_redaction_dangling",
                material_id=row["material_id"],
                current_redaction_id=row["current_redaction_id"],
            )


def _verify_blobs(conn: sqlite3.Connection, report: VerificationReport) -> None:
    rows = conn.execute(
        "SELECT sha256, data, size, media_type FROM blobs"
    ).fetchall()
    report.blob_count = len(rows)
    for row in rows:
        raw = row["data"]
        if not isinstance(raw, bytes):
            report.fail(
                "blob_type_mismatch",
                stored=row["sha256"],
                actual_type=type(raw).__name__,
            )
            continue
        data = raw
        actual = digest_bytes(data)
        if actual != row["sha256"]:
            report.fail(
                "blob_digest_mismatch",
                stored=row["sha256"],
                actual=actual,
            )
        if len(data) != row["size"]:
            report.fail(
                "blob_size_mismatch",
                sha256=row["sha256"],
                stored_size=row["size"],
                actual_size=len(data),
            )


def _verify_packages(conn: sqlite3.Connection, report: VerificationReport) -> None:
    packages = conn.execute("SELECT * FROM packages").fetchall()
    report.package_count = len(packages)

    # version_id -> withdrawn，供封存清单引用检查
    withdrawn_versions = {
        r["version_id"]: bool(r["withdrawn"])
        for r in conn.execute("SELECT version_id, withdrawn FROM versions")
    }

    for pkg in packages:
        entries = conn.execute(
            "SELECT * FROM entries WHERE package_id = ?"
            " ORDER BY material_id, version_id",
            (pkg["package_id"],),
        ).fetchall()

        # 条目声明的 sha256 必须与版本表一致，且字节可重算
        for entry in entries:
            version = conn.execute(
                "SELECT sha256, withdrawn FROM versions WHERE version_id = ?",
                (entry["version_id"],),
            ).fetchone()
            if version is None:
                report.fail(
                    "entry_version_missing",
                    package_id=pkg["package_id"],
                    version_id=entry["version_id"],
                )
                continue
            if version["sha256"] != entry["sha256"]:
                report.fail(
                    "entry_digest_drift",
                    package_id=pkg["package_id"],
                    version_id=entry["version_id"],
                    entry_sha256=entry["sha256"],
                    version_sha256=version["sha256"],
                )
            blob = conn.execute(
                "SELECT data FROM blobs WHERE sha256 = ?", (entry["sha256"],)
            ).fetchone()
            if blob is None:
                report.fail(
                    "blob_missing",
                    package_id=pkg["package_id"],
                    sha256=entry["sha256"],
                )
            elif not isinstance(blob["data"], bytes):
                report.fail(
                    "blob_type_mismatch",
                    package_id=pkg["package_id"],
                    sha256=entry["sha256"],
                )
            elif digest_bytes(blob["data"]) != entry["sha256"]:
                report.fail(
                    "blob_tampered",
                    package_id=pkg["package_id"],
                    sha256=entry["sha256"],
                )

        if pkg["status"] in ("sealed", "under_review", "decided"):
            report.sealed_count += 1
            expected = manifest_fingerprint(
                pkg["package_id"],
                pkg["institution_id"],
                [
                    {
                        "material_id": e["material_id"],
                        "version_id": e["version_id"],
                        "sha256": e["sha256"],
                        "kind": e["kind"],
                        "sensitivity": e["sensitivity"],
                    }
                    for e in entries
                ],
                pkg["sealed_at"],
            )
            stored = pkg["manifest_fingerprint"]
            if stored != expected:
                report.fail(
                    "manifest_fingerprint_mismatch",
                    package_id=pkg["package_id"],
                    stored=stored,
                    expected=expected,
                )

            # 撤回不破坏历史指纹，但必须显式标注：该包引用的材料事后被撤回
            for e in entries:
                if withdrawn_versions.get(e["version_id"]):
                    report.withdrawn_in_sealed.append(
                        {
                            "package_id": pkg["package_id"],
                            "version_id": e["version_id"],
                            "material_id": e["material_id"],
                        }
                    )
                    report.warn(
                        "sealed_entry_withdrawn",
                        package_id=pkg["package_id"],
                        version_id=e["version_id"],
                    )

        if pkg["status"] == "decided":
            report.decided_count += 1
            requests = [
                {
                    "request_id": r["request_id"],
                    "reviewer_id": r["reviewer_id"],
                    "status": r["status"],
                    "verdict": r["verdict"],
                    "comment": r["comment"],
                    "assigned_at": r["assigned_at"],
                    "completed_at": r["completed_at"],
                }
                for r in conn.execute(
                    "SELECT * FROM requests WHERE package_id = ? ORDER BY request_id",
                    (pkg["package_id"],),
                )
            ]
            objections = [
                {
                    "objection_id": r["objection_id"],
                    "request_id": r["request_id"],
                    "reviewer_id": r["reviewer_id"],
                    "category": r["category"],
                    "detail": r["detail"],
                    "created_at": r["created_at"],
                }
                for r in conn.execute(
                    "SELECT * FROM objections WHERE package_id = ? ORDER BY objection_id",
                    (pkg["package_id"],),
                )
            ]
            expected_review = review_record_fingerprint(
                pkg["package_id"],
                pkg["manifest_fingerprint"],
                requests,
                objections,
            )
            if pkg["review_fingerprint"] != expected_review:
                report.fail(
                    "review_fingerprint_mismatch",
                    package_id=pkg["package_id"],
                    stored=pkg["review_fingerprint"],
                    expected=expected_review,
                )
