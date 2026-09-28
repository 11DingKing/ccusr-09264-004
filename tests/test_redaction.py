"""敏感反馈脱敏版本：每次脱敏留版本、按身份选内容、切换不改旧反馈。"""
import base64
import unittest

from service_09252_006.domain.enums import (
    MaterialKind,
    Role,
    Sensitivity,
)
from service_09252_006.domain.errors import PermissionDeniedError
from tests.flow import seal_new_package, upload_material
from tests.support import Harness

P1 = "敏感反馈：企业 A 要求匿名，联系人张三 13800000000".encode("utf-8")
C1 = "敏感反馈：企业***要求匿名，联系人***".encode("utf-8")
P2 = "敏感反馈 v2：企业 A 与企业 B 联合，联系人李四".encode("utf-8")
C2 = "敏感反馈 v2：企业***，联系人***".encode("utf-8")
C1B = "敏感反馈（更严格裁剪）：内容已隐藏".encode("utf-8")


class RedactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        self.authority = self.h.user("auth", Role.QUALITY_AUTHORITY, institution_id=None)
        self.auditor = self.h.user("aud", Role.AUDITOR, institution_id=None)
        self.reviewer = self.h.user("rev-1", Role.REVIEWER, institution_id="inst-ext")
        self.item = upload_material(
            self.h, self.admin,
            kind=MaterialKind.ENTERPRISE_FEEDBACK.value,
            data=P1, title="企业反馈",
            sensitivity=Sensitivity.SENSITIVE.value,
        )
        self.mid = self.item.material["material_id"]
        self.v1 = self.item.version["version_id"]
        self.sealed = seal_new_package(self.h, self.admin, items=[self.item])
        self.pid = self.sealed.package_id

    def tearDown(self) -> None:
        self.h.close()

    # ------------------------------------------------ 版本生成与留存
    def test_each_redaction_generates_immutable_version(self) -> None:
        r1 = self.h.ctx.redactions.create_redaction(
            self.admin, material_id=self.mid, redacted_content=C1
        )
        self.assertEqual(r1["redaction_no"], 1)
        self.assertIsNone(r1["supersedes_redaction_id"])
        self.assertTrue(r1["active"])

        # 上传原反馈 v2，再次脱敏 -> 第 2 版，链接到第 1 版
        self.h.ctx.evidence.upload_version(
            self.admin, material_id=self.mid, data=P2
        )
        r2 = self.h.ctx.redactions.create_redaction(
            self.admin, material_id=self.mid, redacted_content=C2
        )
        self.assertEqual(r2["redaction_no"], 2)
        self.assertEqual(r2["supersedes_redaction_id"], r1["redaction_id"])
        self.assertTrue(r2["active"])

        # 列表留存全部历史版本，当前指针指向第 2 版
        listing = self.h.ctx.redactions.list_redactions(self.admin, self.mid)
        self.assertEqual(len(listing["redactions"]), 2)
        self.assertEqual(
            [r["redaction_no"] for r in listing["redactions"]], [1, 2]
        )
        self.assertEqual(listing["current_redaction_id"], r2["redaction_id"])
        self.assertTrue(listing["redactions"][1]["active"])
        self.assertFalse(listing["redactions"][0]["active"])

    def test_same_cropped_text_replays_existing_version(self) -> None:
        r1 = self.h.ctx.redactions.create_redaction(
            self.admin, material_id=self.mid, redacted_content=C1
        )
        again = self.h.ctx.redactions.create_redaction(
            self.admin, material_id=self.mid, redacted_content=C1
        )
        self.assertEqual(again["redaction_id"], r1["redaction_id"])
        self.assertTrue(again["replayed"])
        self.assertEqual(
            len(self.h.ctx.redactions.list_redactions(self.admin, self.mid)["redactions"]),
            1,
        )

    def test_only_sensitive_feedback_can_be_redacted(self) -> None:
        normal = upload_material(
            self.h, self.admin,
            kind=MaterialKind.SYLLABUS.value, data=b"out", title="大纲",
        )
        from service_09252_006.domain.errors import ValidationError

        with self.assertRaises(ValidationError):
            self.h.ctx.redactions.create_redaction(
                self.admin,
                material_id=normal.material["material_id"],
                redacted_content=b"cropped",
            )

    def test_submitter_cannot_create_redaction(self) -> None:
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.redactions.create_redaction(
                self.submitter, material_id=self.mid, redacted_content=C1
            )

    # ------------------------------------------------ 按身份选择内容
    def test_authorized_see_plaintext_member_sees_cropped(self) -> None:
        self.h.ctx.redactions.create_redaction(
            self.admin, material_id=self.mid, redacted_content=C1
        )

        # 授权人：本机构管理员 / 权威机构 / 审计 看到原文
        for actor in (self.admin, self.authority, self.auditor):
            meta, data, _ = self.h.ctx.packages.download_entry(
                actor, package_id=self.pid, version_id=self.v1
            )
            self.assertEqual(data, P1)
            self.assertEqual(meta["content_view"], "plaintext")

        # 普通成员（提交人）：看到裁剪文，拿不到原文
        meta, data, _ = self.h.ctx.packages.download_entry(
            self.submitter, package_id=self.pid, version_id=self.v1
        )
        self.assertEqual(data, C1)
        self.assertEqual(meta["content_view"], "redacted")
        import hashlib

        self.assertEqual(meta["sha256"], "sha256:" + hashlib.sha256(C1).hexdigest())

        # 包视图：普通成员条目只暴露裁剪文摘要，不暴露原文指纹
        view = self.h.ctx.packages.build_package_view(self.submitter, self.pid)
        entry = next(e for e in view["entries"] if e["version_id"] == self.v1)
        self.assertEqual(entry["content_view"], "redacted")
        self.assertNotIn("sha256", entry)
        self.assertEqual(
            entry["redacted_sha256"],
            "sha256:" + hashlib.sha256(C1).hexdigest(),
        )

    def test_member_blocked_until_redaction_exists(self) -> None:
        # 脱敏版本生成前：普通成员条目完全遮蔽，下载被拒（拿不到原文）
        view = self.h.ctx.packages.build_package_view(self.submitter, self.pid)
        entry = next(e for e in view["entries"] if e["version_id"] == self.v1)
        self.assertTrue(entry["redacted"])
        self.assertNotIn("sha256", entry)
        self.assertNotIn("redacted_sha256", entry)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.download_entry(
                self.submitter, package_id=self.pid, version_id=self.v1
            )

        # 生成脱敏版本后立即可见裁剪文
        self.h.ctx.redactions.create_redaction(
            self.admin, material_id=self.mid, redacted_content=C1
        )
        _, data, _ = self.h.ctx.packages.download_entry(
            self.submitter, package_id=self.pid, version_id=self.v1
        )
        self.assertEqual(data, C1)

    def test_assigned_reviewer_plaintext_revoked_on_cancel(self) -> None:
        self.h.ctx.redactions.create_redaction(
            self.admin, material_id=self.mid, redacted_content=C1
        )
        req = self.h.ctx.reviews.assign_reviewer(
            self.authority, package_id=self.pid, reviewer_id=self.reviewer.user_id
        )
        _, data, _ = self.h.ctx.packages.download_entry(
            self.reviewer, package_id=self.pid, version_id=self.v1
        )
        self.assertEqual(data, P1)  # 有效分配的评审人看原文

        self.h.ctx.reviews.cancel_request(
            self.authority, request_id=req["request_id"], reason="改派"
        )
        # 取消后：跨机构评审人既无原文也无裁剪文（非本机构成员）
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.download_entry(
                self.reviewer, package_id=self.pid, version_id=self.v1
            )

    # --------------------------------------- 切换版本不改变旧反馈显示
    def test_switching_version_does_not_change_old_feedback(self) -> None:
        # v1 原文 -> r1(C1)，封存进历史包，普通成员看到 C1
        r1 = self.h.ctx.redactions.create_redaction(
            self.admin, material_id=self.mid, redacted_content=C1
        )
        _, data, _ = self.h.ctx.packages.download_entry(
            self.submitter, package_id=self.pid, version_id=self.v1
        )
        self.assertEqual(data, C1)
        fingerprint_before = self.h.repo.get_package(self.pid).manifest_fingerprint

        # 原反馈演进到 v2，生成锚定 v2 的 r2(C2)，当前脱敏版本随之切到 r2
        self.h.ctx.evidence.upload_version(
            self.admin, material_id=self.mid, data=P2
        )
        r2 = self.h.ctx.redactions.create_redaction(
            self.admin, material_id=self.mid, redacted_content=C2
        )
        self.assertEqual(r2["redaction_no"], 2)
        self.assertEqual(
            self.h.repo.get_material(self.mid).current_redaction_id,
            r2["redaction_id"],
        )

        # 历史包固定引用 v1：普通成员看到的仍是 r1 的裁剪文 C1，而非当前 r2 的 C2
        _, data_old, _ = self.h.ctx.packages.download_entry(
            self.submitter, package_id=self.pid, version_id=self.v1
        )
        self.assertEqual(data_old, C1)
        view = self.h.ctx.packages.build_package_view(self.submitter, self.pid)
        entry = next(e for e in view["entries"] if e["version_id"] == self.v1)
        self.assertEqual(entry["redaction_id"], r1["redaction_id"])

        # 授权人看历史包仍是原文 P1；封存指纹不变
        _, data_plain, _ = self.h.ctx.packages.download_entry(
            self.admin, package_id=self.pid, version_id=self.v1
        )
        self.assertEqual(data_plain, P1)
        self.assertEqual(
            self.h.repo.get_package(self.pid).manifest_fingerprint,
            fingerprint_before,
        )

        # 历史脱敏版本仍留存、可查询；当前指针可在历史版本间显式切换
        self.assertIsNotNone(self.h.repo.get_redaction(r2["redaction_id"]))
        self.h.ctx.redactions.activate_redaction(
            self.admin, material_id=self.mid, redaction_id=r1["redaction_id"]
        )
        _, data_back, _ = self.h.ctx.packages.download_entry(
            self.submitter, package_id=self.pid, version_id=self.v1
        )
        self.assertEqual(data_back, C1)
        # r2 记录未因切回 r1 而被删除
        self.assertIsNotNone(self.h.repo.get_redaction(r2["redaction_id"]))

    def test_switching_crops_of_same_old_feedback_version(self) -> None:
        # 对同一原版本 v1 做两次裁剪 r1(C1) 与 r1b(C1B)，可在两者间切换；
        # 切换只改当前指针，历史裁剪文与原文都不被修改。
        r1 = self.h.ctx.redactions.create_redaction(
            self.admin, material_id=self.mid, redacted_content=C1
        )
        r1b = self.h.ctx.redactions.create_redaction(
            self.admin,
            material_id=self.mid,
            redacted_content=C1B,
            source_version_id=self.v1,
        )
        self.assertEqual(r1b["source_version_id"], self.v1)
        # 新裁剪成为当前 -> 历史包 v1 的普通成员视图随之显示更严格的 C1B
        _, data_now, _ = self.h.ctx.packages.download_entry(
            self.submitter, package_id=self.pid, version_id=self.v1
        )
        self.assertEqual(data_now, C1B)

        # 切回 r1 -> 显示 C1
        self.h.ctx.redactions.activate_redaction(
            self.admin, material_id=self.mid, redaction_id=r1["redaction_id"]
        )
        _, data_back, _ = self.h.ctx.packages.download_entry(
            self.submitter, package_id=self.pid, version_id=self.v1
        )
        self.assertEqual(data_back, C1)

        # 授权人始终看原文，与裁剪切换无关
        _, data_plain, _ = self.h.ctx.packages.download_entry(
            self.admin, package_id=self.pid, version_id=self.v1
        )
        self.assertEqual(data_plain, P1)


class RedactionMigrationTests(unittest.TestCase):
    """v1 旧库条件迁移到 v2：新增脱敏表与指针列。"""

    def test_v1_database_migrates(self) -> None:
        import os
        import sqlite3
        import tempfile

        from service_09252_006.persistence.sqlite_repo import SqliteRepository

        fd, path = tempfile.mkstemp(prefix="qe-v1-", suffix=".db")
        os.close(fd)
        os.unlink(path)
        conn = sqlite3.connect(path)
        # 最小 v1 结构：materials / versions（无 current_redaction_id 列）
        conn.executescript(
            """
            CREATE TABLE materials (
                material_id TEXT PRIMARY KEY, institution_id TEXT NOT NULL,
                kind TEXT NOT NULL, sensitivity TEXT NOT NULL, title TEXT NOT NULL,
                current_version_id TEXT, withdrawn INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE versions (
                version_id TEXT PRIMARY KEY, material_id TEXT NOT NULL,
                institution_id TEXT NOT NULL, sha256 TEXT NOT NULL,
                size INTEGER NOT NULL, media_type TEXT NOT NULL,
                version_no INTEGER NOT NULL, supersedes_version_id TEXT,
                created_by TEXT NOT NULL, created_at TEXT NOT NULL,
                withdrawn INTEGER NOT NULL DEFAULT 0, withdrawn_at TEXT,
                UNIQUE(material_id, version_no)
            );
            PRAGMA user_version = 1;
            """
        )
        conn.commit()
        conn.close()

        repo = SqliteRepository(path)
        try:
            self.assertEqual(
                repo._conn.execute("PRAGMA user_version").fetchone()[0], 2
            )
            cols = {r[1] for r in repo._conn.execute("PRAGMA table_info(materials)")}
            self.assertIn("current_redaction_id", cols)
            names = {
                r[0]
                for r in repo._conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertIn("redactions", names)
            self.assertIsNone(repo.get_current_redaction("mat_x"))
        finally:
            repo.close()
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(path + suffix)
                except FileNotFoundError:
                    pass


if __name__ == "__main__":
    unittest.main()
