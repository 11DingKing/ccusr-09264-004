"""敏感反馈脱敏版本：

- 每次脱敏生成不可变版本，授权人看原文、普通成员看裁剪文；
- 版本切换只动“当前指针”，封存包固定当时的脱敏版本，
  切换后旧反馈仍可读且显示不变；
- 授权范围留存 SQLite，Python 按身份选择内容；
- schema v1 -> v2 条件迁移与离线核验。
"""
import unittest

from service_09252_006.application.container import ApplicationContext
from service_09252_006.domain.enums import (
    MaterialKind,
    Role,
    Sensitivity,
)
from service_09252_006.domain.errors import (
    PermissionDeniedError,
    ValidationError,
)
from tests.flow import seal_new_package, upload_material
from tests.support import Harness

ORIGINAL_TEXT = "敏感反馈：企业 X 要求匿名，联系人张三 13800000000"
REDACTED_V1 = "敏感反馈：某企业提出改进建议（已匿名）"
REDACTED_V2 = "敏感反馈：企业反馈已脱敏处理 v2"


class RedactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        self.admin_b = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.auditor = self.h.user("aud", Role.AUDITOR, institution_id=None)
        self.reviewer = self.h.user(
            "rev-1", Role.REVIEWER, institution_id="inst-ext"
        )
        self.item = upload_material(
            self.h, self.admin,
            kind=MaterialKind.ENTERPRISE_FEEDBACK.value,
            data=ORIGINAL_TEXT.encode("utf-8"),
            title="企业反馈",
            sensitivity=Sensitivity.SENSITIVE.value,
        )
        self.vid = self.item.version["version_id"]

    def tearDown(self) -> None:
        self.h.close()

    # ----------------------------------------------------------- 辅助
    def _create(self, text, *, activate=False, key=None):
        return self.h.ctx.redactions.create_redaction(
            self.admin,
            version_id=self.vid,
            data=text.encode("utf-8"),
            activate=activate,
            idempotency_key=key,
        )

    def _entry(self, view):
        return next(e for e in view["entries"] if e["version_id"] == self.vid)

    def _sealed_with_feedback(self):
        return seal_new_package(self.h, self.admin, items=[self.item])

    def _download(self, actor, pid):
        return self.h.ctx.packages.download_entry(
            actor, package_id=pid, version_id=self.vid
        )

    # ------------------------------------------------------- 版本生成
    def test_each_redaction_is_a_new_immutable_version(self) -> None:
        r1 = self._create(REDACTED_V1)
        r2 = self._create(REDACTED_V2)
        self.assertEqual(r1["redaction_no"], 1)
        self.assertEqual(r2["redaction_no"], 2)
        self.assertNotEqual(r1["redaction_id"], r2["redaction_id"])
        self.assertEqual(r1["source_version_id"], self.vid)
        self.assertEqual(r1["scope"], "institution")
        # 创建后不自动启用：当前指针为空，普通成员仍被遮蔽
        self.assertIsNone(
            self.h.repo.get_version(self.vid).current_redaction_id
        )
        listed = self.h.ctx.redactions.list_redactions(self.admin, self.vid)
        self.assertEqual([r["redaction_no"] for r in listed], [1, 2])

    def test_same_redacted_bytes_replay_existing_version(self) -> None:
        r1 = self._create(REDACTED_V1, key="rdc-1")
        again = self._create(REDACTED_V1, key="rdc-1")
        self.assertEqual(again["redaction_id"], r1["redaction_id"])
        self.assertTrue(again["replayed"])
        # 不同幂等键但相同字节：仍回放同一条，不产生新版本
        same_bytes = self._create(REDACTED_V1, key="rdc-1b")
        self.assertEqual(same_bytes["redaction_id"], r1["redaction_id"])
        self.assertEqual(
            len(self.h.ctx.redactions.list_redactions(self.admin, self.vid)), 1
        )

    def test_only_sensitive_feedback_can_be_redacted(self) -> None:
        syllabus = upload_material(
            self.h, self.admin,
            kind=MaterialKind.SYLLABUS.value,
            data="大纲".encode("utf-8"),
        )
        with self.assertRaises(ValidationError):
            self.h.ctx.redactions.create_redaction(
                self.admin,
                version_id=syllabus.version["version_id"],
                data="裁剪大纲".encode("utf-8"),
            )

    def test_redaction_must_differ_from_original(self) -> None:
        with self.assertRaises(ValidationError):
            self._create(ORIGINAL_TEXT)

    def test_only_home_institution_admin_manages_redactions(self) -> None:
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.redactions.create_redaction(
                self.admin_b, version_id=self.vid,
                data=REDACTED_V1.encode("utf-8"),
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.redactions.create_redaction(
                self.submitter, version_id=self.vid,
                data=REDACTED_V1.encode("utf-8"),
            )

    # ------------------------------------------------- 身份 -> 内容选择
    def test_authorized_identities_always_see_original(self) -> None:
        self._create(REDACTED_V1, activate=True)
        sealed = self._sealed_with_feedback()
        for actor in (self.admin, self.authority, self.auditor):
            view = self.h.ctx.packages.build_package_view(actor, sealed.package_id)
            entry = self._entry(view)
            self.assertEqual(entry["content_tier"], "original")
            self.assertNotIn("redaction_id", entry)
            meta, data, _ = self._download(actor, sealed.package_id)
            self.assertEqual(meta["content_tier"], "original")
            self.assertEqual(data, ORIGINAL_TEXT.encode("utf-8"))

    def test_assigned_reviewer_sees_original_even_when_redaction_active(self) -> None:
        self._create(REDACTED_V1, activate=True)
        sealed = self._sealed_with_feedback()
        self.h.ctx.reviews.assign_reviewer(
            self.authority,
            package_id=sealed.package_id,
            reviewer_id=self.reviewer.user_id,
        )
        meta, data, _ = self._download(self.reviewer, sealed.package_id)
        self.assertEqual(meta["content_tier"], "original")
        self.assertEqual(data, ORIGINAL_TEXT.encode("utf-8"))

    def test_submitter_sees_redacted_tier_after_activation(self) -> None:
        sealed = self._sealed_with_feedback()
        # 封存时无脱敏版本：普通成员完全遮蔽，下载 403
        view = self.h.ctx.packages.build_package_view(self.submitter, sealed.package_id)
        entry = self._entry(view)
        self.assertEqual(entry["content_tier"], "hidden")
        self.assertTrue(entry["redacted"])
        with self.assertRaises(PermissionDeniedError):
            self._download(self.submitter, sealed.package_id)

        # 仅创建不启用：依旧遮蔽
        r1 = self._create(REDACTED_V1)
        view = self.h.ctx.packages.build_package_view(self.submitter, sealed.package_id)
        self.assertEqual(self._entry(view)["content_tier"], "hidden")

        # 启用后：此后封存的包固定 v1，普通成员可见裁剪文
        self.h.ctx.redactions.activate_redaction(
            self.admin, redaction_id=r1["redaction_id"]
        )
        later = seal_new_package(self.h, self.admin, items=[self.item], title="启用后的新包")
        view = self.h.ctx.packages.build_package_view(self.submitter, later.package_id)
        entry = self._entry(view)
        self.assertEqual(entry["content_tier"], "redacted")
        self.assertEqual(entry["redaction_id"], r1["redaction_id"])
        meta, data, _ = self._download(self.submitter, later.package_id)
        self.assertEqual(meta["content_tier"], "redacted")
        self.assertEqual(meta["redaction_id"], r1["redaction_id"])
        self.assertEqual(data, REDACTED_V1.encode("utf-8"))
        self.assertNotEqual(data, ORIGINAL_TEXT.encode("utf-8"))

    def test_foreign_reviewer_never_falls_back_to_redacted_text(self) -> None:
        self._create(REDACTED_V1, activate=True)
        sealed = self._sealed_with_feedback()
        # 未被分配的外机构评审人：连包都打不开
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.reviewer, sealed.package_id)
        # 分配后取消：原文权即时收回，裁剪文也不对外机构开放
        req = self.h.ctx.reviews.assign_reviewer(
            self.authority, package_id=sealed.package_id,
            reviewer_id=self.reviewer.user_id,
        )
        self.h.ctx.reviews.cancel_request(
            self.authority, request_id=req["request_id"], reason="改派"
        )
        with self.assertRaises(PermissionDeniedError):
            self._download(self.reviewer, sealed.package_id)

    # --------------------------------------------- 切换不改旧反馈的显示
    def test_switching_version_does_not_change_sealed_package(self) -> None:
        # 封存前已启用 v1，封存把 v1 固定进历史包
        r1 = self._create(REDACTED_V1, activate=True)
        sealed = self._sealed_with_feedback()
        pid = sealed.package_id

        view1 = self.h.ctx.packages.build_package_view(self.submitter, pid)
        self.assertEqual(self._entry(view1)["redaction_id"], r1["redaction_id"])
        _, data_v1, _ = self._download(self.submitter, pid)
        self.assertEqual(data_v1, REDACTED_V1.encode("utf-8"))

        # 之后再脱敏、切换到 v2
        r2 = self._create(REDACTED_V2, activate=True)
        self.assertEqual(
            self.h.repo.get_version(self.vid).current_redaction_id,
            r2["redaction_id"],
        )

        # 旧包：普通成员依旧读到固定的 v1，旧反馈仍可读、显示不变
        view2 = self.h.ctx.packages.build_package_view(self.submitter, pid)
        entry2 = self._entry(view2)
        self.assertEqual(entry2["content_tier"], "redacted")
        self.assertEqual(entry2["redaction_id"], r1["redaction_id"])
        self.assertTrue(entry2["pinned"])
        _, data_after, _ = self._download(self.submitter, pid)
        self.assertEqual(data_after, REDACTED_V1.encode("utf-8"))

        # 旧脱敏版本按其自身 id 也仍可读到，字节不变
        _, old_bytes = self.h.ctx.redactions.download_redaction(
            self.submitter, r1["redaction_id"]
        )
        self.assertEqual(old_bytes, REDACTED_V1.encode("utf-8"))

        # 授权人在旧包始终看原文，不受任何切换影响
        _, admin_bytes, _ = self._download(self.admin, pid)
        self.assertEqual(admin_bytes, ORIGINAL_TEXT.encode("utf-8"))

    def test_sealed_package_without_redaction_never_retroactively_shows_one(self) -> None:
        # 封存时不存在任何脱敏版本
        sealed = self._sealed_with_feedback()
        pid = sealed.package_id
        self._create(REDACTED_V1, activate=True)
        # 历史包固定的是“当时完全遮蔽”：不回落显示裁剪文
        view = self.h.ctx.packages.build_package_view(self.submitter, pid)
        self.assertEqual(self._entry(view)["content_tier"], "hidden")
        with self.assertRaises(PermissionDeniedError):
            self._download(self.submitter, pid)

    def test_new_package_after_switch_shows_new_redaction(self) -> None:
        r1 = self._create(REDACTED_V1, activate=True)
        old = self._sealed_with_feedback()
        r2 = self._create(REDACTED_V2, activate=True)
        new = self._sealed_with_feedback()
        # 旧包固定 v1，新包固定 v2
        self.assertEqual(
            self._entry(
                self.h.ctx.packages.build_package_view(self.submitter, old.package_id)
            )["redaction_id"],
            r1["redaction_id"],
        )
        new_entry = self._entry(
            self.h.ctx.packages.build_package_view(self.submitter, new.package_id)
        )
        self.assertEqual(new_entry["redaction_id"], r2["redaction_id"])
        _, data, _ = self._download(self.submitter, new.package_id)
        self.assertEqual(data, REDACTED_V2.encode("utf-8"))

    def test_draft_package_follows_current_pointer(self) -> None:
        pkg = self.h.ctx.packages.create_package(self.admin, title="草稿包")
        pid = pkg["package_id"]
        self.h.ctx.packages.add_entry(
            self.admin, package_id=pid, version_id=self.vid
        )
        r1 = self._create(REDACTED_V1)
        # 未启用：草稿包也遮蔽
        view = self.h.ctx.packages.build_package_view(self.submitter, pid)
        self.assertEqual(self._entry(view)["content_tier"], "hidden")
        # 启用 v1：草稿跟随
        self.h.ctx.redactions.activate_redaction(
            self.admin, redaction_id=r1["redaction_id"]
        )
        view = self.h.ctx.packages.build_package_view(self.submitter, pid)
        self.assertEqual(self._entry(view)["redaction_id"], r1["redaction_id"])
        # 切到 v2：草稿跟随新指针
        r2 = self._create(REDACTED_V2, activate=True)
        view = self.h.ctx.packages.build_package_view(self.submitter, pid)
        self.assertEqual(self._entry(view)["redaction_id"], r2["redaction_id"])

    def test_manifest_fingerprint_unchanged_by_redaction_lifecycle(self) -> None:
        r1 = self._create(REDACTED_V1, activate=True)
        sealed = self._sealed_with_feedback()
        fingerprint = sealed.sealed["manifest_fingerprint"]
        self._create(REDACTED_V2, activate=True)
        self.h.ctx.redactions.activate_redaction(
            self.admin, redaction_id=r1["redaction_id"]
        )
        view = self.h.ctx.packages.build_package_view(self.admin, sealed.package_id)
        self.assertEqual(view["manifest_fingerprint"], fingerprint)

    # ----------------------------------------------------------- 迁移
    def test_schema_v1_to_v2_migration_preserves_data(self) -> None:
        import os
        import sqlite3
        import tempfile

        fd, path = tempfile.mkstemp(prefix="qe-migrate-", suffix=".db")
        os.close(fd)
        os.unlink(path)
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE blobs (
                sha256 TEXT PRIMARY KEY, data BLOB NOT NULL, media_type TEXT NOT NULL,
                size INTEGER NOT NULL, created_at TEXT NOT NULL
            );
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
                withdrawn INTEGER NOT NULL DEFAULT 0, withdrawn_at TEXT
            );
            CREATE TABLE entries (
                entry_id TEXT PRIMARY KEY, package_id TEXT NOT NULL,
                material_id TEXT NOT NULL, version_id TEXT NOT NULL,
                sha256 TEXT NOT NULL, kind TEXT NOT NULL,
                sensitivity TEXT NOT NULL, added_at TEXT NOT NULL,
                UNIQUE(package_id, version_id)
            );
            INSERT INTO materials(material_id, institution_id, kind, sensitivity,
                title, current_version_id, withdrawn, created_at)
            VALUES ('mat_old', 'inst-a', 'enterprise_feedback', 'sensitive',
                '旧反馈', NULL, 0, '2026-09-01T00:00:00+00:00');
            INSERT INTO versions(version_id, material_id, institution_id, sha256,
                size, media_type, version_no, created_by, created_at, withdrawn)
            VALUES ('ver_old', 'mat_old', 'inst-a', 'abcd', 4,
                'text/plain', 1, 'admin-a', '2026-09-01T00:00:00+00:00', 0);
            PRAGMA user_version = 1;
            """
        )
        conn.commit()
        conn.close()

        ctx = ApplicationContext(
            path, clock=self.h.clock, ids=self.h.ids
        )
        try:
            user_version = ctx.repo._conn.execute(
                "PRAGMA user_version"
            ).fetchone()[0]
            self.assertEqual(user_version, 2)
            version = ctx.repo.get_version("ver_old")
            self.assertIsNotNone(version)
            self.assertIsNone(version.current_redaction_id)
            # 迁移后新功能可用：指针列存在且可写（更新 0 行也说明列可用）
            ok = ctx.repo.pin_entry_redaction("pkg_x", "ver_old", None)
            self.assertFalse(ok)
            cols = {
                r[1] for r in ctx.repo._conn.execute("PRAGMA table_info(entries)")
            }
            self.assertIn("pinned_redaction_id", cols)
        finally:
            ctx.close()
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(path + suffix)
                except FileNotFoundError:
                    pass


if __name__ == "__main__":
    unittest.main()
