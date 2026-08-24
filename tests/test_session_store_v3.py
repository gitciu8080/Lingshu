"""session_store v0.3.0 测试：blob 引用表、删除孤儿判定、Workspace 字段。

覆盖计划验收项：
- 删除测试：删除会话只清理所属引用；共享 blob 在最后一个引用删除前保留。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import core.auth as auth
import core.session_store as session_store


class SessionStoreV3Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(
            auth,
            "DB_PATH",
            Path(self.temp_dir.name) / "sessions.db",
        )
        self.db_patch.start()
        conn = auth.get_db()
        try:
            conn.execute(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL)"
            )
            conn.execute("INSERT INTO users (id, username) VALUES (1, 'tester')")
            conn.execute("INSERT INTO users (id, username) VALUES (2, 'tester2')")
            conn.commit()
        finally:
            conn.close()
        session_store.init_sessions_db()

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.temp_dir.cleanup()


class BlobRefTest(SessionStoreV3Test):
    def test_add_and_list_blob_ref(self) -> None:
        session_store.create_session(1, "t", session_id="sess-blob")
        session_store.add_blob_ref("sess-blob", "a" * 64, "task.zip", 1234)
        refs = session_store.list_blob_refs("sess-blob")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["sha256"], "a" * 64)
        self.assertEqual(refs[0]["original_name"], "task.zip")
        self.assertEqual(refs[0]["size"], 1234)

    def test_add_same_blob_twice_is_idempotent(self) -> None:
        session_store.create_session(1, "t", session_id="sess-idem")
        session_store.add_blob_ref("sess-idem", "b" * 64, "x.bin")
        session_store.add_blob_ref("sess-idem", "b" * 64, "x.bin")
        self.assertEqual(len(session_store.list_blob_refs("sess-idem")), 1)


class DeleteSessionBlobSemanticsTest(SessionStoreV3Test):
    def test_delete_returns_orphaned_blob_when_last_reference_removed(self) -> None:
        session_store.create_session(1, "t", session_id="sess-own")
        session_store.add_blob_ref("sess-own", "c" * 64, "only.bin", 5)
        orphaned = session_store.delete_session("sess-own")
        self.assertEqual(orphaned, ["c" * 64])
        self.assertIsNone(session_store.get_session("sess-own"))

    def test_shared_blob_survives_first_delete(self) -> None:
        """两个会话共享 blob：删除其一不得产生孤儿，第二个删除才孤儿。"""
        session_store.create_session(1, "t", session_id="sess-a")
        session_store.create_session(1, "t", session_id="sess-b")
        session_store.add_blob_ref("sess-a", "d" * 64, "shared.zip", 9)
        session_store.add_blob_ref("sess-b", "d" * 64, "shared.zip", 9)

        orphaned_a = session_store.delete_session("sess-a")
        self.assertEqual(orphaned_a, [], "共享 blob 仍有引用，不得列为孤儿")
        # 会话 B 的引用仍在
        self.assertEqual(len(session_store.list_blob_refs("sess-b")), 1)

        orphaned_b = session_store.delete_session("sess-b")
        self.assertEqual(orphaned_b, ["d" * 64], "最后一个引用删除后才孤儿")

    def test_delete_cleans_all_session_data(self) -> None:
        session_store.create_session(1, "t", session_id="sess-full")
        session_store.add_message("sess-full", "agent", "内容")
        session_store.upsert_stream_snapshot("sess-full", "r1", "b1", "Recon", "text", "x")
        session_store.add_blob_ref("sess-full", "e" * 64, "f", 1)

        session_store.delete_session("sess-full")

        self.assertEqual(session_store.get_messages("sess-full"), [])
        self.assertEqual(session_store.get_stream_snapshots("sess-full"), [])
        self.assertEqual(session_store.list_blob_refs("sess-full"), [])
        self.assertIsNone(session_store.get_session("sess-full"))


class SessionWorkspaceFieldsTest(SessionStoreV3Test):
    def test_new_fields_exist_with_defaults(self) -> None:
        session_store.create_session(1, "t", session_id="sess-fields")
        row = session_store.get_session("sess-fields")
        self.assertEqual(row["workspace_id"], "")
        self.assertEqual(row["workspace_version"], 0)
        self.assertEqual(row["resume_status"], "fresh")
        self.assertEqual(row["checkpoint_seq"], 0)

    def test_update_workspace_fields_via_whitelist(self) -> None:
        session_store.create_session(1, "t", session_id="sess-update")
        session_store.update_session(
            "sess-update",
            workspace_id="u1-sess-update",
            workspace_version=2,
            resume_status="resumable",
            checkpoint_seq=7,
        )
        row = session_store.get_session("sess-update")
        self.assertEqual(row["workspace_id"], "u1-sess-update")
        self.assertEqual(row["workspace_version"], 2)
        self.assertEqual(row["resume_status"], "resumable")
        self.assertEqual(row["checkpoint_seq"], 7)

    def test_legacy_schema_migration_adds_columns(self) -> None:
        """旧库（无 v3 列）init_sessions_db() 后自动补列。"""
        # 模拟旧 schema：先删掉新列再调用 init 迁移
        conn = auth.get_db()
        try:
            conn.execute("ALTER TABLE sessions DROP COLUMN workspace_id")
            conn.execute("ALTER TABLE sessions DROP COLUMN workspace_version")
            conn.execute("ALTER TABLE sessions DROP COLUMN resume_status")
            conn.execute("ALTER TABLE sessions DROP COLUMN checkpoint_seq")
            conn.commit()
        finally:
            conn.close()
        session_store.init_sessions_db()
        session_store.create_session(1, "t", session_id="sess-legacy")
        row = session_store.get_session("sess-legacy")
        self.assertEqual(row["workspace_id"], "")
        self.assertEqual(row["resume_status"], "fresh")


if __name__ == "__main__":
    unittest.main()
