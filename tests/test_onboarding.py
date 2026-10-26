"""首次登录引导：onboarded 列迁移、标记接口与认证负载的回归测试。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import auth


class OnboardingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(auth, "DB_PATH", Path(self.temp.name) / "users.db")
        self.db_patch.start()
        auth.init_db()
        conn = auth.get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES ('u1', 'x')",
            )
            conn.commit()
            self.user_id = conn.execute(
                "SELECT id FROM users WHERE username='u1'",
            ).fetchone()["id"]
        finally:
            conn.close()

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.temp.cleanup()

    def test_column_migration_and_default(self) -> None:
        conn = auth.get_db()
        try:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
            row = conn.execute(
                "SELECT onboarded FROM users WHERE id = ?", (self.user_id,),
            ).fetchone()
        finally:
            conn.close()
        self.assertIn("onboarded", columns)
        self.assertEqual(row["onboarded"], 0)

    def test_mark_onboarded_idempotent(self) -> None:
        auth.mark_onboarded(self.user_id)
        auth.mark_onboarded(self.user_id)  # 幂等
        conn = auth.get_db()
        try:
            row = conn.execute(
                "SELECT onboarded FROM users WHERE id = ?", (self.user_id,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["onboarded"], 1)

    def test_current_user_payload_carries_onboarded(self) -> None:
        user = auth.get_user_by_username("u1")
        self.assertIsNotNone(user)
        self.assertIn("onboarded", user)
        self.assertFalse(user["onboarded"])
        auth.mark_onboarded(self.user_id)
        user = auth.get_user_by_username("u1")
        self.assertTrue(user["onboarded"])


if __name__ == "__main__":
    unittest.main()
