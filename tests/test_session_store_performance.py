"""SQLite batch persistence and cursor pagination regression tests."""

from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import auth
import session_store


class SessionStorePerformanceTest(unittest.TestCase):
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
            conn.commit()
        finally:
            conn.close()
        session_store.init_sessions_db()
        session_store.create_session(1, "127.0.0.1", session_id="page-test")

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_latest_history_and_before_cursor(self) -> None:
        for index in range(1, 6):
            session_store.add_message("page-test", "agent", f"消息 {index}")

        latest, _, has_more = session_store.get_history_page(
            "page-test", limit=2,
        )
        self.assertEqual([row["seq"] for row in latest], [4, 5])
        self.assertTrue(has_more)

        older, _, has_more = session_store.get_history_page(
            "page-test", before_seq=4, limit=2, include_snapshots=False,
        )
        self.assertEqual([row["seq"] for row in older], [2, 3])
        self.assertTrue(has_more)

        oldest, _, has_more = session_store.get_history_page(
            "page-test", before_seq=2, limit=2, include_snapshots=False,
        )
        self.assertEqual([row["seq"] for row in oldest], [1])
        self.assertFalse(has_more)

    def test_batch_assigns_ordered_sequences_and_updates_snapshot(self) -> None:
        results = session_store.apply_persistence_batch([
            {
                "type": "message", "session_id": "page-test",
                "role": "agent", "content": "A", "event_type": "text_end",
                "agent_name": "Brain",
            },
            {
                "type": "snapshot_upsert", "session_id": "page-test",
                "block_id": "b1", "agent_name": "Brain",
                "stream_type": "text", "content": "未完成",
            },
            {
                "type": "message", "session_id": "page-test",
                "role": "agent", "content": "B", "event_type": "text_end",
                "agent_name": "Brain",
            },
        ])
        self.assertEqual(results, [1, None, 2])
        messages, snapshots, _ = session_store.get_history_page(
            "page-test", limit=10,
        )
        self.assertEqual([row["content"] for row in messages], ["A", "B"])
        self.assertEqual(snapshots[0]["content"], "未完成")

    def test_parallel_writers_are_serialized_without_lock_errors(self) -> None:
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(
                    session_store.add_message,
                    "page-test",
                    "agent",
                    f"并发消息 {index}",
                )
                for index in range(40)
            ]
            sequences = [future.result() for future in futures]

        self.assertEqual(sorted(sequences), list(range(1, 41)))
        messages = session_store.get_all_messages("page-test")
        self.assertEqual(len(messages), 40)
        self.assertEqual([row["seq"] for row in messages], list(range(1, 41)))


if __name__ == "__main__":
    unittest.main()
