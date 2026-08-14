"""Regression tests for the legacy WebUI streaming hot path."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

import api


class LegacyStreamSnapshotThrottleTest(unittest.TestCase):
    def test_character_deltas_do_not_commit_one_snapshot_per_character(self) -> None:
        context = api.SessionContext(
            session_id="stream-test",
            user_id=1,
            input_queue=asyncio.Queue(),
        )
        persisted: list[tuple[str, dict]] = []

        def persist(_session_id: str, event_type: str, payload: dict):
            persisted.append((event_type, dict(payload)))
            return None

        with (
            patch.object(api, "_persist_event", side_effect=persist),
            patch.object(api.session_store, "upsert_stream_snapshot") as upsert,
            patch.object(api.session_store, "delete_stream_snapshot") as delete,
            patch.object(api.time, "monotonic", side_effect=[10.0, 10.05, 10.25]),
        ):
            callback = api._make_session_callback("stream-test", context)
            callback("text_start", agent="Brain")
            callback("text_delta", agent="Brain", delta="甲")
            callback("text_delta", agent="Brain", delta="乙")
            callback("text_delta", agent="Brain", delta="丙")
            callback("text_end", agent="Brain")

        self.assertEqual(upsert.call_count, 2)
        self.assertEqual(upsert.call_args_list[0].args[-1], "甲")
        self.assertEqual(upsert.call_args_list[1].args[-1], "甲乙丙")
        delete.assert_called_once()
        end_payload = next(payload for event, payload in persisted if event == "text_end")
        self.assertEqual(end_payload["full_text"], "甲乙丙")


class AsyncPersistenceBatchTest(unittest.IsolatedAsyncioTestCase):
    async def test_live_callback_batches_snapshot_and_message_operations(self) -> None:
        context = api.SessionContext(
            session_id="batch-test",
            user_id=1,
            input_queue=asyncio.Queue(),
        )
        captured: list[list[dict]] = []

        def apply_batch(operations: list[dict]):
            captured.append(operations)
            return [1 if operation.get("type") == "message" else None for operation in operations]

        api._persistence_queue = asyncio.Queue(maxsize=100)
        worker = asyncio.create_task(api._persistence_worker())
        try:
            with patch.object(api.session_store, "apply_persistence_batch", side_effect=apply_batch):
                callback = api._make_session_callback("batch-test", context)
                callback("text_start", agent="Brain")
                callback("text_delta", agent="Brain", delta="流")
                callback("text_end", agent="Brain")
                await api._flush_persistence()
        finally:
            worker.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await worker
            api._persistence_queue = None

        operation_types = [
            operation["type"]
            for batch in captured
            for operation in batch
        ]
        self.assertEqual(
            operation_types,
            ["message", "snapshot_upsert", "snapshot_delete", "message"],
        )


class StreamReconnectSnapshotTest(unittest.IsolatedAsyncioTestCase):
    async def test_reconnect_snapshot_keeps_active_block_id(self) -> None:
        context = api.SessionContext(
            session_id="reconnect-test",
            user_id=1,
            input_queue=asyncio.Queue(),
        )
        context.stream_buffers["text:Attack"] = "中断前已经返回的内容"
        context.stream_blocks["text:Attack"] = "text:Attack:7"

        async def empty_messages(*_args, **_kwargs):
            return []

        with patch.object(asyncio, "to_thread", side_effect=empty_messages):
            generator = api._session_event_generator("reconnect-test", context, 0)
            frame = await anext(generator)
            await generator.aclose()

        self.assertIn('"type": "stream_snapshot"', frame)
        self.assertIn('"block_id": "text:Attack:7"', frame)


if __name__ == "__main__":
    unittest.main()
