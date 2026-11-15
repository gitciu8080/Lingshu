"""会话任务协程结构性兜底与 mission_end payload 契约（2026-11-15 压测复盘）。

背景：畸形归档曾以 SystemExit 穿透 except Exception 杀死整个 uvicorn
进程（源头已改 RuntimeError，21317c0）；此处回归 _run_and_cleanup 的
结构性兜底——任务级 BaseException 永不升级为进程级死亡。

同时锁定 mission_end 事件契约：payload 必须含 success/flag/phase，
workbench 驱动器（workbench_nss 等）据此直接判定成败，无需再
GET /api/session/{id} 轮询兜底。
"""
from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import api


def _ctx(cancel_requested: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        input_queue=asyncio.Queue(),
        agent_tasks=set(),
        steering_state={},
        cancel_requested=cancel_requested,
        tool_buffers={},
        user_id=1,
        task=None,
        pending_approval_request=None,
        approval_decision_submitted=False,
    )


def _completed_mission() -> SimpleNamespace:
    from core.TaskState import Phase

    return SimpleNamespace(
        success=True,
        phase=Phase.COMPLETED,
        flag="NSSCTF{ok}",
        summary="测试摘要",
    )


class SessionTaskIsolationTest(unittest.TestCase):
    """任务协程异常收敛：BaseException 不升级为进程级死亡。"""

    def _run(self, side_effect, ctx=None):
        events: list[tuple[str, dict]] = []
        callback = lambda etype, **payload: events.append((etype, payload))
        submitted: list[list[dict]] = []

        async def fake_submit(operations, **kwargs):
            submitted.append(list(operations))

        async def fake_flush():
            return None

        with patch.object(api, "run_mission", new=AsyncMock(side_effect=side_effect)), \
             patch.object(api, "session_store", new=SimpleNamespace(
                 get_session=lambda sid: {})), \
             patch.object(api.ps, "submit", new=fake_submit), \
             patch.object(api, "_flush_persistence", new=fake_flush), \
             patch.object(api, "_save_long_term_memory", new=lambda *a, **k: None):
            asyncio.run(api._run_and_cleanup(
                session_id="isolation-test-0001",
                ctx=ctx or _ctx(),
                target="10.10.10.5", goal="测试", model_ver="Min",
                provider="deepseek", callback=callback,
            ))
        return events, submitted

    def test_system_exit_converges_to_failed_session(self) -> None:
        # 2026-11-15 实测复现形态：任务协程内抛 SystemExit
        events, submitted = self._run(SystemExit(1))
        # 1) 异常被 _run_and_cleanup 捕获，协程正常返回（不 re-raise）
        error_events = [p for etype, p in events if etype == "error"]
        self.assertTrue(any("SystemExit" in str(p.get("message")) for p in error_events))
        # 2) mission_end 事件照常发出且 status=failed
        end_events = [p for etype, p in events if etype == "mission_end"]
        self.assertEqual(len(end_events), 1)
        self.assertEqual(end_events[0].get("status"), "failed")
        # 3) 会话落库操作含 status=failed（uvicorn 进程存活语义）
        fields = {}
        for ops in submitted:
            for op in ops:
                if op.get("type") == "session_update":
                    fields.update(op.get("fields") or {})
        self.assertEqual(fields.get("status"), "failed")
        self.assertEqual(fields.get("phase"), "failed")

    def test_runtime_error_converges_to_failed_session(self) -> None:
        events, submitted = self._run(RuntimeError("[安全错误] 解压失败: 路径冲突"))
        end_events = [p for etype, p in events if etype == "mission_end"]
        self.assertEqual(end_events[0].get("status"), "failed")
        self.assertTrue(any(
            "解压失败" in str(p.get("message")) for etype, p in events if etype == "error"
        ))

    def test_keyboard_interrupt_propagates(self) -> None:
        # KeyboardInterrupt 是运维停止服务的信号：保持向上传递
        with self.assertRaises(KeyboardInterrupt):
            self._run(KeyboardInterrupt())


class MissionEndPayloadTest(unittest.TestCase):
    """mission_end payload 必须透出 success/flag/phase。"""

    def _run(self, mission) -> list[tuple[str, dict]]:
        events: list[tuple[str, dict]] = []
        callback = lambda etype, **payload: events.append((etype, payload))

        async def fake_submit(operations, **kwargs):
            return None

        async def fake_flush():
            return None

        with patch.object(api, "run_mission", new=AsyncMock(return_value=mission)), \
             patch.object(api, "session_store", new=SimpleNamespace(
                 get_session=lambda sid: {})), \
             patch.object(api.ps, "submit", new=fake_submit), \
             patch.object(api, "_flush_persistence", new=fake_flush), \
             patch.object(api, "_save_long_term_memory", new=lambda *a, **k: None):
            asyncio.run(api._run_and_cleanup(
                session_id="payload-test-0001",
                ctx=_ctx(),
                target="10.10.10.5", goal="测试", model_ver="Min",
                provider="deepseek", callback=callback,
            ))
        return events

    def test_success_path_carries_success_flag_phase(self) -> None:
        events = self._run(_completed_mission())
        end_events = [p for etype, p in events if etype == "mission_end"]
        self.assertEqual(len(end_events), 1)
        payload = end_events[0]
        self.assertEqual(payload.get("status"), "completed")
        self.assertIs(payload.get("success"), True)
        self.assertEqual(payload.get("flag"), "NSSCTF{ok}")
        self.assertEqual(payload.get("phase"), "completed")

    def test_failed_path_carries_explicit_fields(self) -> None:
        from core.TaskState import Phase

        mission = SimpleNamespace(
            success=False, phase=Phase.FAILED, flag=None, summary="失败摘要",
        )
        events = self._run(mission)
        payload = [p for etype, p in events if etype == "mission_end"][0]
        self.assertEqual(payload.get("status"), "failed")
        self.assertIs(payload.get("success"), False)
        self.assertIsNone(payload.get("flag"))
        self.assertEqual(payload.get("phase"), "failed")


class MissionEndPersistenceTest(unittest.TestCase):
    """mission_end 落库映射与 SSE 回放重建均保留完整终态字段。"""

    def test_persistence_mapping_keeps_terminal_fields(self) -> None:
        from core.session_events import message_operation

        op = message_operation("s1", "mission_end", {
            "message": "任务执行已结束",
            "status": "completed",
            "success": True,
            "flag": "NSSCTF{ok}",
            "phase": "completed",
        })
        import json as _json

        content = _json.loads(op["content"])
        self.assertEqual(content["status"], "completed")
        self.assertIs(content["success"], True)
        self.assertEqual(content["flag"], "NSSCTF{ok}")
        self.assertEqual(content["phase"], "completed")

    def test_replay_rebuilds_terminal_fields(self) -> None:
        import json as _json

        stored = _json.dumps({
            "message": "任务已结束", "status": "failed",
            "success": False, "flag": None, "phase": "failed",
        }, ensure_ascii=False)
        event = api._message_to_event({
            "event_type": "mission_end", "session_id": "s1",
            "agent_name": "system", "seq": 9, "content": stored,
        })
        self.assertIs(event["success"], False)
        self.assertEqual(event["status"], "failed")
        self.assertEqual(event["phase"], "failed")

    def test_replay_tolerates_legacy_plain_text(self) -> None:
        # 旧版本落库的「状态: cancelled」纯文本：回放降级为 content，不抛错
        event = api._message_to_event({
            "event_type": "mission_end", "session_id": "s1",
            "agent_name": "system", "seq": 9, "content": "状态: cancelled",
        })
        self.assertEqual(event.get("content"), "状态: cancelled")


if __name__ == "__main__":
    unittest.main()
