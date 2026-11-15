"""plan_updated 事件去重与终态停播（2026-11-15 压测复盘）回归测试。

证据：driver-20261115.log 同一秒广播 2~3 条内容完全相同的"计划更新
（6 项）"（全天 12 个重复时间点、19 条多余事件）；任务 completed
（17:11:56）后仍继续广播 3 次（17:12:12×2、17:12:20）。

修复（Tools/Plan.py）：
- push_plan_update 按条目内容指纹（json→sha256）去重，终态快照只广播一次；
- _commit（AddPlan/UpdatePlan/DeletePlan 路径）在任务终态后不再广播，
  审计与权威 JSON 照常落盘。
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from core.TaskState import MissionState, MissionStore, Phase
from Tools.Plan import (
    create_add_plan_tool,
    create_update_plan_tool,
    push_plan_update,
)


def _chunk_text(chunk) -> str:
    content = getattr(chunk, "content", chunk)
    if isinstance(content, str):
        return content
    return "".join(getattr(b, "text", str(b)) for b in content)


def _mission() -> MissionState:
    mission = MissionState(
        target="10.10.10.5", goal="对授权目标完成渗透测试评估", authorized=True,
    )
    mission.transition(Phase.RECON, "t")
    mission.transition(Phase.ANALYSIS, "t")
    return mission


class PlanEventDedupeTest(unittest.TestCase):
    """同内容变更只广播一次；内容真实变化仍正常广播。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "m.json")
        self.mission = _mission()
        self.events: list[tuple[str, dict]] = []

        def callback(event_type: str, **payload) -> None:
            self.events.append((event_type, payload))

        self.callback = callback
        self.add = create_add_plan_tool(self.mission, self.store, callback)
        self.update = create_update_plan_tool(self.mission, self.store, callback)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _plan_events(self) -> int:
        return sum(1 for etype, _ in self.events if etype == "plan_updated")

    def test_add_then_duplicate_update_emits_once(self) -> None:
        asyncio.run(self.add.call(id=1, content="侦察目标端口", phase="recon"))
        self.assertEqual(self._plan_events(), 1)

        # 同值 UpdatePlan ×2：内容指纹一致 → 只广播一次
        asyncio.run(self.update.call(id="p1", status="in_progress"))
        asyncio.run(self.update.call(id="p1", status="in_progress"))
        self.assertEqual(self._plan_events(), 2)

        # 内容真实变化 → 正常广播
        asyncio.run(self.update.call(id="p1", status="failed", evidence="端口不可达"))
        self.assertEqual(self._plan_events(), 3)
        self.assertEqual(self.mission.plan_items[0]["status"], "failed")

    def test_identical_snapshot_push_deduped(self) -> None:
        # 直接模拟收尾多路径 finalize：同内容重复 push 只发一次
        push_plan_update(self.mission, self.callback)
        push_plan_update(self.mission, self.callback)
        push_plan_update(self.mission, self.callback)
        self.assertEqual(self._plan_events(), 1)

    def test_no_callback_is_noop(self) -> None:
        # event_callback=None（CLI 静默路径）不应抛错
        push_plan_update(self.mission, None)


class TerminalPlanBroadcastTest(unittest.TestCase):
    """终态后：计划维护工具不再广播；终态快照只广播一次。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "m.json")
        self.mission = _mission()
        self.events: list[tuple[str, dict]] = []
        self.callback = lambda etype, **payload: self.events.append((etype, payload))
        self.add = create_add_plan_tool(self.mission, self.store, self.callback)
        self.update = create_update_plan_tool(self.mission, self.store, self.callback)
        asyncio.run(self.add.call(id=1, content="侦察目标端口", phase="recon"))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _plan_events(self) -> int:
        return sum(1 for etype, _ in self.events if etype == "plan_updated")

    def test_update_after_terminal_emits_no_event(self) -> None:
        self.mission.transition(Phase.COMPLETED, "test")
        result = _chunk_text(asyncio.run(self.update.call(
            id="p1", status="completed", evidence="已验证",
        )))
        # 变更本身生效（权威 JSON / 审计照常），但 SSE 不再广播
        self.assertIn("已更新", result)
        self.assertEqual(self.mission.plan_items[0]["status"], "completed")
        self.assertEqual(self._plan_events(), 1)  # 仅 AddPlan 那一条

    def test_terminal_snapshot_broadcast_exactly_once(self) -> None:
        # complete_mission 形态：终态固化后的第一条快照允许广播一次
        # （前端依赖它看到 in_progress→completed/skipped 的最终标记），
        # 之后的任何再广播（同内容或内容又变）一律拦截。
        self.mission.transition(Phase.COMPLETED, "test")
        for item in self.mission.plan_items:
            item["status"] = "completed"
        push_plan_update(self.mission, self.callback)
        self.assertEqual(self._plan_events(), 2)

        # 同内容重放（run_mission 失败收敛路径重复 finalize）
        push_plan_update(self.mission, self.callback)
        # 终态后又发生内容变化（越权变更）→ 仍不再广播
        self.mission.plan_items[0]["status"] = "failed"
        push_plan_update(self.mission, self.callback)
        self.assertEqual(self._plan_events(), 2)


if __name__ == "__main__":
    unittest.main()
