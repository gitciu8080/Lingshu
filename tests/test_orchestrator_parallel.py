"""标准模式 Orchestrator 后台并行派遣与 Brain 顾问测试。

覆盖 P5（recon/reverse background=true / check_experts / 主循环窥视通道）
与 P6（consult_brain 挂载与咨询语义）。审计链保留性经事件断言锁定。
fast 模式行为由 tests/test_parallel_experts.py 与 test_fast_mode.py 锁定，此处不重复。
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agent.Orchestrator import _REPORT_RETURN_LIMIT, _bounded_report, create_orchestrator_agent
from core.TaskState import MissionState, MissionStore, Phase
from main import _fast_pending_report_hint


def _chunk_text(chunk) -> str:
    content = getattr(chunk, "content", chunk)
    if isinstance(content, str):
        return content
    return "".join(getattr(b, "text", str(b)) for b in content)


def _expert(name: str) -> SimpleNamespace:
    return SimpleNamespace(name=name)


def _mission() -> MissionState:
    mission = MissionState(target="127.0.0.1", goal="对授权目标完成渗透测试评估", authorized=True)
    mission.transition(Phase.RECON, "test")
    mission.transition(Phase.ANALYSIS, "test")
    return mission


def _fetch_tool(agent, name: str):
    """取工具；不存在时返回 None（不假设 toolkit 的缺失行为）。"""
    try:
        return asyncio.run(agent.toolkit.get_tool(name))
    except Exception:
        return None


class OrchestratorParallelTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "mission.json")
        self.mission = _mission()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _orchestrator(self, brain_agent=None):
        orchestrator = create_orchestrator_agent(
            model=SimpleNamespace(),
            recon_agent=_expert("Ethan - 网络侦察专家"),
            attack_agent=_expert("Mike - Web 渗透专家"),
            reserve_agent=_expert("Ryan - 逆向程序专家"),
            mission=self.mission,
            store=self.store,
            event_callback=None,
            approval_callback=None,
            scope_registry=None,
            max_iters=5,
            brain_agent=brain_agent,
        )
        self.bg = orchestrator._lingshu_bg
        return orchestrator

    def _tool(self, agent, name: str):
        return asyncio.run(agent.toolkit.get_tool(name))

    # ── P5：后台派遣 ──────────────────────────────────────────────

    def test_background_recon_returns_handle_then_collectable(self) -> None:
        orchestrator = self._orchestrator()
        dispatch = self._tool(orchestrator, "dispatch_recon")
        check = self._tool(orchestrator, "check_experts")

        async def run() -> tuple[str, str]:
            handle = _chunk_text(await dispatch.call(focus="端口补扫", background=True))
            collected = _chunk_text(await check.call(wait=True, timeout=5))
            return handle, collected

        with patch(
            "agent.Orchestrator.run_expert_reply_with_continuation",
            new=AsyncMock(return_value="侦察完成：80/tcp 开放"),
        ):
            handle, collected = asyncio.run(run())
        self.assertIn("recon#", handle)
        self.assertIn("后台", handle)
        self.assertIn("已收取 1 份报告", collected)
        self.assertIn("侦察完成", collected)
        # 收取后清空
        self.assertEqual(self.bg["ready"], [])
        # 审计链保留：后台路径记录了派遣与后台发起事件
        actions = [str(getattr(e, "action", "")) for e in self.mission.events]
        self.assertIn("dispatch_recon", actions)
        self.assertIn("dispatch_background", actions)

    def test_same_role_busy_rejected_and_hint_fires(self) -> None:
        orchestrator = self._orchestrator()
        dispatch = self._tool(orchestrator, "dispatch_recon")

        async def run() -> None:
            released = asyncio.Event()
            started = asyncio.Event()

            async def slow_expert(*args, **kwargs):
                started.set()
                await released.wait()
                return "慢速侦察报告"

            with patch(
                "agent.Orchestrator.run_expert_reply_with_continuation",
                new=slow_expert,
            ):
                first = _chunk_text(await dispatch.call(focus="A", background=True))
                self.assertIn("recon#", first)
                await asyncio.wait_for(started.wait(), 2)
                busy = _chunk_text(await dispatch.call(focus="B", background=True))
                self.assertIn("正在执行", busy)
                self.assertIn("check_experts", busy)
                released.set()
                # 后台完成 → ready 队列非空 → 主循环窥视通道有提示
                await asyncio.sleep(0.05)
                self.assertTrue(self.bg["ready"])
                self.assertIsNotNone(_fast_pending_report_hint(orchestrator))
                # 收取后提示消失
                check = await orchestrator.toolkit.get_tool("check_experts")
                collected = _chunk_text(await check.call(wait=False))
                self.assertIn("已收取 1 份报告", collected)
                self.assertIsNone(_fast_pending_report_hint(orchestrator))

        asyncio.run(run())

    def test_background_two_roles_parallel_then_collected(self) -> None:
        orchestrator = self._orchestrator()
        recon = self._tool(orchestrator, "dispatch_recon")
        reverse = self._tool(orchestrator, "dispatch_reverse")

        async def run() -> None:
            released = asyncio.Event()

            async def slow_expert(*args, **kwargs):
                await released.wait()
                return "报告"

            with patch(
                "agent.Orchestrator.run_expert_reply_with_continuation",
                new=slow_expert,
            ):
                first = _chunk_text(await recon.call(focus="A", background=True))
                second = _chunk_text(await reverse.call(
                    binary_path="/tmp/bin.elf", objective="B", background=True,
                ))
                self.assertIn("recon#", first)
                self.assertIn("reverse#", second)
                # 两席占满：running=2；同 role 再派被忙碌互斥拒绝
                self.assertEqual(len(self.bg["running"]), 2)
                busy = _chunk_text(await recon.call(focus="C", route="artifact", background=True))
                self.assertIn("正在执行", busy)
                released.set()
                check = await orchestrator.toolkit.get_tool("check_experts")
                collected = _chunk_text(await check.call(wait=True, timeout=5))
                self.assertIn("已收取 2 份报告", collected)

        asyncio.run(run())

    def test_attack_has_no_background_param_recon_does(self) -> None:
        orchestrator = self._orchestrator()
        attack = self._tool(orchestrator, "dispatch_attack")
        recon = self._tool(orchestrator, "dispatch_reverse")
        attack_props = ((getattr(attack, "input_schema", None) or {}).get("properties") or {})
        reverse_props = ((getattr(recon, "input_schema", None) or {}).get("properties") or {})
        self.assertNotIn("background", attack_props)
        self.assertIn("background", reverse_props)

    # ── P6：Brain 顾问 ────────────────────────────────────────────

    def test_consult_brain_absent_without_brain_agent(self) -> None:
        orchestrator = self._orchestrator(brain_agent=None)
        self.assertIsNone(_fetch_tool(orchestrator, "consult_brain"))

    def test_consult_brain_returns_advice_and_audits(self) -> None:
        brain = _expert("Sophia - 战略规划专家")
        orchestrator = self._orchestrator(brain_agent=brain)
        consult = self._tool(orchestrator, "consult_brain")

        async def run() -> str:
            return _chunk_text(await consult.call(
                trigger="计划项失败过半", context_summary="SQL 注入路径受阻",
            ))

        with patch(
            "agent.Orchestrator.run_expert_reply_with_continuation",
            new=AsyncMock(return_value="建议：将计划项 3 改为侧写绕过"),
        ):
            result = asyncio.run(run())
        self.assertIn("[Brain 顾问建议]", result)
        self.assertIn("计划项 3", result)
        self.assertEqual(
            str(getattr(self.mission.events[-1], "action", "")), "brain_consulted",
        )


class BoundedReportTest(unittest.TestCase):
    def test_short_report_untouched(self) -> None:
        self.assertEqual(_bounded_report("短报告"), "短报告")

    def test_long_report_truncated_with_pointer(self) -> None:
        long_text = "A" * (_REPORT_RETURN_LIMIT + 500)
        result = _bounded_report(long_text)
        self.assertTrue(result.startswith("A" * _REPORT_RETURN_LIMIT))
        self.assertIn("已截断", result)
        self.assertIn("Evidence", result)
        self.assertLess(len(result), len(long_text))


if __name__ == "__main__":
    unittest.main()
