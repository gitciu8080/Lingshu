"""标准模式工作流审计修复（498e11b4/06549049 复盘）回归测试。

覆盖六项修复：
F1 工具面契约——标准模式注册 view_evidence；workspace_root 提供时注册
   workspace_read（AgentScope offload 的 tool_result-*.txt 从此可读回）；
F2 截断对齐——_bounded_report 3000 上限 + 尾注指路 view_evidence；
F3 阶段活锁——后台侦察运行时 Attack 拒绝文案给 check_experts 指引，
   dispatch_recon(background=true) 文案不再误导"可推进 Attack"；
F4 文本化 tool_call 检测——_TEXTUAL_TOOL_CALL_RE 命中真实泄漏样本；
F5 stale running attempt——超过 30 分钟或不可解析的 started_at 判定为陈旧；
F6 tool_result_summary 事件——session_events 落库映射（role=system）。
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agent.Orchestrator import (
    _REPORT_RETURN_LIMIT,
    _bounded_report,
    create_orchestrator_agent,
)
from core.TaskState import MissionState, MissionStore, Phase
from core.session_events import message_operation
from main import _TEXTUAL_TOOL_CALL_RE, _attempt_started_at_stale


def _chunk_text(chunk) -> str:
    content = getattr(chunk, "content", chunk)
    if isinstance(content, str):
        return content
    return "".join(getattr(b, "text", str(b)) for b in content)


def _expert(name: str) -> SimpleNamespace:
    return SimpleNamespace(name=name)


def _fetch_tool(agent, name: str):
    try:
        return asyncio.run(agent.toolkit.get_tool(name))
    except Exception:
        return None


def _mission(mode: str = "authorized_pentest") -> MissionState:
    mission = MissionState(
        target="10.10.10.5", goal="对授权目标完成渗透测试评估", authorized=True,
    )
    mission.mission_mode = mode
    mission.transition(Phase.RECON, "test")
    mission.transition(Phase.ANALYSIS, "test")
    return mission


class ToolSurfaceContractTest(unittest.TestCase):
    """F1：标准模式工具面包含证据检索与工作区文件读取。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "mission.json")
        self.mission = _mission()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _build(self, workspace_root: str | None):
        return create_orchestrator_agent(
            model=SimpleNamespace(),
            recon_agent=_expert("Ethan - 网络侦察专家"),
            attack_agent=_expert("Mike - Web 渗透专家"),
            reserve_agent=_expert("Ryan - 逆向程序专家"),
            mission=self.mission,
            store=self.store,
            max_iters=5,
            workspace_root=workspace_root,
        )

    def test_view_evidence_registered_in_standard_mode(self) -> None:
        agent = self._build(workspace_root=None)
        self.assertIsNotNone(_fetch_tool(agent, "view_evidence"))

    def test_workspace_read_registered_with_root(self) -> None:
        agent = self._build(workspace_root=self.temp.name)
        self.assertIsNotNone(_fetch_tool(agent, "workspace_read"))
        self.assertIsNotNone(_fetch_tool(agent, "workspace_glob"))
        self.assertIsNotNone(_fetch_tool(agent, "workspace_grep"))

    def test_workspace_read_reads_offloaded_tool_result(self) -> None:
        # 模拟 AgentScope offload：sessions/<sid>-orchestrator/tool_result-*.txt
        ws = Path(self.temp.name)
        offload_dir = ws / "sessions" / "498e-orchestrator"
        offload_dir.mkdir(parents=True)
        (offload_dir / "tool_result-call_x.txt").write_text(
            " leaked evidence tail", encoding="utf-8",
        )
        agent = self._build(workspace_root=str(ws))
        tool = _fetch_tool(agent, "workspace_read")
        result = asyncio.run(tool.call(
            path="sessions/498e-orchestrator/tool_result-call_x.txt", max_bytes=1000,
        ))
        self.assertIn("leaked evidence tail", _chunk_text(result))

    def test_workspace_read_rejects_escape(self) -> None:
        agent = self._build(workspace_root=self.temp.name)
        tool = _fetch_tool(agent, "workspace_read")
        with self.assertRaises(Exception):
            asyncio.run(tool.call(path="/etc/passwd"))


class BoundedReportTest(unittest.TestCase):
    """F2：截断上限与尾注指路。"""

    def test_limit_is_3000(self) -> None:
        self.assertEqual(_REPORT_RETURN_LIMIT, 3000)

    def test_tail_points_to_view_evidence(self) -> None:
        result = _bounded_report("x" * (_REPORT_RETURN_LIMIT + 100))
        self.assertIn("view_evidence", result)
        self.assertNotIn("view_mission_state", result)


class PhaseGateGuidanceTest(unittest.TestCase):
    """F3：后台侦察运行时 Attack 拒绝给指引；后台文案不再误导。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "mission.json")
        self.mission = _mission()
        self.mission.transition(Phase.RECON, "back to recon")
        self.orchestrator = create_orchestrator_agent(
            model=SimpleNamespace(),
            recon_agent=_expert("Ethan - 网络侦察专家"),
            attack_agent=_expert("Mike - Web 渗透专家"),
            reserve_agent=_expert("Ryan - 逆向程序专家"),
            mission=self.mission,
            store=self.store,
            max_iters=5,
        )
        self.bg = self.orchestrator._lingshu_bg

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_attack_rejected_with_guidance_while_bg_recon_busy(self) -> None:
        self.bg["busy_roles"].add("recon")
        attack = asyncio.run(self.orchestrator.toolkit.get_tool("dispatch_attack"))
        result = _chunk_text(asyncio.run(attack.call(
            target_info="x", objective="漏洞验证",
        )))
        self.assertIn("check_experts", result)
        self.assertIn("后台侦察仍在执行", result)

    def test_plain_recon_phase_rejection_unchanged(self) -> None:
        attack = asyncio.run(self.orchestrator.toolkit.get_tool("dispatch_attack"))
        result = _chunk_text(asyncio.run(attack.call(
            target_info="x", objective="漏洞验证",
        )))
        self.assertIn("不允许派遣 Attack", result)
        self.assertNotIn("后台侦察仍在执行", result)

    def test_bg_recon_text_warns_about_attack_gate(self) -> None:
        recon = asyncio.run(self.orchestrator.toolkit.get_tool("dispatch_recon"))

        async def run() -> str:
            released = asyncio.Event()

            async def slow_expert(*args, **kwargs):
                await released.wait()
                return "报告"

            with patch(
                "agent.Orchestrator.run_expert_reply_with_continuation",
                new=slow_expert,
            ):
                text = _chunk_text(await recon.call(focus="A", background=True))
                released.set()
                check = await self.orchestrator.toolkit.get_tool("check_experts")
                await check.call(wait=True, timeout=5)
            return text

        text = asyncio.run(run())
        self.assertIn("Attack 受阶段", text)
        self.assertNotIn("（如 Attack", text)


class TextualToolCallDetectionTest(unittest.TestCase):
    """F4：文本化工具调用正则命中真实泄漏样本。"""

    REAL_LEAK = (
        "Let me read the truncated session file.\n"
        "<tool_call>\n<function=Read>\n<parameter=file_path>\n"
        "/home/kali/.../tool_result-call_1c6f58137f554a078a5fce7c.txt\n"
        "</parameter>\n</function>\n</tool_call>"
    )

    def test_matches_real_leak_sample(self) -> None:
        self.assertTrue(_TEXTUAL_TOOL_CALL_RE.search(self.REAL_LEAK))

    def test_matches_function_open_tag_only(self) -> None:
        self.assertTrue(_TEXTUAL_TOOL_CALL_RE.search("<function=query_file>"))

    def test_normal_text_not_matched(self) -> None:
        self.assertIsNone(_TEXTUAL_TOOL_CALL_RE.search(
            "侦察报告已读取，准备派遣 Attack 专家进行验证。",
        ))


class StaleAttemptTest(unittest.TestCase):
    """F5：陈旧 running attempt 判定。"""

    def test_recent_attempt_not_stale(self) -> None:
        recent = datetime.now().isoformat()
        self.assertFalse(_attempt_started_at_stale(recent))

    def test_old_attempt_stale(self) -> None:
        old = (datetime.now() - timedelta(minutes=31)).isoformat()
        self.assertTrue(_attempt_started_at_stale(old))

    def test_unparseable_timestamp_stale(self) -> None:
        self.assertTrue(_attempt_started_at_stale("not-a-timestamp"))
        self.assertTrue(_attempt_started_at_stale(""))


class ToolResultSummaryEventTest(unittest.TestCase):
    """F6：tool_result_summary 落库映射（role=system）。"""

    def test_persisted_as_system_message(self) -> None:
        op = message_operation(
            "sess-1", "tool_result_summary",
            {"tool": "dispatch_attack", "action_id": "a1", "tail": "rc=0"},
        )
        self.assertIsNotNone(op)
        self.assertEqual(op["role"], "system")
        self.assertEqual(op["event_type"], "tool_result_summary")
        self.assertIn("rc=0", op["content"])

    def test_event_type_in_persist_whitelist(self) -> None:
        from core.session_events import PERSIST_EVENT_TYPES
        self.assertIn("tool_result_summary", PERSIST_EVENT_TYPES)


if __name__ == "__main__":
    unittest.main()
