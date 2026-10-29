"""终态后追问（QA）功能测试。

覆盖：AgentState 快照序列化往返（main._save_agent_state_snapshot）、
两个调度者工厂的 qa_readonly 工具面、view_evidence 只读工具、
素材简报 _build_qa_brief、终态判定与问答入口（受理/409 互斥）。
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agentscope.message import Msg
from agentscope.state import AgentState

import api as api_module
from agent.Captain import create_fast_captain_agent
from agent.Orchestrator import create_orchestrator_agent
from core.TaskState import MissionState, MissionStore, Phase
from main import _save_agent_state_snapshot


def _expert(name: str) -> SimpleNamespace:
    return SimpleNamespace(name=name)


def _mission() -> MissionState:
    mission = MissionState(
        target="127.0.0.1", goal="对授权目标完成渗透测试评估", authorized=True,
    )
    mission.transition(Phase.RECON, "test")
    mission.transition(Phase.ANALYSIS, "test")
    mission.transition(Phase.EXPLOITATION, "test")
    mission.flag = "flag{test_1234}"
    mission.success = True
    return mission


def _fetch_tool(agent, name: str):
    try:
        return asyncio.run(agent.toolkit.get_tool(name))
    except Exception:
        return None


def _chunk_text(chunk) -> str:
    content = getattr(chunk, "content", chunk)
    if isinstance(content, str):
        return content
    return "".join(getattr(b, "text", str(b)) for b in content)


class AgentStateSnapshotTest(unittest.TestCase):
    def test_roundtrip_via_main_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = AgentState(session_id="m-orchestrator")
            state.context.append(
                Msg(
                    name="user", role="user",
                    content=[{"type": "text", "text": "flag 是怎么得出的？"}],
                ),
            )
            agent = SimpleNamespace(state=state)
            _save_agent_state_snapshot(tmp, "orchestrator", agent)
            path = Path(tmp) / "mission" / "agent_state-orchestrator.json"
            self.assertTrue(path.is_file())
            restored = AgentState.model_validate_json(
                path.read_text(encoding="utf-8"),
            )
            self.assertEqual(
                restored.session_id, "m-orchestrator",
            )
            self.assertEqual(len(restored.context), 1)

    def test_missing_state_is_silent_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _save_agent_state_snapshot(tmp, "orchestrator", SimpleNamespace())
            _save_agent_state_snapshot(None, "orchestrator", None)
            self.assertFalse(
                (Path(tmp) / "mission" / "agent_state-orchestrator.json").exists(),
            )


class OrchestratorQaReadonlyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "mission.json")
        self.mission = _mission()
        evidence = self.mission.add_evidence(
            "Mike - Web 渗透专家", "attack_report",
            "SQL 注入验证成功，从 information_schema 泄露管理员口令哈希，"
            "解密后登录后台在配置页读取 flag{test_1234}。",
            confidence=0.9,
        )
        self.mission.add_fact(
            "Attack 报告中发现待验证 Flag/关键凭据候选：flag{test_1234}",
            "Mike - Web 渗透专家", [evidence.id], confidence=0.85,
        )
        self.mission.add_attack_step("SQL 注入获取后台权限", "验证成功")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _agent(self):
        return create_orchestrator_agent(
            model=SimpleNamespace(),
            recon_agent=_expert("Ethan - 网络侦察专家"),
            attack_agent=_expert("Mike - Web 渗透专家"),
            reserve_agent=_expert("Ryan - 逆向程序专家"),
            mission=self.mission,
            store=self.store,
            event_callback=None,
            max_iters=4,
            qa_readonly=True,
        )

    def test_qa_tool_surface_is_readonly(self) -> None:
        agent = self._agent()
        for name in (
            "dispatch_recon", "dispatch_attack", "dispatch_reverse",
            "complete_mission", "manage_hypothesis",
            "request_exploitation_approval",
        ):
            self.assertIsNone(_fetch_tool(agent, name), name)
        for name in ("view_mission_state", "view_evidence", "ListPlan"):
            self.assertIsNotNone(_fetch_tool(agent, name), name)

    def test_view_evidence_returns_full_text(self) -> None:
        agent = self._agent()
        tool = asyncio.run(agent.toolkit.get_tool("view_evidence"))
        result = _chunk_text(asyncio.run(tool.call(keyword="flag")))
        self.assertIn("flag{test_1234}", result)
        self.assertIn("证据", result)
        # 关键词过滤不命中时给出提示
        miss = _chunk_text(asyncio.run(tool.call(keyword="不存在的关键词xyz")))
        self.assertIn("无匹配证据", miss)

    def test_normal_mode_keeps_dispatch_tools(self) -> None:
        agent = create_orchestrator_agent(
            model=SimpleNamespace(),
            recon_agent=_expert("Ethan - 网络侦察专家"),
            attack_agent=_expert("Mike - Web 渗透专家"),
            reserve_agent=_expert("Ryan - 逆向程序专家"),
            mission=self.mission,
            store=self.store,
            event_callback=None,
            max_iters=4,
        )
        self.assertIsNotNone(_fetch_tool(agent, "dispatch_attack"))


class CaptainQaReadonlyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "mission.json")
        self.mission = _mission()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_qa_tool_surface_empty(self) -> None:
        agent = create_fast_captain_agent(
            model=SimpleNamespace(), experts={}, mission=self.mission,
            store=self.store, event_callback=None, target="127.0.0.1",
            workdir=self.temp.name, timeout=5, max_iters=4, qa_readonly=True,
        )
        for name in (
            "spawn_expert", "check_experts", "fast_complete_mission",
            "scoped_shell", "submit_flag",
        ):
            self.assertIsNone(_fetch_tool(agent, name), name)

    def test_normal_mode_keeps_spawn(self) -> None:
        agent = create_fast_captain_agent(
            model=SimpleNamespace(), experts={}, mission=self.mission,
            store=self.store, event_callback=None, target="127.0.0.1",
            workdir=self.temp.name, timeout=5, max_iters=4,
        )
        self.assertIsNotNone(_fetch_tool(agent, "spawn_expert"))


class QaBriefTest(unittest.TestCase):
    def test_brief_contains_evidence_and_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = MissionStore(Path(tmp) / "mission.json")
            mission = _mission()
            evidence = mission.add_evidence(
                "Mike - Web 渗透专家", "attack_report", "注入获得 flag{test_1234}",
                confidence=0.9,
            )
            mission.add_fact("发现 flag 候选", "attack", [evidence.id])
            mission.add_attack_step("SQL 注入", "成功")
            brief = api_module._build_qa_brief(mission)
        self.assertIn("flag{test_1234}", brief)
        self.assertIn("证据原文", brief)
        self.assertIn("攻击步骤", brief)


class StartPostMissionQaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        api_module._terminal_contexts.clear()

    def tearDown(self) -> None:
        api_module._terminal_contexts.clear()
        self.temp.cleanup()

    def test_terminal_check(self) -> None:
        session_id = "qa-term-session"
        with patch.object(
            api_module.session_store, "get_session",
            return_value={"id": session_id, "status": "completed"},
        ):
            self.assertTrue(asyncio.run(api_module._is_terminal_session(session_id)))
        with patch.object(
            api_module.session_store, "get_session",
            return_value={"id": session_id, "status": "active"},
        ):
            self.assertFalse(asyncio.run(api_module._is_terminal_session(session_id)))

    def test_accept_and_user_message_persisted(self) -> None:
        session_id = "qa-accept-session"
        written: list[dict] = []

        async def fake_write(session_id_arg, role, content, event_type, agent_name):
            written.append({
                "role": role, "content": content,
                "event_type": event_type, "agent": agent_name,
            })
            return len(written)

        with patch.object(
            api_module.session_store, "get_session",
            return_value={"id": session_id, "status": "completed"},
        ), patch.object(
            api_module, "_write_session_message", new=fake_write,
        ), patch.object(
            api_module, "_run_post_mission_qa", new=AsyncMock(return_value=None),
        ):
            result = asyncio.run(api_module._start_post_mission_qa(
                session_id, "怎么拿到 flag 的", {"id": 1},
            ))
            self.assertEqual(result["status"], "qa_accepted")
            ctx = api_module._terminal_contexts[session_id]
            self.assertIsNotNone(ctx.qa_task)
            asyncio.run(ctx.qa_task)
        self.assertEqual(written[0]["role"], "user")
        self.assertEqual(written[0]["event_type"], "user_message")
        self.assertIn("flag", written[0]["content"])

    def test_busy_conflict_rejected_with_409(self) -> None:
        session_id = "qa-busy-session"

        async def run() -> None:
            # 直接构造一个带未完成 qa_task 的终态上下文（互斥检查先于落库）
            ctx = api_module.SessionContext(
                session_id=session_id, user_id=1, input_queue=asyncio.Queue(),
            )
            ctx.qa_task = asyncio.get_running_loop().create_future()  # 永不完成
            api_module._terminal_contexts[session_id] = ctx
            await api_module._start_post_mission_qa(session_id, "再问一次", {"id": 1})

        with self.assertRaises(Exception) as ctx_manager:
            asyncio.run(run())
        self.assertIn("409", str(ctx_manager.exception))


class RunPostMissionQaEndToEndTest(unittest.TestCase):
    """回归锁定：QA runner 必须以同步方式调用会话回调。

    _make_session_callback 返回同步函数；此前误写 await callback(...)
    触发 "'NoneType' object can't be awaited"。本用例以最小 mock 跑通
    完整 runner（含真实 callback、事件发布与落库提交路径）。
    """

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.session_id = "qa-runner-session"
        api_module._terminal_contexts.clear()
        # 准备权威任务 JSON（MissionStore.for_session 读取处）
        base_dir = Path(self.temp.name) / "sessions"
        base_dir.mkdir(parents=True)
        store = MissionStore.for_session(self.session_id, base_dir=base_dir)
        self._original_sessions_dir = api_module._sessions_dir
        api_module._sessions_dir = base_dir
        self._submitted: list[list[dict]] = []

        async def fake_submit(operations, wait=False):
            self._submitted.append(list(operations))
            return len(self._submitted)

        def fake_queue(operations):
            self._submitted.append(list(operations))
            return True

        def fake_fallback(operations):
            self._submitted.append(list(operations))

        self._patches = [
            patch.object(
                api_module, "ps",
                SimpleNamespace(
                    submit=fake_submit,
                    queue_persistence_operations=fake_queue,
                    fallback_direct_write=fake_fallback,
                ),
            ),
            patch.object(api_module, "create_model", return_value=SimpleNamespace()),
            patch.object(
                api_module, "set_usage_context", return_value=None,
            ),
            patch.object(
                api_module, "get_workspace_service",
                return_value=SimpleNamespace(
                    mission_dir=lambda *a: Path(self.temp.name) / "mission",
                    workspace_dir=lambda *a: Path(self.temp.name) / "ws",
                    get=AsyncMock(return_value=SimpleNamespace()),
                    pin=AsyncMock(return_value=None),
                    unpin=AsyncMock(return_value=None),
                    close_one=AsyncMock(return_value=None),
                ),
            ),
            patch.object(
                api_module, "run_interruptible_agent_reply",
                new=AsyncMock(return_value=SimpleNamespace(
                    get_text_content=lambda: "Flag 由 SQL 注入获得，见证据 1。",
                )),
            ),
        ]
        self._store = store
        self._mission = _mission()
        self._mission.add_evidence(
            "attack", "attack_report", "注入取得 flag{t}", confidence=0.9,
        )
        store.save(self._mission)

    def tearDown(self) -> None:
        for p in self._patches:
            p.stop()
        api_module._sessions_dir = self._original_sessions_dir
        api_module._terminal_contexts.clear()
        self.temp.cleanup()

    def test_runner_completes_with_sync_callback_and_persists_reply(self) -> None:
        for p in self._patches:
            p.start()
        asyncio.run(api_module._run_post_mission_qa(
            self.session_id, "flag 是怎么得出的？", 1,
        ))
        # 回复经回调落库：message 操作（role=agent，agent_name=调度者真名）
        flat = [op for batch in self._submitted for op in batch]
        reply_ops = [
            op for op in flat
            if op.get("type") == "message" and "SQL 注入" in str(op.get("content"))
        ]
        self.assertTrue(reply_ops, flat)
        self.assertEqual(reply_ops[-1]["role"], "agent")
        self.assertIn("Alex", reply_ops[-1]["agent_name"])


if __name__ == "__main__":
    unittest.main()
