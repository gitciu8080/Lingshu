"""阶段 3 测试：内部 Agent 的 Offloader / ContextConfig / 角色会话状态接线。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentscope.credential import OpenAICredential
from agentscope.model import OpenAIChatModel
from pydantic import SecretStr

from agent.context import (
    TRIGGER_RATIO,
    RESERVE_RATIO,
    TOOL_RESULT_LIMIT,
    build_agent_context_config,
    build_role_agent_state,
)
from agent.Brain import create_brain_agent
from agent.Analysis import create_analysis_agent
from agent.Recon import create_artifact_triage_agent
from agent.Summary import create_summary_agent


def _model() -> OpenAIChatModel:
    return OpenAIChatModel(
        model="test",
        credential=OpenAICredential(api_key=SecretStr("test")),
    )


class ContextConfigContractTest(unittest.TestCase):
    def test_plan_locked_ratios(self) -> None:
        cfg = build_agent_context_config()
        self.assertEqual(cfg.trigger_ratio, TRIGGER_RATIO)
        self.assertEqual(cfg.reserve_ratio, RESERVE_RATIO)
        self.assertEqual(cfg.tool_result_limit, TOOL_RESULT_LIMIT)

    def test_summary_schema_preserves_resume_semantics(self) -> None:
        cfg = build_agent_context_config()
        schema = cfg.summary_schema
        props = schema["properties"]
        for key in (
            "authorized_scope",
            "approval_status",
            "plan_items",
            "evidence_paths",
            "failed_fingerprints",
            "flag_submission",
            "next_action",
        ):
            self.assertIn(key, props, f"摘要 Schema 缺少 {key}")


class RoleStateTest(unittest.TestCase):
    def test_role_session_id_is_deterministic(self) -> None:
        state = build_role_agent_state("sess-1", "brain")
        self.assertEqual(state.session_id, "sess-1-brain")
        state2 = build_role_agent_state("sess-1", "recon")
        self.assertEqual(state2.session_id, "sess-1-recon")

    def test_roles_are_partitioned(self) -> None:
        brain = build_role_agent_state("m1", "brain")
        recon = build_role_agent_state("m1", "recon")
        self.assertNotEqual(brain.session_id, recon.session_id)


class AgentOffloaderWiringTest(unittest.IsolatedAsyncioTestCase):
    async def _workspace(self):
        from agentscope.workspace import LocalWorkspace

        workdir = Path(tempfile.mkdtemp(prefix="lingshu-wire-"))
        ws = LocalWorkspace(workdir=str(workdir))
        await ws.initialize()
        return ws, workdir

    async def test_brain_receives_offloader_and_role_state(self) -> None:
        ws, workdir = await self._workspace()
        try:
            agent = create_brain_agent(
                _model(),
                offloader=ws,
                context_config=build_agent_context_config(),
                state=build_role_agent_state("sess-9", "brain"),
            )
            self.assertIs(agent.offloader, ws)
            self.assertIsNotNone(agent.context_config)
            self.assertEqual(agent.state.session_id, "sess-9-brain")
        finally:
            await ws.close()

    async def test_analysis_wired(self) -> None:
        ws, workdir = await self._workspace()
        try:
            agent = create_analysis_agent(
                _model(),
                offloader=ws,
                context_config=build_agent_context_config(),
                state=build_role_agent_state("sess-9", "analysis"),
            )
            self.assertIs(agent.offloader, ws)
            self.assertEqual(agent.state.session_id, "sess-9-analysis")
        finally:
            await ws.close()

    async def test_triage_receives_artifact_root(self) -> None:
        ws, workdir = await self._workspace()
        try:
            agent = create_artifact_triage_agent(
                _model(),
                workdir=workdir,
                project_dir=workdir,
                timeout=30,
                offloader=ws,
                context_config=build_agent_context_config(),
                state=build_role_agent_state("sess-9", "recon"),
                artifact_root=workdir,
            )
            self.assertIs(agent.offloader, ws)
            self.assertEqual(agent.state.session_id, "sess-9-recon")
            # scoped_shell 工具已绑定 artifact_root（通过 toolkit 内的 FunctionTool）
            from agentscope.tool import Toolkit

            self.assertIsInstance(agent.toolkit, Toolkit)
            self.assertIsNotNone(
                await agent.toolkit.get_tool("scoped_shell"),
                "triage 必须持有 scoped_shell 工具",
            )
        finally:
            await ws.close()

    async def test_summary_wired(self) -> None:
        ws, workdir = await self._workspace()
        try:
            agent = create_summary_agent(
                _model(),
                offloader=ws,
                context_config=build_agent_context_config(),
                state=build_role_agent_state("sess-9", "summary"),
            )
            self.assertIs(agent.offloader, ws)
            self.assertEqual(agent.state.session_id, "sess-9-summary")
        finally:
            await ws.close()

    async def test_offload_writes_to_role_partition(self) -> None:
        from agentscope.message import AssistantMsg

        ws, workdir = await self._workspace()
        try:
            agent = create_brain_agent(
                _model(),
                offloader=ws,
                context_config=build_agent_context_config(),
                state=build_role_agent_state("m42", "brain"),
            )
            # 直接通过 offloader 验证角色分区写入
            await ws.offload_context(
                agent.state.session_id,
                [AssistantMsg(name="brain", content="计划")],
            )
            jsonl = workdir / "sessions" / "m42-brain" / "context.jsonl"
            self.assertTrue(jsonl.is_file())
        finally:
            await ws.close()


if __name__ == "__main__":
    unittest.main()
