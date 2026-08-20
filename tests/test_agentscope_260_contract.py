"""AgentScope 2.0.6 契约测试：升级后必须保持的 API 与行为。

覆盖计划第 1 阶段验收项：
- 依赖测试：2.0.6 导入、LocalWorkspace 初始化、Offloader 与 ContextConfig 契约。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import agentscope
from agentscope.agent import Agent, ContextConfig
from agentscope.message import AssistantMsg, ToolResultBlock
from agentscope.workspace import LocalWorkspace

EXPECTED_VERSION = "2.0.6"


class VersionContractTest(unittest.TestCase):
    def test_agentscope_version_is_pinned_to_260(self) -> None:
        self.assertEqual(agentscope.__version__, EXPECTED_VERSION)

    def test_workspace_extra_is_installed(self) -> None:
        from agentscope.workspace import (  # noqa: F401
            BubblewrapWorkspace,
            DockerWorkspace,
            LocalWorkspace,
            WorkspaceBase,
        )

    def test_lingshu_docker_workspace_subclasses_dockerworkspace(self) -> None:
        """LingshuDockerWorkspace 必须继承 DockerWorkspace（host 网络子类化）。"""
        from agentscope.workspace import DockerWorkspace

        from workspace_service import LingshuDockerWorkspace

        self.assertTrue(issubclass(LingshuDockerWorkspace, DockerWorkspace))
        inst = LingshuDockerWorkspace(base_image="kali-full:latest")
        self.assertEqual(inst.base_image, "kali-full:latest")


class ContextConfigContractTest(unittest.TestCase):
    def test_context_config_fields_match_plan_contract(self) -> None:
        fields = set(ContextConfig.model_fields.keys())
        self.assertIn("trigger_ratio", fields)
        self.assertIn("reserve_ratio", fields)
        self.assertIn("tool_result_limit", fields)
        self.assertIn("summary_schema", fields)

    def test_plan_ratios_are_accepted(self) -> None:
        cfg = ContextConfig(
            trigger_ratio=0.75,
            reserve_ratio=0.12,
            tool_result_limit=4000,
        )
        self.assertEqual(cfg.trigger_ratio, 0.75)
        self.assertEqual(cfg.reserve_ratio, 0.12)
        self.assertEqual(cfg.tool_result_limit, 4000)

    def test_custom_summary_schema_is_accepted(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "authorized_scope": {"type": "array"},
                "approval_status": {"type": "string"},
                "evidence_paths": {"type": "array"},
                "next_action": {"type": "string"},
            },
        }
        cfg = ContextConfig(summary_schema=schema)
        self.assertEqual(cfg.summary_schema, schema)

    def test_trigger_ratio_upper_bound_0_9_rejects_too_high(self) -> None:
        with self.assertRaises(Exception):
            ContextConfig(trigger_ratio=0.95)


class LocalWorkspaceContractTest(unittest.IsolatedAsyncioTestCase):
    async def _make_workspace(self) -> tuple[LocalWorkspace, Path]:
        workdir = Path(tempfile.mkdtemp(prefix="lingshu-contract-"))
        ws = LocalWorkspace(workdir=str(workdir))
        await ws.initialize()
        return ws, workdir

    async def test_initialize_creates_workdir_and_lazy_layout(self) -> None:
        """2.0.6 的 LocalWorkspace.initialize() 只建 workdir；会话子目录在
        offload 时惰性创建。契约：workdir 必须存在且可写。"""
        ws, workdir = await self._make_workspace()
        try:
            self.assertTrue(workdir.is_dir())
            # 惰性布局：尚未 offload 时不要求 sessions/ 存在
            await ws.offload_context(
                "probe",
                [AssistantMsg(name="probe", content="x")],
            )
            self.assertTrue((workdir / "sessions").is_dir())
            self.assertTrue((workdir / "skills").is_dir())
        finally:
            await ws.close()

    async def test_offload_context_writes_jsonl(self) -> None:
        ws, workdir = await self._make_workspace()
        try:
            msgs = [AssistantMsg(name="brain", content="摘要内容")]
            ref = await ws.offload_context("mission-1-brain", msgs)
            jsonl = workdir / "sessions" / "mission-1-brain" / "context.jsonl"
            self.assertTrue(jsonl.is_file(), f"未生成 context.jsonl: {ref}")
            line = json.loads(jsonl.read_text(encoding="utf-8").strip().splitlines()[-1])
            blocks = line["content"]
            self.assertIsInstance(blocks, list)
            texts = [b.get("text", "") for b in blocks if b.get("type") == "text"]
            self.assertIn("摘要内容", texts)
        finally:
            await ws.close()

    async def test_offload_tool_result_writes_file_and_returns_reference(self) -> None:
        ws, workdir = await self._make_workspace()
        try:
            block = ToolResultBlock(
                id="call-1",
                name="scoped_shell",
                output="x" * 5000,
            )
            ref = await ws.offload_tool_result("mission-1-recon", block)
            # 2.0.6 返回宿主绝对路径；灵枢服务层负责将其转为相对引用。
            # 契约：路径必须指向 workdir 内的实际文件。
            self.assertTrue(Path(ref).is_file(), f"offload 文件不存在: {ref}")
            self.assertTrue(Path(ref).resolve().is_relative_to(workdir.resolve()))
            self.assertEqual(Path(ref).read_text(encoding="utf-8"), "x" * 5000)
        finally:
            await ws.close()

    async def test_offloaded_sessions_are_partitioned(self) -> None:
        ws, workdir = await self._make_workspace()
        try:
            await ws.offload_context(
                "mission-1-brain",
                [AssistantMsg(name="brain", content="A")],
            )
            await ws.offload_context(
                "mission-1-recon",
                [AssistantMsg(name="recon", content="B")],
            )
            brain_dir = workdir / "sessions" / "mission-1-brain"
            recon_dir = workdir / "sessions" / "mission-1-recon"
            self.assertTrue(brain_dir.is_dir())
            self.assertTrue(recon_dir.is_dir())
            self.assertNotIn(
                "mission-1-recon",
                [p.name for p in brain_dir.iterdir()],
            )
        finally:
            await ws.close()


class AgentOffloaderContractTest(unittest.IsolatedAsyncioTestCase):
    async def test_agent_accepts_offloader_and_context_config(self) -> None:
        """Agent 构造签名必须能接收 Workspace 作为 offloader + ContextConfig。"""
        from agentscope.credential import OpenAICredential
        from agentscope.model import OpenAIChatModel
        from pydantic import SecretStr

        model = OpenAIChatModel(
            model="test",
            credential=OpenAICredential(api_key=SecretStr("test")),
        )
        workdir = Path(tempfile.mkdtemp(prefix="lingshu-agent-"))
        ws = LocalWorkspace(workdir=str(workdir))
        await ws.initialize()
        try:
            agent = Agent(
                name="brain",
                system_prompt="你是一个测试 Agent。",
                model=model,
                offloader=ws,
                context_config=ContextConfig(
                    trigger_ratio=0.75,
                    reserve_ratio=0.12,
                    tool_result_limit=4000,
                ),
            )
            self.assertIs(agent.offloader, ws)
            self.assertIsNotNone(agent.context_config)
        finally:
            await ws.close()


if __name__ == "__main__":
    unittest.main()
