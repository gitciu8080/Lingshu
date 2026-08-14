"""Qwen llama.cpp 接入与严格工具参数契约测试。"""

from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agentscope.message import ToolCallBlock

from config import RuntimeConfig
from LLM.model import Qwen, QwenModelUnavailableError, resolve_qwen_model
from TaskState import MissionState, MissionStore
from Tools.Plan import create_submit_plan_tool
from Tools.tooling import (
    AllowedFunctionTool,
    StrictJSONToolkit,
    ToolJSONValidationError,
)


def _runtime(**overrides) -> RuntimeConfig:
    values = {
        "qwen_api_key": "test",
        "qwen_base_url": "http://qwen.invalid/v1",
        "qwen_model": "configured-model",
        "qwen_repeat_penalty": 1.08,
    }
    values.update(overrides)
    return RuntimeConfig(**values)


class QwenModelResolutionTest(unittest.IsolatedAsyncioTestCase):
    async def _resolve(self, ids: list[str], configured: str = "configured-model"):
        client = SimpleNamespace(
            models=SimpleNamespace(
                list=AsyncMock(return_value=SimpleNamespace(
                    data=[SimpleNamespace(id=item) for item in ids],
                )),
            ),
            close=AsyncMock(),
        )
        with patch("LLM.model.AsyncOpenAI", return_value=client):
            result = await resolve_qwen_model(_runtime(qwen_model=configured))
        client.models.list.assert_awaited_once()
        client.close.assert_awaited_once()
        return result

    async def test_configured_model_is_kept(self) -> None:
        self.assertEqual(
            await self._resolve(["configured-model", "other"]),
            ("configured-model", False),
        )

    async def test_unique_server_model_resolves_alias(self) -> None:
        self.assertEqual(
            await self._resolve(["actual-model"]),
            ("actual-model", True),
        )

    async def test_no_model_rejects_start(self) -> None:
        client = SimpleNamespace(
            models=SimpleNamespace(list=AsyncMock(return_value=SimpleNamespace(data=[]))),
            close=AsyncMock(),
        )
        with patch("LLM.model.AsyncOpenAI", return_value=client):
            with self.assertRaises(QwenModelUnavailableError):
                await resolve_qwen_model(_runtime())

    async def test_ambiguous_models_reject_start(self) -> None:
        with self.assertRaises(QwenModelUnavailableError):
            await self._resolve(["one", "two"])


class QwenRequestPolicyTest(unittest.IsolatedAsyncioTestCase):
    async def _capture(self, level: str, tools=None, tool_call_mode: str = "simple"):
        model = Qwen(
            level, temperature=0.37,
            config=_runtime(qwen_tool_call_mode=tool_call_mode),
        )
        sentinel = object()
        with patch(
            "LLM.model.OpenAIChatModel._call_api",
            new=AsyncMock(return_value=sentinel),
        ) as parent:
            result = await model._call_api("configured-model", [], tools=tools)
        self.assertIs(result, sentinel)
        return parent.await_args.kwargs

    async def test_low_disables_thinking_for_plain_text(self) -> None:
        kwargs = await self._capture("Low")
        self.assertFalse(kwargs["extra_body"]["chat_template_kwargs"]["enable_thinking"])
        self.assertEqual(kwargs["extra_body"]["repeat_penalty"], 1.08)
        self.assertNotIn("temperature", kwargs)

    async def test_min_enables_thinking_for_plain_text(self) -> None:
        kwargs = await self._capture("Min")
        self.assertTrue(kwargs["extra_body"]["chat_template_kwargs"]["enable_thinking"])

    async def test_tools_disable_thinking_and_force_temperature(self) -> None:
        kwargs = await self._capture("Max", tools=[{"type": "function"}])
        self.assertFalse(kwargs["extra_body"]["chat_template_kwargs"]["enable_thinking"])
        self.assertEqual(kwargs["temperature"], 0.1)
        self.assertFalse(kwargs["parallel_tool_calls"])
        self.assertEqual(kwargs["reasoning_effort"], "none")

    async def test_standard_tools_keep_call_temperature(self) -> None:
        kwargs = await self._capture(
            "Max", tools=[{"type": "function"}], tool_call_mode="standard",
        )
        self.assertNotIn("temperature", kwargs)
        self.assertFalse(kwargs["parallel_tool_calls"])
        self.assertEqual(kwargs["reasoning_effort"], "none")


class QwenRepeatPenaltyTest(unittest.TestCase):
    def test_default_is_108(self) -> None:
        # 空值等价于未显式配置，同时覆盖项目本地 .env，避免测试依赖机器状态。
        with patch.dict(os.environ, {"QWEN_REPEAT_PENALTY": ""}, clear=True):
            self.assertEqual(RuntimeConfig.from_env().qwen_repeat_penalty, 1.08)

    def test_explicit_high_value_is_preserved_with_warning(self) -> None:
        with patch.dict(os.environ, {"QWEN_REPEAT_PENALTY": "1.35"}, clear=True):
            with self.assertLogs("config", level="WARNING"):
                cfg = RuntimeConfig.from_env()
        self.assertEqual(cfg.qwen_repeat_penalty, 1.35)

    def test_tool_call_mode_comes_from_environment(self) -> None:
        with patch.dict(os.environ, {"QWEN_TOOL_CALL_MODE": "standard"}, clear=True):
            self.assertEqual(RuntimeConfig.from_env().qwen_tool_call_mode, "standard")


class StrictToolJSONTest(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_json_gets_one_retry_then_raises_without_calling_tool(self) -> None:
        invoked = 0

        def guarded(value: int) -> str:
            nonlocal invoked
            invoked += 1
            return str(value)

        toolkit = StrictJSONToolkit(tools=[AllowedFunctionTool(guarded)])
        state = SimpleNamespace(tool_context=SimpleNamespace(activated_groups=[]))

        async def consume(raw: str):
            return [
                item
                async for item in toolkit.call_tool(
                    ToolCallBlock(id="call-1", name="guarded", input=raw),
                    state,
                )
            ]

        first = await consume('{"value":')
        self.assertIn("只允许再重试一次", str(first))
        with self.assertRaises(ToolJSONValidationError):
            await consume('{"value":"not-an-int"}')
        self.assertEqual(invoked, 0)


class BrainBatchPlanTest(unittest.IsolatedAsyncioTestCase):
    async def test_submit_plan_commits_atomically_once(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-plan-batch-"))
        store = MissionStore(root / "mission.json")
        mission = MissionState(target="127.0.0.1", goal="test", authorized=True)
        tool = create_submit_plan_tool(mission, store)
        result = await tool(items=[
            {"id": 1, "content": "收集事实", "phase": "recon"},
            {"id": 2, "content": "分析证据", "phase": "analysis"},
            {"id": 3, "content": "授权验证", "phase": "exploitation"},
            {"id": 4, "content": "整理结果", "phase": "complete"},
        ])
        self.assertIn("批量登记 4 项", str(result))
        self.assertEqual([item["id"] for item in mission.plan_items], ["p1", "p2", "p3", "p4"])
        self.assertEqual(mission.checkpoint_seq, 1)

    async def test_invalid_batch_does_not_partially_mutate(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-plan-batch-bad-"))
        store = MissionStore(root / "mission.json")
        mission = MissionState(target="127.0.0.1", goal="test", authorized=True)
        tool = create_submit_plan_tool(mission, store)
        await tool(items=[
            {"id": 1, "content": "a", "phase": "recon"},
            {"id": 3, "content": "b", "phase": "analysis"},
            {"id": 4, "content": "c", "phase": "exploitation"},
            {"id": 5, "content": "d", "phase": "complete"},
        ])
        self.assertEqual(mission.plan_items, [])


if __name__ == "__main__":
    unittest.main()
