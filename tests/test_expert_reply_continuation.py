"""P2 专家回复补轮续跑回归测试（c5ca9b2b 复盘）。

覆盖 ``run_expert_reply_with_continuation``：
- 正常文本直接返回；
- 超迭代补一轮后产出的报告被返回；连续超迭代才上抛；
- 空回复先从 agent.state.context 兜底提取，恢复文本带来源标注；
- 兜底取不到时补一轮；补轮后仍为空返回空串；
- CancelledError 直接透传（不吞 steering/停止请求）。

用 fake agent + patch ``run_interruptible_agent_reply`` 隔离模型依赖。
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from agentscope.message import Msg

from Tools.tooling import (
    AgentMaxIterationsError,
    run_expert_reply_with_continuation,
)


def _msg(role: str, text: str) -> Msg:
    return Msg(name="t", role=role, content=[{"type": "text", "text": text}])


class _FakeAgent:
    name = "FakeExpert"

    def __init__(self, context: list | None = None) -> None:
        self.state = type("S", (), {"context": context or []})()


def _fake_reply_factory(outcomes: list):
    """依次消费 outcomes：str=正常返回文本，Exception=抛出。"""
    calls = {"n": 0}

    async def _fake(agent, inputs, prefix="", on_event=None):
        index = calls["n"]
        calls["n"] += 1
        outcome = outcomes[min(index, len(outcomes) - 1)]
        if isinstance(outcome, Exception):
            raise outcome
        return _msg("assistant", outcome)

    return _fake, calls


class ContinuationTest(unittest.IsolatedAsyncioTestCase):
    async def test_normal_text_returned_directly(self) -> None:
        fake, calls = _fake_reply_factory(["最终报告"])
        with patch("Tools.tooling.run_interruptible_agent_reply", fake):
            text = await run_expert_reply_with_continuation(
                _FakeAgent(), _msg("user", "q"), label="X",
            )
        self.assertEqual(text, "最终报告")
        self.assertEqual(calls["n"], 1)

    async def test_max_iters_gets_continuation_round(self) -> None:
        fake, calls = _fake_reply_factory(
            [AgentMaxIterationsError("max"), "补轮后的报告"],
        )
        with patch("Tools.tooling.run_interruptible_agent_reply", fake):
            text = await run_expert_reply_with_continuation(
                _FakeAgent(), _msg("user", "q"), label="X",
            )
        self.assertEqual(text, "补轮后的报告")
        self.assertEqual(calls["n"], 2)

    async def test_max_iters_twice_raises(self) -> None:
        fake, _ = _fake_reply_factory([AgentMaxIterationsError("max")])
        with patch("Tools.tooling.run_interruptible_agent_reply", fake):
            with self.assertRaises(AgentMaxIterationsError):
                await run_expert_reply_with_continuation(
                    _FakeAgent(), _msg("user", "q"), label="X",
                )

    async def test_empty_reply_recovered_from_context(self) -> None:
        agent = _FakeAgent(
            [
                _msg("user", "任务开始"),
                _msg("assistant", "截断前的报告残段"),
                _msg("assistant", "   "),  # 空白最终消息
            ]
        )
        fake, _ = _fake_reply_factory([""])
        with patch("Tools.tooling.run_interruptible_agent_reply", fake):
            text = await run_expert_reply_with_continuation(
                agent, _msg("user", "q"), label="X",
            )
        self.assertIn("恢复机制", text)
        self.assertIn("截断前的报告残段", text)

    async def test_empty_reply_without_context_gets_retry_round(self) -> None:
        agent = _FakeAgent([_msg("user", "任务开始")])  # 无 assistant 消息
        fake, calls = _fake_reply_factory(["", "补轮后终于输出"])
        with patch("Tools.tooling.run_interruptible_agent_reply", fake):
            text = await run_expert_reply_with_continuation(
                agent, _msg("user", "q"), label="X",
            )
        self.assertEqual(text, "补轮后终于输出")
        self.assertEqual(calls["n"], 2)

    async def test_empty_after_retry_returns_empty_string(self) -> None:
        agent = _FakeAgent([_msg("user", "任务开始")])
        fake, calls = _fake_reply_factory(["", ""])
        with patch("Tools.tooling.run_interruptible_agent_reply", fake):
            text = await run_expert_reply_with_continuation(
                agent, _msg("user", "q"), label="X",
            )
        self.assertEqual(text, "")
        self.assertEqual(calls["n"], 2)  # 不无限补轮

    async def test_cancelled_error_propagates_immediately(self) -> None:
        async def _cancel(agent, inputs, prefix="", on_event=None):
            raise asyncio.CancelledError()

        with patch("Tools.tooling.run_interruptible_agent_reply", _cancel):
            with self.assertRaises(asyncio.CancelledError):
                await run_expert_reply_with_continuation(
                    _FakeAgent(), _msg("user", "q"), label="X",
                )


if __name__ == "__main__":
    unittest.main()
