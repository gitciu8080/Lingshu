"""dispatch_attack 注入已判错候选排除集（2026-11-15 压测复盘）回归测试。

背景：attempt#13561 对正确内容 Y0u_know_broadca5t_att4ck 连续 6 次
换壳提交被判错。修复：Orchestrator 组装 Attack 派发上下文时，若
mission.nss_rejected_keys 非空则注入排除集提示（最近 20 条、每条
截断 64 字符），Attack/Orchestrator 提示词同步补核对要求。
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent.Orchestrator import create_orchestrator_agent
from core.TaskState import MissionState, MissionStore, Phase

REJECTED_HEADER = "【已判错候选（归一化键，禁止再次提交其任何变体）】"


def _chunk_text(chunk) -> str:
    content = getattr(chunk, "content", chunk)
    if isinstance(content, str):
        return content
    return "".join(getattr(b, "text", str(b)) for b in content)


def _mission() -> MissionState:
    mission = MissionState(
        target="10.10.10.5", goal="完成 CTF 解题", authorized=True,
    )
    mission.transition(Phase.RECON, "t")
    mission.transition(Phase.ANALYSIS, "t")
    return mission


class RejectedKeysInjectionTest(unittest.TestCase):
    """排除集注入：非空注入、为空不注入、超限截断。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "m.json")
        self.mission = _mission()
        self.mission.exploitation_approved = True

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _dispatch_and_capture(self) -> tuple[str, str]:
        captured = {}

        async def fake_reply(agent, msg, **kwargs):
            captured["content"] = msg.content
            return "Attack 报告：无可行候选"

        agent = create_orchestrator_agent(
            model=SimpleNamespace(),
            recon_agent=SimpleNamespace(name="Ethan"),
            attack_agent=SimpleNamespace(name="Mike"),
            reserve_agent=SimpleNamespace(name="Ryan"),
            mission=self.mission, store=self.store, max_iters=5,
        )
        tool = asyncio.run(agent.toolkit.get_tool("dispatch_attack"))
        with patch(
            "agent.Orchestrator.run_expert_reply_with_continuation",
            new=fake_reply,
        ):
            result = _chunk_text(asyncio.run(tool.call(
                target_info="x", objective="寻找 Flag",
            )))
        return result, _chunk_text(
            type("M", (), {"content": captured["content"]})()
        )

    def test_injects_when_rejected_keys_present(self) -> None:
        self.mission.nss_rejected_keys = ["y0u_know_broadca5t_att4ck"]
        _, content = self._dispatch_and_capture()
        self.assertIn(REJECTED_HEADER, content)
        self.assertIn("y0u_know_broadca5t_att4ck", content)

    def test_no_injection_when_empty(self) -> None:
        self.mission.nss_rejected_keys = []
        _, content = self._dispatch_and_capture()
        self.assertNotIn(REJECTED_HEADER, content)

    def test_caps_to_recent_20_and_truncates_64(self) -> None:
        self.mission.nss_rejected_keys = [f"key_{i:02d}" for i in range(30)]
        self.mission.nss_rejected_keys.append("z" * 100)
        _, content = self._dispatch_and_capture()
        self.assertIn(REJECTED_HEADER, content)
        # 最近 20 条：key_11..key_29 + 100 字符长键（截断为 64）
        self.assertIn("key_29", content)
        self.assertIn("key_11", content)
        self.assertNotIn("key_10", content)
        self.assertNotIn("z" * 65, content)
        self.assertIn("z" * 64, content)


if __name__ == "__main__":
    unittest.main()
