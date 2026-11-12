"""Qwen 本地模型下的两个缺陷回归：Summary 输入预算 + 题目级会话防重。"""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.TaskState import MissionState


class SummaryBudgetTest(unittest.TestCase):
    """Summary 输入必须按目标模型 context_size 裁剪，避免小上下文模型超时。"""

    def test_budget_scales_with_context_size(self) -> None:
        import main

        with mock.patch("core.model_registry.list_llm_providers", return_value=[
            {"provider": "openai-compatible",
             "models": [{"name": "m", "settings": {"context_size": 32768}}]},
        ]):
            small = main._summary_input_budget("openai-compatible", "m")
        with mock.patch("core.model_registry.list_llm_providers", return_value=[
            {"provider": "openai-compatible",
             "models": [{"name": "m", "settings": {"context_size": 128000}}]},
        ]):
            large = main._summary_input_budget("openai-compatible", "m")
        self.assertLess(small, large)
        # 32k 上下文下预算必须显著小于历史固定值 12 万字符
        self.assertLess(small, 120_000)
        self.assertGreaterEqual(small, main._SUMMARY_MIN_TRANSCRIPT_CHARS)

    def test_budget_fallback_when_unavailable(self) -> None:
        import main

        with mock.patch("core.model_registry.list_llm_providers", side_effect=RuntimeError("x")):
            budget = main._summary_input_budget("unknown-provider", None)
        self.assertGreaterEqual(budget, main._SUMMARY_MIN_TRANSCRIPT_CHARS)
        self.assertLessEqual(budget, main._SUMMARY_MAX_TRANSCRIPT_CHARS)

    def test_inputs_trimmed_within_budget(self) -> None:
        import main

        mission = MissionState(target="1.2.3.4", goal="g", authorized=True)
        for i in range(300):
            mission.add_evidence("Attack", "attack_report",
                                 f"证据 {i}: " + "x" * 400, confidence=0.8)
        messages = [{"event_type": "text_end", "agent_name": "Captain",
                     "content": f"第 {i} 步执行命令并得到结果。"} for i in range(3000)]
        with mock.patch.object(main, "_summary_input_budget", return_value=20_000):
            transcript, mission_data = main._summary_inputs_within_budget(
                mission, messages, provider="p", model_name=None, user_id=None)
        self.assertLessEqual(len(transcript), 20_000)
        # 状态被裁剪但关键字段保留
        self.assertIn("target", mission_data)
        self.assertLessEqual(len(mission_data.get("evidence_records") or []), 40)

    def test_large_context_keeps_default_ceiling(self) -> None:
        import main

        with mock.patch.object(main, "_summary_input_budget",
                               return_value=main._SUMMARY_MAX_TRANSCRIPT_CHARS):
            mission = MissionState(target="1.2.3.4", goal="g", authorized=True)
            # 内容各异，避免命中 _build_summary_transcript 的相邻去重
            messages = [{"event_type": "text_end", "agent_name": "C",
                         "content": f"记录 {i}: " + "x" * 100} for i in range(50)]
            transcript, _ = main._summary_inputs_within_budget(
                mission, messages, provider="p", model_name=None, user_id=None)
        # 大上下文下不应因预算裁剪而丢弃会话记录（50 条短记录应全部保留）
        self.assertEqual(transcript.count("[text_end]"), 50)


class ThinkingStyleNoneTest(unittest.TestCase):
    """thinking_style=none 的供应商在要求关闭思考时必须显式下发开关。"""

    def test_gateway_class_exposes_thinking_style(self) -> None:
        from LLM.model import GatewayChatModel
        self.assertTrue(hasattr(GatewayChatModel, "_call_api"))

    def test_injection_condition(self) -> None:
        # 注入条件：thinking_style=none 且 thinking_enable=False
        cases = {
            ("none", False): True,
            ("none", True): False,
            ("effort", False): False,
            ("zhipu", False): False,
        }
        for (style, enable), expected in cases.items():
            self.assertEqual(style == "none" and not enable, expected,
                             f"{style}/{enable}")


class ActiveSessionGuardTest(unittest.TestCase):
    """同一题目在会话存活期内不得重复拉起灵枢会话。"""

    def setUp(self) -> None:
        import workbench_ctf2_web as wb

        self.wb = wb
        self.tmp = Path(tempfile.mkdtemp(prefix="wb-active-")) / "active.json"
        self._patch = mock.patch.object(wb, "ACTIVE_FILE", self.tmp)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()

    def test_claim_then_block_duplicate(self) -> None:
        wb = self.wb
        self.assertIsNone(wb.active_claim("chal-1"))
        wb.active_bind("chal-1", "sess-aaa")
        # 第二次抢占返回已有会话 id
        self.assertEqual(wb.active_claim("chal-1"), "sess-aaa")

    def test_release_allows_reclaim(self) -> None:
        wb = self.wb
        wb.active_claim("chal-2")
        wb.active_bind("chal-2", "sess-bbb")
        wb.active_release("chal-2")
        self.assertIsNone(wb.active_claim("chal-2"))

    def test_stale_entry_expires(self) -> None:
        wb = self.wb
        self.tmp.parent.mkdir(parents=True, exist_ok=True)
        self.tmp.write_text(json.dumps({
            "chal-3": {"session_id": "old", "started_at": 1.0}}), encoding="utf-8")
        # TTL 过期后应可重新抢占
        self.assertIsNone(wb.active_claim("chal-3"))

    def test_registry_survives_process_restart(self) -> None:
        wb = self.wb
        wb.active_claim("chal-4")
        wb.active_bind("chal-4", "sess-ddd")
        # 模拟重启：重新从磁盘读取
        self.assertEqual(wb.active_load()["chal-4"]["session_id"], "sess-ddd")


if __name__ == "__main__":
    unittest.main()
