"""软预算降档 + fast_summary 开关测试（纯本地，不触真实 LLM/DB）。"""
from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest import mock

from core.TaskState import MissionState


# ────────────────────────────────────────────────────────
# 软预算：降档函数
# ────────────────────────────────────────────────────────

def _fake_model(provider: str, effort: str | None, enable: bool = True):
    return SimpleNamespace(
        parameters=SimpleNamespace(thinking_enable=enable, reasoning_effort=effort),
        _lingshu_usage_meta={"provider": provider, "model_name": "m"},
    )


class DowngradeThinkingTest(unittest.TestCase):
    def test_effort_model_downgrades_one_step(self) -> None:
        # openai 风格：medium → low
        from main import _downgrade_thinking_intensity
        model = _fake_model("openai", "medium")
        changed = _downgrade_thinking_intensity([model])
        self.assertEqual(changed, ["openai→low（effort=low）"])
        self.assertEqual(model.parameters.reasoning_effort, "low")
        self.assertTrue(model.parameters.thinking_enable)

    def test_low_downgrades_to_off(self) -> None:
        from main import _downgrade_thinking_intensity
        model = _fake_model("openai", "low")
        changed = _downgrade_thinking_intensity([model])
        self.assertEqual(len(changed), 1)
        self.assertFalse(model.parameters.thinking_enable)

    def test_zhipu_switches_thinking_off(self) -> None:
        # zhipu 无中间档：直接关闭
        from main import _downgrade_thinking_intensity
        model = _fake_model("zhipu", None, enable=True)
        changed = _downgrade_thinking_intensity([model])
        self.assertEqual(len(changed), 1)
        self.assertFalse(model.parameters.thinking_enable)

    def test_already_off_and_none_style_skipped(self) -> None:
        from main import _downgrade_thinking_intensity
        off = _fake_model("openai", None, enable=False)
        qwen = _fake_model("qwen", None, enable=True)   # thinking_style none
        self.assertEqual(_downgrade_thinking_intensity([off, qwen]), [])

    def test_duplicate_instances_deduplicated(self) -> None:
        from main import _downgrade_thinking_intensity
        model = _fake_model("openai", "high")
        changed = _downgrade_thinking_intensity([model, model, None])
        self.assertEqual(changed, ["openai→medium（effort=medium）"])


class SessionTokenAccumulatorTest(unittest.TestCase):
    def test_accumulate_read_clear(self) -> None:
        import LLM.model as model_mod
        model_mod._SESSION_TOKEN_TOTALS.clear()
        instance = SimpleNamespace(
            _lingshu_usage_ctx={"user_id": 1, "session_id": "sess-budget",
                                "role": "main"},
            _lingshu_usage_meta={"provider": "openai", "model_name": "m"},
        )
        usage = SimpleNamespace(input_tokens=100, output_tokens=50)
        with mock.patch.object(model_mod, "_write_usage"):
            model_mod._report_model_usage(instance, usage)
            model_mod._report_model_usage(instance, usage)
        self.assertEqual(model_mod.get_session_token_total("sess-budget"), 300)
        model_mod.clear_session_token_total("sess-budget")
        self.assertEqual(model_mod.get_session_token_total("sess-budget"), 0)

    def test_zero_usage_not_accumulated(self) -> None:
        import LLM.model as model_mod
        model_mod._SESSION_TOKEN_TOTALS.clear()
        instance = SimpleNamespace(
            _lingshu_usage_ctx={"session_id": "s2"}, _lingshu_usage_meta={})
        with mock.patch.object(model_mod, "_write_usage") as write:
            model_mod._report_model_usage(
                instance, SimpleNamespace(input_tokens=0, output_tokens=0))
            write.assert_not_called()
        self.assertEqual(model_mod.get_session_token_total("s2"), 0)


# ────────────────────────────────────────────────────────
# fast_summary：收尾 gate
# ────────────────────────────────────────────────────────

def _mission_for_summary() -> MissionState:
    mission = MissionState(target="1.2.3.4", goal="g", authorized=True,
                           session_id="sess-fs")
    return mission


class FastSummaryGateTest(unittest.TestCase):
    def test_disabled_fills_fallback_and_skips_llm(self) -> None:
        import main

        mission = _mission_for_summary()
        mission.success = True
        mission.flag = "flag{x}"
        with mock.patch.object(main, "run_summary_report",
                               side_effect=AssertionError("不应调用 Summary")):
            asyncio.run(main._finalize_summary_report(
                mission, provider="deepseek", model_ver="Min",
                messages=[{"type": "text_end", "content": "x"}],
                event_callback=None, reports_dir="/tmp", report_key="sess-fs",
                fast_summary=False))
        self.assertIn("fast 模式总结已关闭", mission.summary)
        self.assertIn("flag{x}", mission.summary)
        self.assertIn("成功", mission.summary)
        actions = [getattr(e, "action", None) for e in mission.events]
        self.assertIn("fast_summary_skipped", actions)

    def test_enabled_still_runs_summary(self) -> None:
        import main

        mission = _mission_for_summary()
        with mock.patch.object(main, "run_summary_report") as run:
            asyncio.run(main._finalize_summary_report(
                mission, provider="deepseek", model_ver="Min",
                messages=[{"type": "text_end", "content": "x"}],
                event_callback=None, reports_dir="/tmp", report_key="sess-fs",
                fast_summary=True))
        run.assert_called_once()

    def test_existing_summary_not_overwritten(self) -> None:
        import main

        mission = _mission_for_summary()
        mission.summary = "已有的总结内容"
        with mock.patch.object(main, "run_summary_report",
                               side_effect=AssertionError("不应调用")):
            asyncio.run(main._finalize_summary_report(
                mission, provider="deepseek", model_ver="Min",
                messages=[{"type": "text_end", "content": "x"}],
                event_callback=None, reports_dir="/tmp", report_key="sess-fs",
                fast_summary=False))
        self.assertEqual(mission.summary, "已有的总结内容")


if __name__ == "__main__":
    unittest.main()
