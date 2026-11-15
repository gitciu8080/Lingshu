"""Summary 详细度分档（2026-11-15 详细度回归复盘）回归测试。

回归根因：a0593e6 为本地模型防超时引入的一刀切约束（输入预算
1.0 字符/token×50% 预留 + SUMMARY.md 2500 字输出上限）让云端报告
的输入/输出双双砍半。修复：本地/云端分档——云端 1.5 字符/token、
预留 35%（恢复 ef3a4ae 时代 120k 输入水平）、篇幅要求 5000~8000 字；
本地维持保守预算与 2500 字但超时上限上浮 60%。
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from main import (
    _SUMMARY_MAX_TRANSCRIPT_CHARS,
    _summary_input_budget,
    _summary_length_directive,
    _summary_provider_is_local,
)


def _registry(base_url: str, context_size: int) -> list[dict]:
    return [{
        "provider": "openai-compatible",
        "base_url": base_url,
        "models": [{"name": "demo", "enabled": True,
                    "settings": {"context_size": context_size}}],
    }]


class SummaryBudgetTierTest(unittest.TestCase):
    """本地/云端预算分档：云端显著更大且可达 120k 上限。"""

    def test_cloud_budget_larger_than_local(self) -> None:
        local = _summary_input_budget("openai-compatible", "demo", is_local=True)
        cloud = _summary_input_budget("openai-compatible", "demo", is_local=False)
        self.assertGreater(cloud, local)

    def test_cloud_recovers_120k_for_128k_context(self) -> None:
        with patch("core.model_registry.list_llm_providers",
                   return_value=_registry("http://api.deepseek.com", 128_000)):
            budget = _summary_input_budget("openai-compatible", "demo", is_local=False)
        # 128k × 0.65 × 1.5 = 124.8k → 触达 120k 上限（ef3a4ae 水平）
        self.assertEqual(budget, _SUMMARY_MAX_TRANSCRIPT_CHARS)

    def test_local_stays_conservative(self) -> None:
        with patch("core.model_registry.list_llm_providers",
                   return_value=_registry("http://127.0.0.1:8081", 128_000)):
            budget = _summary_input_budget("openai-compatible", "demo", is_local=True)
        # 128k × 0.55 × 1.2 ≈ 84.5k（防本地 prefill 超时）
        self.assertLess(budget, 100_000)
        self.assertGreater(budget, 60_000)


class SummaryLocalDetectionTest(unittest.TestCase):
    """端点属地检测：私网/回环=本地，公网=云端。"""

    def test_private_base_url_is_local(self) -> None:
        with patch("core.model_registry.list_llm_providers",
                   return_value=_registry("http://127.0.0.1:8081", 128_000)):
            self.assertTrue(_summary_provider_is_local("openai-compatible", "demo"))

    def test_public_base_url_is_cloud(self) -> None:
        with patch("core.model_registry.list_llm_providers",
                   return_value=_registry("https://api.deepseek.com", 128_000)):
            self.assertFalse(_summary_provider_is_local("openai-compatible", "demo"))

    def test_probe_failure_falls_back_to_local(self) -> None:
        with patch("core.model_registry.list_llm_providers",
                   side_effect=RuntimeError("boom")):
            self.assertTrue(_summary_provider_is_local("openai-compatible", "demo"))


class SummaryLengthDirectiveTest(unittest.TestCase):
    """篇幅指令分档：云端放宽并覆盖系统提示的 2500 字上限。"""

    def test_cloud_directive_expands_length(self) -> None:
        directive = _summary_length_directive(False)
        self.assertIn("5000~8000 字", directive)
        self.assertIn("不适用本轮", directive)
        self.assertIn("mermaid", directive)

    def test_local_directive_keeps_conservative_cap(self) -> None:
        directive = _summary_length_directive(True)
        self.assertIn("2500 字", directive)


if __name__ == "__main__":
    unittest.main()
