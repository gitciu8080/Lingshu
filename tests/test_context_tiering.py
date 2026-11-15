"""上下文预算端点分档（2026-11-15 一刀切排查）回归测试。

覆盖三项：①tool_result_limit / 报告回灌上限分档；②派遣窗口分档；
③RAG 注入量分档。默认（本地/未指定）行为与分档前完全一致。
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from agent.context import (
    CONTEXT_TIER_CLOUD,
    CONTEXT_TIER_LOCAL,
    TOOL_RESULT_LIMIT,
    TOOL_RESULT_LIMIT_CLOUD_CAP,
    build_agent_context_config,
    context_tier_scale,
)
from agent.Orchestrator import (
    _REPORT_RETURN_LIMIT,
    _bounded_report,
    report_return_limit,
)
from main import _knowledge_caps


def _registry(base_url: str) -> list[dict]:
    return [{
        "provider": "openai-compatible",
        "base_url": base_url,
        "models": [{"name": "demo", "enabled": True, "settings": {}}],
    }]


class RegistryEndpointTierTest(unittest.TestCase):
    """core.model_registry.provider_endpoint_is_local 属地探测。"""

    def test_private_endpoint_is_local(self) -> None:
        from core.model_registry import provider_endpoint_is_local

        with patch("core.model_registry.list_llm_providers",
                   return_value=_registry("http://127.0.0.1:8081")):
            self.assertTrue(
                provider_endpoint_is_local("openai-compatible", "demo"))

    def test_public_endpoint_is_cloud(self) -> None:
        from core.model_registry import provider_endpoint_is_local

        with patch("core.model_registry.list_llm_providers",
                   return_value=_registry("https://api.deepseek.com")):
            self.assertFalse(
                provider_endpoint_is_local("openai-compatible", "demo"))

    def test_probe_failure_falls_back_to_local(self) -> None:
        from core.model_registry import provider_endpoint_is_local

        with patch("core.model_registry.list_llm_providers",
                   side_effect=RuntimeError("boom")):
            self.assertTrue(
                provider_endpoint_is_local("openai-compatible", "demo"))


class ContextTierScaleTest(unittest.TestCase):
    """context_tier_scale 系数与 tool_result_limit 分档。"""

    def test_scale_values(self) -> None:
        self.assertEqual(context_tier_scale(is_local=True), CONTEXT_TIER_LOCAL)
        self.assertEqual(context_tier_scale(is_local=False), CONTEXT_TIER_CLOUD)
        self.assertEqual(CONTEXT_TIER_LOCAL, 1.0)
        self.assertEqual(CONTEXT_TIER_CLOUD, 4.0)

    def test_provider_based_scale_detection(self) -> None:
        with patch("core.model_registry.provider_endpoint_is_local",
                   return_value=False):
            self.assertEqual(
                context_tier_scale(
                    provider="openai-compatible", model_name="demo"),
                CONTEXT_TIER_CLOUD,
            )

    def test_default_role_config_unchanged_for_local(self) -> None:
        # 默认调用（本地/未指定）保持既有契约，不破坏旧行为
        cfg = build_agent_context_config()
        self.assertEqual(cfg.tool_result_limit, TOOL_RESULT_LIMIT)

    def test_cloud_scales_tool_result_limit(self) -> None:
        cfg = build_agent_context_config("attack", tier_scale=CONTEXT_TIER_CLOUD)
        # 2600 × 4 = 10400 est-token
        self.assertEqual(cfg.tool_result_limit, 10400)

    def test_cloud_tool_limit_capped(self) -> None:
        # 默认档 4000 × 4 = 16000 → 触顶 12000
        cfg = build_agent_context_config(tier_scale=CONTEXT_TIER_CLOUD)
        self.assertEqual(cfg.tool_result_limit, TOOL_RESULT_LIMIT_CLOUD_CAP)

    def test_ratios_not_tiered(self) -> None:
        local = build_agent_context_config("attack")
        cloud = build_agent_context_config("attack", tier_scale=CONTEXT_TIER_CLOUD)
        self.assertEqual(local.trigger_ratio, cloud.trigger_ratio)
        self.assertEqual(local.reserve_ratio, cloud.reserve_ratio)


class ReportReturnLimitTest(unittest.TestCase):
    """报告回灌上限分档（本地 3000 不变，云端 ×4 cap 12000）。"""

    def test_local_limit_unchanged(self) -> None:
        self.assertEqual(report_return_limit(1.0), _REPORT_RETURN_LIMIT)
        self.assertEqual(report_return_limit(0.5), _REPORT_RETURN_LIMIT)

    def test_cloud_limit_scaled_and_capped(self) -> None:
        self.assertEqual(report_return_limit(CONTEXT_TIER_CLOUD), 12_000)
        self.assertEqual(report_return_limit(99.0), 12_000)

    def test_bounded_report_default_and_scaled(self) -> None:
        long_report = "x" * 8_000
        # 默认（本地）：截断 + 尾注
        cut = _bounded_report(long_report)
        self.assertIn("已截断", cut)
        self.assertLess(len(cut), 3_500)
        # 云端档：8000 字符不截
        kept = _bounded_report(long_report, limit=report_return_limit(CONTEXT_TIER_CLOUD))
        self.assertEqual(kept, long_report)

    def test_short_report_never_annotated(self) -> None:
        out = _bounded_report("短报告", limit=500)
        self.assertEqual(out, "短报告")


class KnowledgeCapsTest(unittest.TestCase):
    """RAG 注入量分档（_knowledge_caps）。"""

    def test_local_caps_match_defaults(self) -> None:
        caps = _knowledge_caps(1.0)
        self.assertEqual(caps, {
            "fetch_k": 8, "context_k": 4,
            "max_item_chars": 800, "max_context_chars": 3600,
        })

    def test_cloud_caps_scaled_with_fetch_cap(self) -> None:
        caps = _knowledge_caps(CONTEXT_TIER_CLOUD)
        self.assertEqual(caps, {
            "fetch_k": 10,  # 检索层 min(k,10) 封顶
            "context_k": 16,
            "max_item_chars": 3_200,
            "max_context_chars": 14_400,
        })


if __name__ == "__main__":
    unittest.main()
