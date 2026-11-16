"""ARTEX 三项移植（T1-T3）回归测试。

T1 LLM 熔断链：异常分类判据、熔断梯子、FailoverChatModel 切池序列、
   parameters 属性级突变透传、CancelledError 直通、单 profile 不包装。
T2 资产图驱动调度：主循环咽喉点存在增量注入（源码契约）。
T3 冷事实摘要：SCHEMA bump、热层切片尊重 digest_upto、historical 投影、
   维护闭包源码契约。
"""
from __future__ import annotations

import asyncio
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from LLM.failover import (
    FailoverChatModel,
    _is_tripable,
    _record_failure,
    _record_success,
    breaker_open,
    build_chain_keys,
)
from core.TaskState import MissionState, MissionStore, Phase

ROOT = Path(__file__).resolve().parent.parent


def _chunk_text(chunk) -> str:
    content = getattr(chunk, "content", chunk)
    if isinstance(content, str):
        return content
    return "".join(getattr(b, "text", str(b)) for b in content)


# ── T1：异常分类 ──────────────────────────────────────────────────

class _Status(Exception):
    def __init__(self, status_code: int, message: str = "boom"):
        self.status_code = status_code
        super().__init__(message)


class _Named(Exception):
    """按类型名匹配的替身异常（不带 status_code）。"""


class TripableClassificationTest(unittest.TestCase):
    def test_status_code_duck_typing(self) -> None:
        self.assertTrue(_is_tripable(_Status(429, "rate limited")))
        self.assertTrue(_is_tripable(_Status(500, "boom")))
        self.assertTrue(_is_tripable(_Status(401, "auth")))
        self.assertTrue(_is_tripable(_Status(502, "bad gateway")))
        self.assertFalse(_is_tripable(_Status(400, "bad request")))
        self.assertFalse(_is_tripable(_Status(404, "not found")))
        self.assertFalse(_is_tripable(_Status(422, "unprocessable")))

    def test_type_name_matching(self) -> None:
        class APIConnectionError(Exception):
            pass

        class RateLimitError(Exception):
            pass

        self.assertTrue(_is_tripable(APIConnectionError("Connection error.")))
        self.assertTrue(_is_tripable(RateLimitError("limited")))

    def test_string_fallbacks(self) -> None:
        self.assertTrue(_is_tripable(RuntimeError("Upstream stream interrupted")))
        self.assertTrue(_is_tripable(RuntimeError("已达到 5 小时的使用上限")))
        self.assertTrue(_is_tripable(RuntimeError("Error code: 429")))

    def test_non_tripable(self) -> None:
        self.assertFalse(_is_tripable(RuntimeError("invalid request body shape")))
        self.assertFalse(_is_tripable(ValueError("bad value")))

    def test_cancelled_never_tripable(self) -> None:
        self.assertFalse(_is_tripable(asyncio.CancelledError()))


# ── T1：熔断梯子 ──────────────────────────────────────────────────

class BreakerLadderTest(unittest.TestCase):
    def setUp(self) -> None:
        _record_success("unit-key-a")  # 初始化

    def test_ladder_progression_and_reset(self) -> None:
        key = "unit-key-b"
        _record_failure(key, RuntimeError("429"))
        self.assertTrue(breaker_open(key))
        _record_failure(key, RuntimeError("429"))
        _record_failure(key, RuntimeError("429"))
        _record_failure(key, RuntimeError("429"))
        _record_success(key)
        self.assertFalse(breaker_open(key))
        # 再失败 → 梯子从头（60s）
        _record_failure(key, RuntimeError("429"))
        # 60s 内未过期
        self.assertTrue(breaker_open(key))


# ── T1：FailoverChatModel 切池行为 ────────────────────────────────

class _Backend:
    def __init__(self, name: str, behavior):
        self.name = name
        self._behavior = behavior
        self.calls = 0
        self.parameters = SimpleNamespace(thinking_enable=False)

    async def __call__(self, messages, tools=None, tool_choice=None, **kwargs):
        self.calls += 1
        behavior = self._behavior
        if isinstance(behavior, BaseException):
            raise behavior
        if callable(behavior):
            return await behavior(self)
        return SimpleNamespace(get_text_content=lambda: "ok")


class FailoverModelTest(unittest.TestCase):
    def setUp(self) -> None:
        from LLM.failover import reset_breakers
        reset_breakers()

    def _make(self, behaviors: dict[str, Exception | None]):
        backends = {
            key: _Backend(key, behaviors.get(key))
            for key in ("primary", "alt1", "alt2")
        }
        chain = list(behaviors.keys())
        wrapper = FailoverChatModel.__new__(FailoverChatModel)
        wrapper._runtime = SimpleNamespace()
        wrapper._intensity = "medium"
        wrapper._temperature = 0.2
        wrapper._model_name = None
        wrapper._web_search = None
        wrapper._vision = False
        wrapper._keys = chain
        wrapper._backends = [backends["primary"]]
        wrapper._last_ok = 0
        wrapper._pending_ctx = None
        # 预置全部 backend（跳过懒构建路径，聚焦切池序列）
        wrapper._backends = [backends[k] for k in chain]
        return wrapper, backends

    def test_failover_on_tripable_then_success(self) -> None:
        wrapper, backends = self._make({
            "primary": RuntimeError("Upstream stream interrupted"),
            "alt1": None,
            "alt2": None,
        })
        result = asyncio.run(wrapper([SimpleNamespace()]))
        self.assertEqual(backends["primary"].calls, 1)
        self.assertEqual(backends["alt1"].calls, 1)
        self.assertEqual(backends["alt2"].calls, 0)
        self.assertTrue(breaker_open("primary"))

    def test_all_exhausted_reraises_last(self) -> None:
        wrapper, backends = self._make({
            "primary": RuntimeError("429"),
            "alt1": RuntimeError("使用上限"),
            "alt2": RuntimeError("connection reset"),
        })
        with self.assertRaises(RuntimeError):
            asyncio.run(wrapper([SimpleNamespace()]))
        for backend in backends.values():
            self.assertEqual(backend.calls, 1)

    def test_non_tripable_raises_immediately(self) -> None:
        wrapper, backends = self._make({
            "primary": RuntimeError("invalid request body"),
            "alt1": None,
            "alt2": None,
        })
        with self.assertRaises(RuntimeError):
            asyncio.run(wrapper([SimpleNamespace()]))
        self.assertEqual(backends["alt1"].calls, 0)

    def test_cancelled_passthrough(self) -> None:
        wrapper, backends = self._make({"primary": None, "alt1": None, "alt2": None})

        async def cancelled(backend_self):
            raise asyncio.CancelledError()

        backends["primary"]._behavior = cancelled
        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(wrapper([SimpleNamespace()]))
        self.assertEqual(backends["alt1"].calls, 0)

    def test_open_breaker_skipped(self) -> None:
        wrapper, backends = self._make({
            "primary": RuntimeError("429"),
            "alt1": None,
            "alt2": None,
        })
        asyncio.run(wrapper([SimpleNamespace()]))
        # primary 熔断开启 → 再次调用直接从 alt1 开始（primary 不再被调用）
        asyncio.run(wrapper([SimpleNamespace()]))
        self.assertEqual(backends["primary"].calls, 1)
        self.assertEqual(backends["alt1"].calls, 2)

    def test_parameters_mutation_lands_on_active(self) -> None:
        wrapper, backends = self._make({
            "primary": RuntimeError("429"),
            "alt1": None,
            "alt2": None,
        })
        asyncio.run(wrapper([SimpleNamespace()]))  # active → alt1
        wrapper.parameters.thinking_enable = True
        self.assertTrue(backends["alt1"].parameters.thinking_enable)
        self.assertFalse(backends["primary"].parameters.thinking_enable)

    def test_usage_ctx_forwarded_to_all_backends(self) -> None:
        wrapper, backends = self._make({
            "primary": RuntimeError("429"),
            "alt1": None,
            "alt2": None,
        })
        wrapper._lingshu_usage_ctx = {
            "user_id": 13, "session_id": "s1", "role": "attack",
        }
        for backend in backends.values():
            self.assertEqual(backend._lingshu_usage_ctx["user_id"], 13)


class ChainKeysTest(unittest.TestCase):
    def test_chain_excludes_current_and_caps(self) -> None:
        runtime = SimpleNamespace(custom_llm_configs={
            "primary": {}, "alt1": {}, "alt2": {}, "alt3": {}, "alt4": {},
        })
        chain = build_chain_keys(runtime, "primary")
        self.assertEqual(chain[0], "primary")
        self.assertEqual(len(chain), 4)  # 主 + 3 alt

    def test_empty_pool_no_chain(self) -> None:
        runtime = SimpleNamespace(custom_llm_configs={})
        chain = build_chain_keys(runtime, "primary")
        self.assertEqual(chain, ["primary"])


# ── T1：create_model 挂载契约 ─────────────────────────────────────

class CreateModelWiringTest(unittest.TestCase):
    def test_wiring_present(self) -> None:
        src = (ROOT / "LLM" / "model.py").read_text(encoding="utf-8")
        self.assertIn("FailoverChatModel", src)
        self.assertIn("build_chain_keys(runtime, provider)", src)
        self.assertIn("failover_enabled()", src)


# ── T2：资产图驱动调度 ────────────────────────────────────────────

class AssetHintContractTest(unittest.TestCase):
    def test_mount_point_exists(self) -> None:
        src = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("new_assets = mission.assets[_asset_mark:]", src)
        self.assertIn("[资产图更新]", src)
        self.assertIn("_asset_mark = len(mission.assets)", src)


# ── T3：冷事实摘要 ────────────────────────────────────────────────

class ColdDigestTest(unittest.TestCase):
    def test_schema_bumped(self) -> None:
        from core.TaskState import SCHEMA_VERSION
        self.assertEqual(SCHEMA_VERSION, 10)

    def test_hot_slice_respects_digest_upto(self) -> None:
        temp = tempfile.TemporaryDirectory()
        try:
            m = MissionState(target="1.2.3.4", goal="g", authorized=True)
            m.transition(Phase.RECON, "t")
            m.transition(Phase.ANALYSIS, "t")
            seed = m.add_evidence("recon", "recon_report", "种子")
            for i in range(30):
                m.add_fact(f"事实 {i}", "recon", [seed.id])
            m.facts_digest = "旧事实要点摘要"
            m.facts_digest_upto = 22
            layers = m.context_layers(limit=8)
            ids = [f["id"] for f in layers["core_state"]["facts"]]
            # 热层从 22 之后开始（facts[22:][-8:] = 事实 22..29）
            self.assertEqual(len(ids), 8)
            self.assertNotIn("f1", ids)
            hist = layers["historical_context"]["facts_digest"]
            self.assertEqual(hist["covers_facts_upto"], 22)
            self.assertEqual(hist["total_facts"], 30)
            self.assertIn("要点摘要", hist["text"])
        finally:
            temp.cleanup()

    def test_maintenance_closure_present(self) -> None:
        src = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("async def _maintain_facts_digest", src)
        self.assertIn("facts_cold_digest", src)
        self.assertIn("_FACTS_COLD_THRESHOLD = 24", src)
        self.assertIn("_DIGEST_MIN_INTERVAL = 300.0", src)


if __name__ == "__main__":
    unittest.main()
