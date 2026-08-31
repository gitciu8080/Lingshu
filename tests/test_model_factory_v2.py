"""模型工厂 v2 回归测试：供应商目录驱动 + provider::配置ID + 密钥状态。

覆盖：
- core/providers.py：reasoning_effort 收敛、原生工具线协议、思考风格映射；
- core/model_registry.py：models 列表（含旧条目派生）、同一供应商多条
  启用（runtime_key=provider::配置ID）、api_key_status=invalid 跳过；
- LLM.model.create_model：统一入口按目录分发 Responses / Chat 驱动、
  full_endpoint 网关、智谱思考线协议。
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import model_registry as registry
from core.config import RuntimeConfig
from core.providers import (
    PROVIDER_CATALOG,
    clamp_reasoning_effort,
    get_provider_spec,
    native_tool_wire_payloads,
    resolve_provider_thinking,
)

_FACTORY_CASES = ("deepseek", "zhipu", "openai-compatible")


class ProvidersCatalogTest(unittest.TestCase):
    def test_specs_have_required_fields(self) -> None:
        for key, spec in PROVIDER_CATALOG.items():
            self.assertEqual(spec["key"], key)
            self.assertTrue(spec["api_styles"])
            self.assertIn(spec["default_api_style"], spec["api_styles"])
            self.assertIn(spec["thinking_style"], {"zhipu", "effort", "none"})

    def test_clamp_reasoning_effort_by_provider(self) -> None:
        zhipu = get_provider_spec("zhipu")
        self.assertIsNone(clamp_reasoning_effort(zhipu, "high"))
        deepseek = get_provider_spec("deepseek")
        self.assertEqual(clamp_reasoning_effort(deepseek, "max"), "max")
        # chat 协议仅 high/max，由工厂层再做二次收敛
        self.assertEqual(clamp_reasoning_effort(deepseek, "low"), "low")
        unknown = {"key": "x", "reasoning_efforts": ("high", "max")}
        self.assertEqual(clamp_reasoning_effort(unknown, "low"), "high")

    def test_thinking_style_mapping(self) -> None:
        zhipu = get_provider_spec("zhipu")
        self.assertEqual(resolve_provider_thinking(zhipu, "off"), (False, None))
        think, effort = resolve_provider_thinking(zhipu, "high")
        self.assertTrue(think)
        self.assertIsNone(effort)  # 智谱思考开关经 thinking.type 下发
        deepseek = get_provider_spec("deepseek")
        self.assertEqual(resolve_provider_thinking(deepseek, "off"), (False, None))
        self.assertEqual(resolve_provider_thinking(deepseek, "medium"), (True, "medium"))

    def test_native_tool_wire_protocols(self) -> None:
        deepseek = get_provider_spec("deepseek")
        tools, extra = native_tool_wire_payloads(deepseek, "responses", ["web_search"])
        self.assertEqual(tools, [{"type": "web_search"}])
        self.assertEqual(extra, {})
        zhipu = get_provider_spec("zhipu")
        tools, extra = native_tool_wire_payloads(zhipu, "chat_completions", ["web_search"])
        self.assertEqual(tools[0]["type"], "web_search")
        self.assertIn("web_search", tools[0])
        self.assertEqual(extra, {})
        dashscope = get_provider_spec("dashscope")
        tools, extra = native_tool_wire_payloads(dashscope, "chat_completions", ["web_search"])
        self.assertEqual(tools, [])
        self.assertEqual(extra, {"enable_search": True})


class RegistryV2Test(unittest.TestCase):
    """v2 供应商注册表回归：CRUD、runtime key、密钥状态与 v1 迁移。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_patch = patch.object(registry, "LEGACY_DB_PATH", root / "users.db")
        self.path_patch = patch.object(registry, "REGISTRY_PATH", root / "model_api_configs.json")
        self.key_patch = patch.object(registry, "KEY_PATH", root / "model_api.key")
        self.env_patch = patch.dict(os.environ, {"LINGSHU_MODEL_CONFIG_KEY": ""})
        self.db_patch.start()
        self.path_patch.start()
        self.key_patch.start()
        self.env_patch.start()
        registry.init_model_registry()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.key_patch.stop()
        self.path_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()

    @staticmethod
    def llm(name: str, key: str, *, provider: str = "deepseek", enabled: bool = True,
            api_style: str = "chat_completions",
            models: list[str] | None = None) -> dict:
        models = models or ["model-a", "model-b"]
        return {
            "name": name, "provider": provider, "api_style": api_style,
            "base_url": "https://models.example/v1", "api_key": key,
            "gateway_mode": "base_url", "enabled_tools": [],
            "enabled": enabled,
            "models": [
                {"name": name_, "enabled": True, "vision": False, "settings": {}}
                for name_ in models
            ],
        }

    def test_multiple_enabled_configs_get_runtime_keys(self) -> None:
        first = registry.create_llm_provider(self.llm("主配置", "key-one"), 1)
        second = registry.create_llm_provider(self.llm("备用配置", "key-two"), 1)
        active = {item["name"]: item for item in registry.active_llm_providers()}
        # 同一供应商多条启用：runtime_key 为 provider::配置ID
        self.assertEqual(active["主配置"]["runtime_key"], f"deepseek::{first['id']}")
        self.assertEqual(active["备用配置"]["runtime_key"], f"deepseek::{second['id']}")

    def test_single_enabled_config_keeps_plain_provider_key(self) -> None:
        registry.create_llm_provider(self.llm("唯一配置", "key-one"), 1)
        active = registry.active_llm_providers()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["runtime_key"], "deepseek")

    def test_provider_model_crud_and_runtime_view(self) -> None:
        created = registry.create_llm_provider(self.llm(
            "列表配置", "key", provider="zhipu", api_style="chat_completions",
            models=["glm-5.3", "glm-4.7"],
        ), 1)
        self.assertEqual([m["name"] for m in created["models"]], ["glm-5.3", "glm-4.7"])
        # 列表响应永不包含密文
        self.assertNotIn("api_key_ciphertext", created)

        registry.add_provider_model(created["id"], {"name": "glm-4.6"}, 1)
        registry.update_provider_model(
            created["id"], "glm-4.6",
            {"vision": True, "settings": {"temperature": 0.3}}, 1,
        )
        active = registry.active_llm_providers(usable_only=True)[0]
        self.assertEqual(active["vision_model"], "glm-4.6")
        by_name = {m["name"]: m for m in active["models_detail"]}
        self.assertEqual(by_name["glm-4.6"]["settings"]["temperature"], 0.3)

        registry.delete_provider_model(created["id"], "glm-5.3", 1)
        active = registry.active_llm_providers()[0]
        self.assertNotIn("glm-5.3", active["models"])
        self.assertEqual(active["model_name"], "glm-4.7")

    def test_api_key_status_roundtrip(self) -> None:
        created = registry.create_llm_provider(self.llm("有密钥", "secret-1234"), 1)
        self.assertEqual(created["api_key_status"], "ok")
        cleared = registry.update_llm_provider(created["id"], {
            **self.llm("有密钥", ""), "clear_api_key": True,
        }, 1)
        self.assertEqual(cleared["api_key_status"], "unset")
        # 加密密钥轮换 → invalid
        with patch.object(registry, "_fernet_key", side_effect=registry.ModelRegistryError("无效")):
            self.assertEqual(registry._api_key_status("ciphertext"), "invalid")

    def test_invalid_config_skipped_in_overrides(self) -> None:
        first = registry.create_llm_provider(self.llm("主配置", "key-one"), 1)
        broken = registry.create_llm_provider(self.llm("坏配置", "key-two"), 1)
        # 模拟加密密钥丢失：仅坏配置的密文解密失败
        original = registry._decrypt
        broken_ciphertext = next(
            item["api_key_ciphertext"] for item in registry._read_unlocked()["providers"]
            if int(item["id"]) == broken["id"]
        )

        def _selective_decrypt(ciphertext):
            if ciphertext == broken_ciphertext:
                raise registry.ModelRegistryError("密钥失效")
            return original(ciphertext)

        with patch.object(registry, "_decrypt", side_effect=_selective_decrypt):
            overrides = registry.load_runtime_overrides()
        custom = overrides.get("custom_llm_configs", {})
        self.assertNotIn(f"deepseek::{broken['id']}", custom)
        # 坏配置被隔离后，唯一有效配置以 plain provider 键注册
        self.assertIn("deepseek", custom)
        self.assertNotIn("deepseek::", " ".join(custom))
        # 内置全局字段仍由首条有效配置填充
        self.assertEqual(overrides["deepseek_api_key"], "key-one")

    def test_v1_registry_auto_migrates(self) -> None:
        v1 = {
            "version": 1, "next_id": 3, "audit": [],
            "configs": [
                {
                    "id": 1, "name": "DeepSeek官方", "category": "llm",
                    "provider": "deepseek", "api_style": "responses",
                    "base_url": "https://api.deepseek.com", "gateway_mode": "base_url",
                    "native_tools": ["web_search"], "model_name": "deepseek-v4-flash",
                    "model_min": "deepseek-v4-pro", "vision_model": "deepseek-vision",
                    "enabled": True, "api_key_ciphertext": "", "api_key_hint": "",
                    "settings": {"temperature": 0.5},
                },
                {
                    "id": 2, "name": "EmbA", "category": "embedding",
                    "provider": "emb-a", "api_style": "embeddings",
                    "base_url": "https://a.invalid", "model_name": "emb-a-model",
                    "dimensions": 128, "enabled": True,
                    "api_key_ciphertext": "", "api_key_hint": "",
                    "settings": {},
                },
            ],
        }
        import json
        registry.REGISTRY_PATH.write_text(json.dumps(v1), encoding="utf-8")
        registry.init_model_registry()
        providers = registry.list_llm_providers()
        self.assertEqual(len(providers), 1)
        self.assertEqual(providers[0]["enabled_tools"], ["web_search"])
        self.assertEqual(providers[0]["enabled_models"], [
            "deepseek-v4-flash", "deepseek-v4-pro", "deepseek-vision",
        ])
        embeddings = registry.list_embedding_configs()
        self.assertEqual(len(embeddings), 1)
        self.assertEqual(embeddings[0]["model_name"], "emb-a-model")
        # v1 原文件备份保留
        backups = list(Path(str(registry.REGISTRY_PATH) + "*.bak.json").parent.glob(
            "model_api_configs.v1-*.bak.json",
        ))
        self.assertTrue(backups)

    def test_builtin_env_fallback_entry(self) -> None:
        runtime = RuntimeConfig(
            deepseek_api_key="env-key", deepseek_base_url="https://api.deepseek.com",
            deepseek_responses_models=("deepseek-v4-flash",),
            custom_llm_configs={},
        )
        entry = runtime.resolve_llm_entry("deepseek")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["api_key"], "env-key")
        self.assertEqual(entry["api_style"], "responses")
        self.assertIn("deepseek-v4-flash", entry["models"])

    def test_provider_id_key_resolves_entry(self) -> None:
        entry = {"id": 7, "name": "x", "provider": "zhipu", "api_style": "chat_completions",
                 "base_url": "https://x/v1", "api_key": "k", "gateway_mode": "base_url",
                 "native_tools": [], "settings": {}, "models": ["glm-5.3"]}
        runtime = RuntimeConfig(custom_llm_configs={"zhipu::7": entry})
        resolved = runtime.resolve_llm_entry("zhipu::7")
        self.assertEqual(resolved["api_key"], "k")
        self.assertEqual(runtime.get_api_key("zhipu::7"), "k")
        self.assertEqual(runtime.get_base_url("zhipu::7"), "https://x/v1")


class CreateModelDispatchTest(unittest.TestCase):
    @staticmethod
    def _entry(provider: str = "zhipu", api_style: str = "chat_completions",
               gateway_mode: str = "base_url", models: list[str] | None = None,
               native_tools: list[str] | None = None) -> dict:
        return {
            "id": 1, "name": "测试配置", "provider": provider,
            "api_style": api_style, "base_url": "https://gw.example/v1",
            "api_key": "test-key", "gateway_mode": gateway_mode,
            "native_tools": native_tools or [],
            "settings": {"temperature": 0.4},
            "models": models or ["glm-5.3", "glm-4.7"],
            "model_name": (models or ["glm-5.3"])[0],
        }

    def test_chat_provider_uses_gateway_chat_model(self) -> None:
        from LLM.model import GatewayChatModel

        runtime = RuntimeConfig(custom_llm_configs={"zhipu": self._entry()})
        model = create_model_helper(runtime, "zhipu", "glm-4.7")
        self.assertIsInstance(model, GatewayChatModel)
        self.assertEqual(model.model, "glm-4.7")
        self.assertEqual(model.gateway_mode, "base_url")
        self.assertEqual(model.thinking_style, "zhipu")

    def test_chat_full_endpoint_and_native_tools(self) -> None:
        from LLM.model import GatewayChatModel

        runtime = RuntimeConfig(custom_llm_configs={"zhipu": self._entry(
            gateway_mode="full_endpoint", native_tools=["web_search"],
        )})
        model = create_model_helper(runtime, "zhipu", None)
        self.assertEqual(model.gateway_mode, "full_endpoint")
        self.assertEqual(model.model, "glm-5.3")  # 默认取首个模型
        self.assertEqual(model.native_tools, [{"type": "web_search", "web_search": {
            "enable": True, "search_engine": "search_pro",
            "search_result": True, "count": 10, "content_size": "medium",
        }}])

    def test_responses_provider_uses_responses_driver(self) -> None:
        from LLM.model import DeepSeekResponsesModel

        runtime = RuntimeConfig(custom_llm_configs={"deepseek": self._entry(
            provider="deepseek", api_style="responses",
            models=["deepseek-v4-flash", "deepseek-v4-pro"],
        )})
        model = create_model_helper(runtime, "deepseek", None)
        self.assertIsInstance(model, DeepSeekResponsesModel)
        self.assertEqual(model.model, "deepseek-v4-flash")
        self.assertEqual(model.reasoning_wire_format, "responses")

    def test_chat_thinking_intensity_maps_to_effort(self) -> None:
        from LLM.model import GatewayChatModel

        runtime = RuntimeConfig(custom_llm_configs={"openai-compatible": self._entry(
            provider="openai-compatible",
            models=["demo-model"],
        )})
        model = create_model_helper(runtime, "openai-compatible", "demo-model", intensity="high")
        self.assertIsInstance(model, GatewayChatModel)
        self.assertEqual(model.parameters.reasoning_effort, "high")
        low = create_model_helper(runtime, "openai-compatible", "demo-model", intensity="off")
        self.assertFalse(low.parameters.thinking_enable)
        self.assertIsNone(low.parameters.reasoning_effort)


def create_model_helper(runtime: RuntimeConfig, provider: str, model: str | None,
                        intensity: str = "medium"):
    from LLM.model import create_model

    return create_model(
        provider=provider, model=model, thinking_intensity=intensity, config=runtime,
    )


if __name__ == "__main__":
    unittest.main()
