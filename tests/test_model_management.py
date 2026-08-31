"""大模型管理系统回归测试（v2：供应商 → 模型列表 → 每模型超参数）。

移植自 Docker 版同名 pytest 套件，存储层为本地 JSON 注册表
（Fernet 加密 + 原子写），测试通过 patch 路径实现相互隔离。
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from core import model_registry as registry
from LLM.model import DeepSeekResponsesModel, GatewayChatModel, create_model
from core.config import RuntimeConfig


def _provider_payload(
    name: str,
    provider: str,
    model: str,
    *,
    api_style: str = "chat_completions",
    gateway_mode: str = "base_url",
    enabled: bool = True,
    tools: list[str] | None = None,
    vision: bool = False,
    settings: dict | None = None,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "name": model, "enabled": True, "vision": vision,
    }
    if settings is not None:
        entry["settings"] = settings
    return {
        "name": name,
        "provider": provider,
        "api_style": api_style,
        "base_url": "https://example.invalid/v1",
        "gateway_mode": gateway_mode,
        "enabled_tools": tools or [],
        "enabled": enabled,
        "api_key": "sk-test",
        "models": [entry],
    }


class RegistryIsolationMixin:
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self._patches = [
            patch.object(registry, "LEGACY_DB_PATH", root / "users.db"),
            patch.object(registry, "REGISTRY_PATH", root / "model_api_configs.json"),
            patch.object(registry, "KEY_PATH", root / "model_api.key"),
            patch.dict(os.environ, {"LINGSHU_MODEL_CONFIG_KEY": ""}),
        ]
        for item in self._patches:
            item.start()
        registry.init_model_registry()

    def tearDown(self) -> None:
        for item in reversed(self._patches):
            item.stop()
        self.temp.cleanup()


class ProviderCRUDTest(RegistryIsolationMixin, unittest.TestCase):
    # ── 供应商 CRUD 与 runtime key ──

    def test_same_provider_multiple_vendors_can_be_enabled_together(self) -> None:
        """同一 provider（官方/中转）的多条配置可同时启用，runtime key 用 ::id 区分。"""
        official = registry.create_llm_provider(
            _provider_payload(
                "DeepSeek官方", "deepseek", "deepseek-v4-flash", api_style="responses",
            ),
            actor_id=1,
        )
        relay = registry.create_llm_provider(
            _provider_payload(
                "DeepSeek中转", "deepseek", "deepseek-v4-flash",
                api_style="chat_completions", gateway_mode="full_endpoint",
            ),
            actor_id=1,
        )
        providers = registry.active_llm_providers(usable_only=True)
        self.assertEqual(
            {item["runtime_key"] for item in providers},
            {f"deepseek::{official['id']}", f"deepseek::{relay['id']}"},
        )
        runtime = registry.load_runtime_overrides()
        custom = runtime["custom_llm_configs"]
        self.assertEqual(
            set(custom),
            {f"deepseek::{official['id']}", f"deepseek::{relay['id']}"},
        )
        self.assertEqual(custom[f"deepseek::{official['id']}"]["api_style"], "responses")
        self.assertEqual(custom[f"deepseek::{relay['id']}"]["gateway_mode"], "full_endpoint")

    def test_unique_provider_uses_plain_runtime_key(self) -> None:
        registry.create_llm_provider(
            _provider_payload("VendorA", "openai", "model-x", api_style="responses"),
            actor_id=1,
        )
        registry.create_llm_provider(
            _provider_payload("VendorB", "moonshot", "model-x"), actor_id=1,
        )
        providers = registry.active_llm_providers(usable_only=True)
        self.assertEqual({item["runtime_key"] for item in providers}, {"openai", "moonshot"})
        vendor_a = next(item for item in providers if item["runtime_key"] == "openai")
        self.assertEqual(vendor_a["models"], ["model-x"])

    def test_unknown_provider_rejected(self) -> None:
        with self.assertRaisesRegex(registry.ModelRegistryError, "不支持的供应商"):
            registry.create_llm_provider(
                _provider_payload("Bad", "not-a-catalog-key", "model-x"), actor_id=1,
            )

    def test_duplicate_name_rejected(self) -> None:
        registry.create_llm_provider(
            _provider_payload("同名", "openai", "model-x"), actor_id=1,
        )
        with self.assertRaisesRegex(registry.ModelRegistryError, "已存在"):
            registry.create_llm_provider(
                _provider_payload("同名", "moonshot", "model-y"), actor_id=1,
            )

    def test_update_filters_unsupported_native_tools(self) -> None:
        """协议/供应商变化时，剔除当前组合不再支持的原生工具。"""
        created = registry.create_llm_provider(
            _provider_payload("带工具", "deepseek", "m", api_style="responses",
                              tools=["web_search"]),
            actor_id=1,
        )
        self.assertEqual(created["enabled_tools"], ["web_search"])
        # moonshot 无原生工具目录 → 更新后工具被剔除
        updated = registry.update_llm_provider(created["id"], _provider_payload(
            "带工具", "moonshot", "m",
        ), 1)
        self.assertEqual(updated["enabled_tools"], [])

    def test_api_key_never_leaks_in_list(self) -> None:
        created = registry.create_llm_provider(
            _provider_payload("泄密检查", "openai", "model-x", api_style="responses"),
            actor_id=1,
        )
        self.assertNotIn("api_key_ciphertext", created)
        self.assertNotIn("sk-test", json.dumps(created))
        listed = registry.list_llm_providers()
        self.assertNotIn("sk-test", json.dumps(listed))


class ProviderModelTest(RegistryIsolationMixin, unittest.TestCase):
    # ── 模型列表 CRUD 与超参数 ──

    def test_provider_model_crud(self) -> None:
        created = registry.create_llm_provider(
            _provider_payload(
                "Multi", "deepseek", "deepseek-v4-flash", api_style="responses",
            ),
            actor_id=1,
        )
        pid = created["id"]
        registry.add_provider_model(
            pid,
            {"name": "deepseek-v4-pro", "vision": False,
             "settings": {"temperature": 0.3, "max_tokens": 8192}},
            actor_id=1,
        )
        registry.add_provider_model(
            pid, {"name": "deepseek-v4-flash-vision-exp", "vision": True}, actor_id=1,
        )
        providers = registry.active_llm_providers(usable_only=True)
        entry = providers[0]
        self.assertEqual(entry["models"], [
            "deepseek-v4-flash", "deepseek-v4-pro", "deepseek-v4-flash-vision-exp",
        ])
        self.assertEqual(entry["model_name"], "deepseek-v4-flash")
        self.assertEqual(entry["vision_model"], "deepseek-v4-flash-vision-exp")
        by_name = {m["name"]: m for m in entry["models_detail"]}
        self.assertEqual(by_name["deepseek-v4-pro"]["settings"]["temperature"], 0.3)
        self.assertEqual(by_name["deepseek-v4-pro"]["settings"]["max_tokens"], 8192)

        # 更新超参数，然后删除默认模型 → 默认顺延
        registry.update_provider_model(
            pid, "deepseek-v4-pro",
            {"settings": {"temperature": 0.9, "top_k": None}}, actor_id=1,
        )
        registry.delete_provider_model(pid, "deepseek-v4-flash", actor_id=1)
        entry = registry.active_llm_providers(usable_only=True)[0]
        self.assertEqual(entry["model_name"], "deepseek-v4-pro")
        self.assertNotIn("deepseek-v4-flash", entry["models"])

    def test_duplicate_model_rejected(self) -> None:
        created = registry.create_llm_provider(
            _provider_payload("Dup", "deepseek", "deepseek-v4-flash", api_style="responses"),
            actor_id=1,
        )
        with self.assertRaisesRegex(registry.ModelRegistryError, "已存在"):
            registry.add_provider_model(
                created["id"], {"name": "deepseek-v4-flash"}, actor_id=1,
            )

    def test_model_settings_validation(self) -> None:
        created = registry.create_llm_provider(
            _provider_payload("Vnd", "dashscope", "qwen3-max"), actor_id=1,
        )
        with self.assertRaisesRegex(registry.ModelRegistryError, "temperature"):
            registry.add_provider_model(
                created["id"], {"name": "bad", "settings": {"temperature": 5}}, actor_id=1,
            )
        with self.assertRaises(registry.ModelRegistryError):
            registry.add_provider_model(created["id"], {"name": "a\nb"}, actor_id=1)


class ProbeModelsTest(RegistryIsolationMixin, unittest.TestCase):
    # ── /models 探测：协议分发与响应解析（mock HTTP 层） ──

    def _mock_response(self, payload: object) -> MagicMock:
        response = MagicMock()
        response.json.return_value = payload
        response.raise_for_status.return_value = None
        return response

    def test_openai_compatible_probe(self) -> None:
        with patch.object(registry.httpx, "get", return_value=self._mock_response(
            {"data": [{"id": "model-a"}, {"id": "model-b"}]},
        )) as mock_get:
            result = registry.fetch_provider_models("openai", "https://gw.example/v1", "sk-x")
        self.assertEqual(result["models"], ["model-a", "model-b"])
        self.assertEqual(mock_get.call_args.args[0], "https://gw.example/v1/models")
        self.assertEqual(
            mock_get.call_args.kwargs["headers"], {"Authorization": "Bearer sk-x"},
        )

    def test_ollama_probe_uses_default_host_and_tags(self) -> None:
        with patch.object(registry.httpx, "get", return_value=self._mock_response(
            {"models": [{"name": "qwen3:32b"}]},
        )) as mock_get:
            result = registry.fetch_provider_models("ollama", "", "")
        self.assertEqual(result["models"], ["qwen3:32b"])
        self.assertEqual(mock_get.call_args.args[0], "http://127.0.0.1:11434/api/tags")

    def test_anthropic_probe_headers(self) -> None:
        with patch.object(registry.httpx, "get", return_value=self._mock_response(
            {"data": [{"id": "claude-x"}]},
        )) as mock_get:
            result = registry.fetch_provider_models(
                "anthropic", "https://api.anthropic.com", "sk-ant",
            )
        self.assertEqual(result["models"], ["claude-x"])
        self.assertEqual(mock_get.call_args.args[0], "https://api.anthropic.com/v1/models")
        self.assertEqual(
            mock_get.call_args.kwargs["headers"],
            {"x-api-key": "sk-ant", "anthropic-version": "2023-06-01"},
        )

    def test_gemini_probe_filters_non_generate_models(self) -> None:
        with patch.object(registry.httpx, "get", return_value=self._mock_response(
            {"models": [
                {"name": "models/gemini-a", "supportedGenerationMethods": ["generateContent"]},
                {"name": "models/embed-b", "supportedGenerationMethods": ["embedContent"]},
            ]},
        )) as mock_get:
            result = registry.fetch_provider_models("gemini", "", "g-key")
        self.assertEqual(result["models"], ["gemini-a"])
        self.assertEqual(mock_get.call_args.kwargs["params"], {"key": "g-key"})

    def test_probe_http_error_wrapped(self) -> None:
        response = MagicMock()
        response.raise_for_status.side_effect = registry.httpx.HTTPStatusError(
            "500", request=MagicMock(), response=MagicMock(status_code=500),
        )
        with patch.object(registry.httpx, "get", return_value=response):
            with self.assertRaisesRegex(registry.ModelRegistryError, "模型列表拉取失败"):
                registry.fetch_provider_models("openai", "https://gw.example/v1", "sk-x")


class MigrationTest(RegistryIsolationMixin, unittest.TestCase):
    # ── v1 → v2 迁移 ──

    def test_v1_registry_auto_migrates_with_backup(self) -> None:
        v1 = {
            "version": 1, "next_id": 2, "audit": [],
            "configs": [
                {
                    "id": 1, "name": "中转配置", "category": "llm",
                    "provider": "zhipu1", "api_style": "responses",
                    "base_url": "https://gw.example/v1", "gateway_mode": "base_url",
                    "native_tools": [], "models": ["glm-5.3"],
                    "vision_models": ["glm-5.3"],
                    "enabled": True, "api_key_ciphertext": "", "api_key_hint": "",
                    "settings": {},
                },
            ],
        }
        registry.REGISTRY_PATH.write_text(json.dumps(v1), encoding="utf-8")
        registry.init_model_registry()
        providers = registry.list_llm_providers()
        # 目录外的 provider 键（zhipu1）映射为 openai-compatible
        self.assertEqual(providers[0]["provider"], "openai-compatible")
        self.assertEqual(providers[0]["enabled_models"], ["glm-5.3"])
        detail = providers[0]["models"][0]
        self.assertTrue(detail["vision"])
        self.assertTrue(
            list(registry.REGISTRY_PATH.parent.glob("model_api_configs.v1-*.bak.json")),
        )
        # 迁移后再读取：结构已是 v2，不再重复迁移
        data = json.loads(registry.REGISTRY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], 2)


class EmbeddingTest(RegistryIsolationMixin, unittest.TestCase):
    # ── 嵌入模型：全局单条启用 ──

    @staticmethod
    def _embedding(name: str, *, enabled: bool = True) -> dict:
        return {
            "name": name, "category": "embedding", "provider": "emb-p",
            "api_style": "embeddings", "base_url": "https://emb.example/v1",
            "model_name": f"{name}-model", "dimensions": 128,
            "pass_dimensions": True, "enabled": enabled, "api_key": "sk-emb",
            "settings": {},
        }

    def test_only_one_embedding_enabled(self) -> None:
        first = registry.create_embedding_config(self._embedding("EmbA"), 1)
        self.assertTrue(first["enabled"])
        second = registry.create_embedding_config(self._embedding("EmbB"), 1)
        self.assertTrue(second["enabled"])
        states = {c["name"]: c["enabled"] for c in registry.list_embedding_configs()}
        self.assertFalse(states["EmbA"])
        self.assertTrue(states["EmbB"])

    def test_embedding_runtime_overrides(self) -> None:
        registry.create_embedding_config(self._embedding("EmbA"), 1)
        overrides = registry.load_runtime_overrides()
        self.assertEqual(overrides["embedding_model"], "EmbA-model")
        self.assertEqual(overrides["embedding_dimensions"], 128)
        self.assertEqual(overrides["embedding_api_key"], "sk-emb")


class FactoryDispatchTest(RegistryIsolationMixin, unittest.TestCase):
    # ── 注册表 → 模型工厂端到端（驱动分发） ──

    def test_responses_and_native_drivers(self) -> None:
        registry.create_llm_provider(_provider_payload(
            "DeepSeek官方", "deepseek", "deepseek-v4-flash", api_style="responses",
        ), actor_id=1)
        registry.create_llm_provider(_provider_payload(
            "Claude", "anthropic", "claude-sonnet-4-6", api_style="anthropic",
        ), actor_id=1)
        overrides = registry.load_runtime_overrides()
        runtime = RuntimeConfig(custom_llm_configs=overrides.get("custom_llm_configs", {}))
        self.assertIsInstance(
            create_model(provider="deepseek", config=runtime), DeepSeekResponsesModel,
        )
        model = create_model(provider="anthropic", config=runtime)
        self.assertEqual(type(model).__name__, "AnthropicChatModel")

    def test_chat_gateway_with_zhipu_thinking(self) -> None:
        registry.create_llm_provider(_provider_payload(
            "智谱", "zhipu", "glm-5.3", api_style="chat_completions",
        ), actor_id=1)
        overrides = registry.load_runtime_overrides()
        runtime = RuntimeConfig(custom_llm_configs=overrides.get("custom_llm_configs", {}))
        model = create_model(provider="zhipu", model="glm-5.3", config=runtime)
        self.assertIsInstance(model, GatewayChatModel)
        self.assertEqual(model.thinking_style, "zhipu")


if __name__ == "__main__":
    unittest.main()
