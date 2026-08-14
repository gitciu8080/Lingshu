from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import model_registry


class ModelRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_patch = patch.object(model_registry, "REGISTRY_PATH", root / "model_api_configs.json")
        self.legacy_patch = patch.object(model_registry, "LEGACY_DB_PATH", root / "missing-users.db")
        self.key_patch = patch.object(model_registry, "KEY_PATH", root / "model_api.key")
        self.env_patch = patch.dict(os.environ, {"LINGSHU_MODEL_CONFIG_KEY": ""})
        self.db_patch.start()
        self.legacy_patch.start()
        self.key_patch.start()
        self.env_patch.start()
        model_registry.init_model_registry()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.key_patch.stop()
        self.legacy_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()

    @staticmethod
    def llm(name: str, key: str, *, enabled: bool = True) -> dict:
        return {
            "name": name,
            "category": "llm",
            "provider": "deepseek",
            "api_style": "responses",
            "base_url": "https://models.example/v1",
            "api_key": key,
            "model_low": "model-low",
            "model_min": "model-min",
            "model_max": "model-max",
            "enabled": enabled,
        }

    def test_secret_is_encrypted_and_runtime_receives_plaintext(self) -> None:
        payload = self.llm("primary", "secret-1234")
        payload["settings"] = {
            "temperature": 0.25, "top_p": 0.8, "max_tokens": 4096,
            "max_retries": 2, "context_size": 200000,
            "timeout_seconds": 180, "thinking_enabled": True,
        }
        created = model_registry.create_model_config(payload, 1)
        self.assertNotIn("api_key", created)
        self.assertEqual(created["api_key_masked"], "••••••••1234")
        raw = model_registry.REGISTRY_PATH.read_text(encoding="utf-8")
        self.assertNotIn("secret-1234", raw)
        overrides = model_registry.load_runtime_overrides()
        self.assertEqual(overrides["deepseek_api_key"], "secret-1234")
        self.assertEqual(overrides["deepseek_model_max"], "model-max")
        self.assertEqual(overrides["deepseek_model_settings"]["temperature"], 0.25)
        self.assertEqual(overrides["deepseek_model_settings"]["context_size"], 200000)

    def test_only_one_profile_per_llm_provider_is_active(self) -> None:
        first = model_registry.create_model_config(self.llm("first", "key-one"), 1)
        second = model_registry.create_model_config(self.llm("second", "key-two"), 1)
        configs = {item["id"]: item for item in model_registry.list_model_configs("llm")}
        self.assertFalse(configs[first["id"]]["enabled"])
        self.assertTrue(configs[second["id"]]["enabled"])

    def test_edit_can_preserve_or_clear_key(self) -> None:
        created = model_registry.create_model_config(self.llm("editable", "secret-9876"), 1)
        payload = self.llm("editable", "")
        updated = model_registry.update_model_config(created["id"], payload, 1)
        self.assertTrue(updated["has_api_key"])
        payload["clear_api_key"] = True
        cleared = model_registry.update_model_config(created["id"], payload, 1)
        self.assertFalse(cleared["has_api_key"])
        self.assertEqual(model_registry.load_runtime_overrides()["deepseek_api_key"], "")

    def test_embedding_override_and_delete(self) -> None:
        payload = {
            "name": "local embedding", "category": "embedding",
            "provider": "openai-compatible", "api_style": "embeddings",
            "base_url": "http://127.0.0.1:8201/v1", "api_key": "embed-key",
            "model_name": "bge-m3", "dimensions": 1024,
            "pass_dimensions": False, "enabled": True,
        }
        created = model_registry.create_model_config(payload, 1)
        overrides = model_registry.load_runtime_overrides()
        self.assertEqual(overrides["embedding_model"], "bge-m3")
        self.assertFalse(overrides["embedding_pass_dimensions"])
        model_registry.delete_model_config(created["id"], 1)
        self.assertEqual(model_registry.list_model_configs("embedding"), [])

    def test_qwen_rejects_unsupported_responses_protocol(self) -> None:
        payload = self.llm("qwen", "local-key")
        payload.update(provider="qwen", api_style="responses")
        with self.assertRaisesRegex(model_registry.ModelRegistryError, "Chat Completions"):
            model_registry.create_model_config(payload, 1)

    def test_custom_llm_provider_is_available_to_runtime(self) -> None:
        payload = self.llm("OpenRouter", "router-key")
        payload.update(
            provider="openrouter", api_style="responses",
            base_url="https://openrouter.example/v1",
        )
        created = model_registry.create_model_config(payload, 1)
        self.assertEqual(created["provider"], "openrouter")
        public = model_registry.active_llm_providers()
        self.assertEqual(public[0]["provider"], "openrouter")
        self.assertNotIn("api_key_ciphertext", public[0])
        custom = model_registry.load_runtime_overrides()["custom_llm_configs"]["openrouter"]
        self.assertEqual(custom["api_key"], "router-key")
        self.assertEqual(custom["api_style"], "responses")

        from config import RuntimeConfig
        from LLM.model import OpenAICompatible
        from agentscope.model import OpenAIResponseModel

        runtime = RuntimeConfig(custom_llm_configs={"openrouter": custom})
        model = OpenAICompatible("openrouter", Ver="Min", config=runtime)
        self.assertIsInstance(model, OpenAIResponseModel)
        self.assertEqual(model.model, "model-min")


if __name__ == "__main__":
    unittest.main()
