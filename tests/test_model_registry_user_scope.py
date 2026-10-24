"""模型注册表按用户划分作用域（owner_id 私有池）的回归测试。"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import model_registry as registry
from core.model_registry import (
    ModelRegistryError,
    _UNSET,
    active_llm_providers,
    create_llm_provider,
    delete_llm_provider,
    list_llm_providers,
    load_runtime_overrides,
    update_llm_provider,
)


def _llm_payload(name: str, *, enabled: bool = True, models: list[str] | None = None) -> dict:
    return {
        "name": name, "provider": "deepseek", "api_style": "chat_completions",
        "base_url": "https://models.example/v1", "api_key": "sk-test",
        "gateway_mode": "base_url", "enabled_tools": [], "enabled": enabled,
        "models": [
            {"name": n, "enabled": True, "vision": False, "settings": {}}
            for n in (models or ["model-a"])
        ],
    }


class RegistryUserScopeTest(unittest.TestCase):
    """owner_id 私有池：可见性、runtime_key 作用域、越权拦截与 runtime 覆盖。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        for attr, target in (
            ("db_patch", "LEGACY_DB_PATH"),
            ("path_patch", "REGISTRY_PATH"),
            ("key_patch", "KEY_PATH"),
        ):
            patcher = patch.object(registry, target, root / target.lower())
            setattr(self, attr, patcher.start())
            self.addCleanup(patcher.stop)
        env_patch = patch.dict(os.environ, {"LINGSHU_MODEL_CONFIG_KEY": ""})
        env_patch.start()
        self.addCleanup(env_patch.stop)
        registry.init_model_registry()
        # 平台池 1 条（deepseek，id=1）+ 用户 7/8 各 1 条（deepseek）
        create_llm_provider(_llm_payload("platform-ds"), actor_id=1)
        create_llm_provider(_llm_payload("user7-ds"), actor_id=7, owner_id=7)
        create_llm_provider(_llm_payload("user8-ds"), actor_id=8, owner_id=8)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_owner_id_persisted(self) -> None:
        with patch.object(
            registry, "_read_unlocked",
            wraps=registry._read_unlocked,  # type: ignore[attr-defined]
        ):
            raw = registry._read_unlocked()  # type: ignore[attr-defined]
        by_name = {p["name"]: p for p in raw["providers"]}
        self.assertIsNone(by_name["platform-ds"].get("owner_id"))
        self.assertEqual(by_name["user7-ds"].get("owner_id"), 7)

    def test_visibility_three_scopes(self) -> None:
        user7 = active_llm_providers(owner_user_id=7, owner_is_superadmin=False)
        self.assertEqual([p["name"] for p in user7], ["user7-ds"])
        superadmin = active_llm_providers(owner_user_id=99, owner_is_superadmin=True)
        self.assertEqual(
            sorted(p["name"] for p in superadmin), ["platform-ds"],
            "超管=平台池+自己的私有池（99 号无私有配置时仅平台池）",
        )
        cli = active_llm_providers(owner_user_id=None, owner_is_superadmin=False)
        self.assertEqual([p["name"] for p in cli], ["platform-ds"])
        unset = active_llm_providers(owner_user_id=_UNSET)
        self.assertEqual(len(unset), 3, "_UNSET 哨兵保持旧行为（不过滤）")

    def test_runtime_key_scoped_per_view(self) -> None:
        # 每个视图内 deepseek 均唯一 → runtime_key 均为裸 provider 名，
        # 且互不串（不同用户解析到不同配置）。
        user7 = active_llm_providers(owner_user_id=7)
        self.assertEqual(user7[0]["runtime_key"], "deepseek")
        self.assertEqual(user7[0]["name"], "user7-ds")
        cli = active_llm_providers(owner_user_id=None)
        self.assertEqual(cli[0]["name"], "platform-ds")

    def test_load_runtime_overrides_scoped(self) -> None:
        overrides7 = load_runtime_overrides(owner_user_id=7)
        self.assertIn("deepseek", overrides7["custom_llm_configs"])
        self.assertEqual(
            overrides7["custom_llm_configs"]["deepseek"]["name"], "user7-ds",
        )
        overrides_cli = load_runtime_overrides(owner_user_id=None)
        self.assertEqual(
            overrides_cli["custom_llm_configs"]["deepseek"]["name"], "platform-ds",
        )

    def test_cross_user_update_rejected(self) -> None:
        providers = list_llm_providers(owner_user_id=8)
        target_id = next(p["id"] for p in providers if p["name"] == "user8-ds")
        with self.assertRaises(ModelRegistryError):
            update_llm_provider(
                target_id, _llm_payload("hijack"), actor_id=7,
                actor_user_id=7, actor_is_superadmin=False,
            )
        with self.assertRaises(ModelRegistryError):
            delete_llm_provider(
                target_id, actor_id=7,
                actor_user_id=7, actor_is_superadmin=False,
            )

    def test_superadmin_can_manage_platform(self) -> None:
        providers = list_llm_providers(owner_user_id=99, owner_is_superadmin=True)
        platform_id = next(p["id"] for p in providers if p["name"] == "platform-ds")
        updated = update_llm_provider(
            platform_id, _llm_payload("platform-ds-v2"), actor_id=99,
            actor_user_id=99, actor_is_superadmin=True,
        )
        self.assertEqual(updated["name"], "platform-ds-v2")

    def test_same_name_across_pools_allowed(self) -> None:
        create_llm_provider(_llm_payload("platform-ds"), actor_id=7, owner_id=7)
        # 同名在另一用户池不冲突；同池内仍拒绝
        with self.assertRaises(ModelRegistryError):
            create_llm_provider(_llm_payload("platform-ds"), actor_id=7, owner_id=7)

    def test_embedding_not_filtered_by_scope(self) -> None:
        registry.create_embedding_config(
            {
                "name": "emb", "provider": "openai-compatible",
                "base_url": "https://emb.example/v1", "api_key": "sk-emb",
                "model_name": "text-embedding", "dimensions": 1024,
                "enabled": True,
            },
            actor_id=1,
        )
        for scope in (
            {"owner_user_id": None},
            {"owner_user_id": 7, "owner_is_superadmin": False},
        ):
            overrides = load_runtime_overrides(**scope)
            self.assertEqual(overrides.get("embedding_model"), "text-embedding")


if __name__ == "__main__":
    unittest.main()
