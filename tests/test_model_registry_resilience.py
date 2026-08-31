"""Superadmin 模型注册表密钥恢复回归测试（本地 JSON 存储）。

移植自 Docker 版同名 pytest 套件（原针对 PostgreSQL + 密钥轮换场景）：
加密密钥文件丢失/轮换后，旧密文标记 invalid 且运行时隔离该配置；
重新填写 API Key 保存后即恢复。
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

from core import model_registry as registry


def _payload(name: str, provider: str, key: str) -> dict[str, object]:
    return {
        "name": name,
        "provider": provider,
        "api_style": "chat_completions",
        "base_url": "https://example.invalid/v1",
        "gateway_mode": "base_url",
        "enabled": True,
        "enabled_tools": [],
        "api_key": key,
        "models": [{"name": "example-model", "enabled": True, "vision": False}],
    }


class RegistryKeyRecoveryTest(unittest.TestCase):
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
        self.key_path = root / "model_api.key"
        registry.init_model_registry()

    def tearDown(self) -> None:
        for item in reversed(self._patches):
            item.stop()
        self.temp.cleanup()

    def test_key_rotation_marks_invalid_and_recovery_works(self) -> None:
        created = registry.create_llm_provider(
            _payload("轮换配置", "openai", "sk-original"), actor_id=1,
        )
        self.assertEqual(created["api_key_status"], "ok")

        # 模拟加密密钥文件被删除后重建（轮换）：旧密文无法解密。
        self.key_path.unlink()
        rotated = Fernet.generate_key()
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, rotated + b"\n")
        finally:
            os.close(fd)

        listed = {item["id"]: item for item in registry.list_llm_providers()}
        self.assertEqual(listed[created["id"]]["api_key_status"], "invalid")
        # 运行时视图（usable_only）隔离该配置；带密钥视图直接跳过。
        self.assertEqual(registry.active_llm_providers(usable_only=True), [])
        overrides = registry.load_runtime_overrides()
        self.assertNotIn("custom_llm_configs", overrides)

        # 重新填写 API Key 保存 → 用当前密钥重新加密，配置恢复。
        recovered = registry.update_llm_provider(
            created["id"], _payload("轮换配置", "openai", "sk-new-key"), actor_id=1,
        )
        self.assertEqual(recovered["api_key_status"], "ok")
        active = registry.active_llm_providers(usable_only=True)
        self.assertEqual([item["runtime_key"] for item in active], ["openai"])
        overrides = registry.load_runtime_overrides()
        self.assertEqual(
            overrides["custom_llm_configs"]["openai"]["api_key"], "sk-new-key",
        )

    def test_clear_api_key_marks_unset(self) -> None:
        created = registry.create_llm_provider(
            _payload("清除检查", "openai", "sk-clear-me"), actor_id=1,
        )
        cleared = registry.update_llm_provider(created["id"], {
            **_payload("清除检查", "openai", ""), "clear_api_key": True,
        }, 1)
        self.assertEqual(cleared["api_key_status"], "unset")
        self.assertEqual(cleared["api_key_masked"], "未设置")
        self.assertFalse(cleared["has_api_key"])


if __name__ == "__main__":
    unittest.main()
