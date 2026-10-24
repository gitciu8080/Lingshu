"""用户级 Agent 模型分工（agent_model_bindings）的单元测试。

SQLite 部分把 core.auth 的 DB_PATH 打到临时文件；resolve_role_models 为
纯逻辑，直接注入假的 build_model。
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import auth
from core import model_bindings as mb
from core.model_bindings import (
    AGENT_MODEL_ROLES,
    clear_agent_model_binding,
    get_agent_model_bindings,
    resolve_role_models,
    set_agent_model_binding,
)


class AgentModelBindingsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(auth, "DB_PATH", Path(self.temp.name) / "users.db")
        self.db_patch.start()
        auth.init_db()
        # 测试用户（直接写库，绕过注册接口的密码策略）
        conn = auth.get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES ('u1', 'x')",
            )
            conn.commit()
            self.user_id = conn.execute(
                "SELECT id FROM users WHERE username='u1'",
            ).fetchone()["id"]
        finally:
            conn.close()

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.temp.cleanup()

    def test_table_migration_and_roundtrip(self) -> None:
        conn = auth.get_db()
        try:
            columns = {row["name"] for row in conn.execute(
                "PRAGMA table_info(agent_model_bindings)",
            )}
        finally:
            conn.close()
        self.assertIn("thinking_intensity", columns)

        self.assertEqual(get_agent_model_bindings(self.user_id), {})
        set_agent_model_binding(
            self.user_id, "brain", "deepseek::2", "glm-5.3", "high",
        )
        set_agent_model_binding(self.user_id, "attack", "zhipu", "glm-5.3")
        bindings = get_agent_model_bindings(self.user_id)
        self.assertEqual(bindings["brain"], {
            "provider": "deepseek::2", "model": "glm-5.3", "thinking_intensity": "high",
        })
        self.assertEqual(bindings["attack"]["thinking_intensity"], None)

        # UPSERT 覆盖 + 单角色清除
        set_agent_model_binding(self.user_id, "brain", "qwen", "qwen3", "low")
        clear_agent_model_binding(self.user_id, "attack")
        bindings = get_agent_model_bindings(self.user_id)
        self.assertEqual(bindings["brain"]["provider"], "qwen")
        self.assertNotIn("attack", bindings)

    def test_invalid_role_and_intensity(self) -> None:
        with self.assertRaises(ValueError):
            set_agent_model_binding(self.user_id, "root", "deepseek", "m")
        with self.assertRaises(ValueError):
            set_agent_model_binding(self.user_id, "brain", "deepseek", "m", "ultra")
        with self.assertRaises(ValueError):
            set_agent_model_binding(self.user_id, "brain", "", "m")
        # 全部合法角色可写入
        for role in AGENT_MODEL_ROLES:
            set_agent_model_binding(self.user_id, role, "deepseek", "m")
        self.assertEqual(set(get_agent_model_bindings(self.user_id)), set(AGENT_MODEL_ROLES))

    def test_resolve_role_models_dedup_and_fallback(self) -> None:
        built: list[tuple[str, str, str]] = []
        counter = {"n": 0}

        def build(provider: str, model: str, intensity: str) -> str:
            built.append((provider, model, intensity))
            counter["n"] += 1
            return f"instance-{counter['n']}"

        def failing(provider: str, model: str, intensity: str) -> str:
            if provider == "gone":
                raise ValueError("模型提供商未启用或不存在: gone")
            return build(provider, model, intensity)

        bindings = {
            "brain": {"provider": "a", "model": "m1", "thinking_intensity": None},
            "attack": {"provider": "a", "model": "m1", "thinking_intensity": None},
            "recon": {"provider": "a", "model": "m2", "thinking_intensity": "high"},
            "triage": {"provider": "gone", "model": "m3", "thinking_intensity": None},
            "summary": {"provider": "", "model": "", "thinking_intensity": None},
        }
        shared = "shared-main"
        resolved, warnings = resolve_role_models(bindings, failing, shared, "medium")

        # (a,m1) 只构建一次；brain/attack 共享同一实例
        self.assertEqual(resolved["brain"], resolved["attack"])
        self.assertEqual(len([b for b in built if b[:2] == ("a", "m1")]), 1)
        # 显式 intensity 覆盖默认值；未填时用默认
        self.assertIn(("a", "m2", "high"), built)
        self.assertIn(("a", "m1", "medium"), built)
        # 失效绑定不进入 resolved（调用方按主模型回退）并产生告警；空绑定被跳过
        self.assertNotIn("triage", resolved)
        self.assertNotIn("summary", resolved)
        self.assertEqual(len(warnings), 1)
        self.assertIn("triage", warnings[0])


if __name__ == "__main__":
    unittest.main()
