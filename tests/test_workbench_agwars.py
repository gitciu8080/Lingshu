"""AgWars 工作台测试：HMAC 签名、凭据脱敏、身份文件、目标约束。纯本地。"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import workbench_agwars_agent as ag


class SigningTest(unittest.TestCase):
    """签名必须与平台任务书给出的参考实现逐字节一致。"""

    def test_matches_reference_implementation(self) -> None:
        secret = "s3cr3t"
        ts, nonce = "1700000000", "a" * 32
        msg = f"POST\n/agent/slot\n{ts}\n{nonce}"
        expected = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(ag.AgWarsClient.sign("POST", "/agent/slot", ts, nonce, secret),
                         expected)

    def test_method_is_uppercased(self) -> None:
        args = ("post", "/agent/slot", "1", "n", "k")
        self.assertEqual(ag.AgWarsClient.sign(*args),
                         ag.AgWarsClient.sign("POST", "/agent/slot", "1", "n", "k"))

    def test_signed_headers_shape(self) -> None:
        client = ag.AgWarsClient()
        client.token, client.secret, client.trace = "tok", "sec", "tr_1"
        headers = client.signed_headers("GET", "/agent/slot")
        for name in ("Authorization", "X-Trace-Id", "X-Agent-Timestamp",
                     "X-Agent-Nonce", "X-Agent-Signature"):
            self.assertIn(name, headers)
        self.assertEqual(headers["Authorization"], "Bearer tok")
        self.assertEqual(headers["X-Trace-Id"], "tr_1")
        # 用返回的头重新计算签名，必须自洽
        recomputed = ag.AgWarsClient.sign(
            "GET", "/agent/slot", headers["X-Agent-Timestamp"],
            headers["X-Agent-Nonce"], "sec")
        self.assertEqual(recomputed, headers["X-Agent-Signature"])

    def test_nonce_is_unique_per_request(self) -> None:
        client = ag.AgWarsClient()
        client.token, client.secret, client.trace = "t", "s", "tr"
        a = client.signed_headers("POST", "/agent/slot")
        b = client.signed_headers("POST", "/agent/slot")
        self.assertNotEqual(a["X-Agent-Nonce"], b["X-Agent-Nonce"])
        self.assertNotEqual(a["X-Agent-Signature"], b["X-Agent-Signature"])

    def test_missing_credentials_raises(self) -> None:
        client = ag.AgWarsClient()
        client.token = client.secret = client.trace = ""
        with self.assertRaises(ag.AgWarsError):
            client.signed_headers("POST", "/agent/slot")


class CredentialTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agwars-test-"))
        self.patches = [
            mock.patch.object(ag, "_DATA_DIR", self.tmp),
            mock.patch.object(ag, "CREDENTIALS_FILE", self.tmp / "credentials.json"),
            mock.patch.object(ag, "IDENTITY_FILE", self.tmp / "agent-credentials.md"),
            mock.patch.object(ag, "DEVICE_FILE", self.tmp / "device-id.txt"),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in self.patches:
            patch.stop()

    def test_brief_hides_secrets(self) -> None:
        ag.save_credentials({
            "api_token": "tok_abcdefghijklmnop", "api_secret": "verysecret9999",
            "trace_id": "tr_x", "player_name": "三字名", "agent_id": "agent-1",
            "shard": "shard-1", "score_total": 20000,
        })
        brief = ag.credentials_brief()
        self.assertTrue(brief["registered"])
        dumped = json.dumps(brief, ensure_ascii=False)
        self.assertNotIn("verysecret9999", dumped)      # secret 明文不得出现
        self.assertNotIn("tok_abcdefghijklmnop", dumped)  # token 明文不得出现
        self.assertEqual(brief["secret_hint"], "…9999")

    def test_identity_file_permissions_and_fields(self) -> None:
        data = {"player_name": "三字名", "agent_id": "agent-1", "shard": "shard-1",
                "api_token": "tok", "trace_id": "tr", "player_flag": "pf",
                "api_secret": "sec", "registered_at": "2026-11-12 10:00:00"}
        path = ag.write_identity_file(data)
        text = path.read_text(encoding="utf-8")
        for field in ("用户名", "Agent ID", "分片", "API Token", "Trace ID",
                      "Player Flag", "API Secret", "主人页面"):
            self.assertIn(field, text)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600, oct(mode))

    def test_device_id_stable(self) -> None:
        first = ag.device_id()
        second = ag.device_id()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 32)

    def test_unregistered_brief(self) -> None:
        self.assertEqual(ag.credentials_brief(), {"registered": False})


class ProxyRegistryTest(unittest.TestCase):
    """实例访问代理：token 由工作台注入，模型上下文只见代理地址。"""

    def setUp(self) -> None:
        import workbench_ctf2_web as wb

        self.wb = wb
        self.wb.STATE["agwars"].setdefault("proxies", {}).clear()

    def test_register_and_release(self) -> None:
        wb = self.wb
        proxy_id = wb.agwars_proxy_register("h01", "http://arena.hxorz.com:29000/")
        self.assertIn(proxy_id, wb.STATE["agwars"]["proxies"])
        info = wb.STATE["agwars"]["proxies"][proxy_id]
        self.assertEqual(info["slot_url"], "http://arena.hxorz.com:29000")
        wb.agwars_proxy_release(proxy_id)
        self.assertNotIn(proxy_id, wb.STATE["agwars"]["proxies"])

    def test_proxy_ids_unique(self) -> None:
        wb = self.wb
        a = wb.agwars_proxy_register("h01", "http://x:1")
        b = wb.agwars_proxy_register("h01", "http://x:1")
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), 16)

    def test_unknown_proxy_returns_404(self) -> None:
        from fastapi.testclient import TestClient

        with TestClient(self.wb.app) as client:
            response = client.get("/agwars/proxy/deadbeef/healthz")
        self.assertEqual(response.status_code, 404)

    def test_self_base_uses_runtime_port(self) -> None:
        self.wb.STATE["self_port"] = 9099
        try:
            self.assertEqual(self.wb.agwars_self_base(), "http://127.0.0.1:9099")
        finally:
            self.wb.STATE.pop("self_port", None)


class GoalConstraintTest(unittest.TestCase):
    def test_goal_limits_scope_and_states_rules(self) -> None:
        goal = ag.build_agwars_goal("h01", "http://arena.hxorz.com:29000", "fast")
        self.assertIn("http://arena.hxorz.com:29000", goal)
        self.assertIn("h01", goal)
        self.assertIn("不得访问平台 API", goal)       # 禁止行为写进任务目标
        self.assertIn("其他分片", goal)
        self.assertIn("工作台负责提交", goal)


if __name__ == "__main__":
    unittest.main()
