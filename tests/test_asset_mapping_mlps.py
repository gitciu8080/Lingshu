"""资产台账 + scope 自动扩容 + AssetIntel + mlps 测试（纯本地）。"""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import httpx

from agent.categorize import extract_assets, extract_verdicts
from agent.Orchestrator import (
    _auto_expand_scope_for_asset,
    mlps_completion_gate,
)
from core.TaskState import AssetRecord, MissionState
from Tools.ScopeRegistry import ScopeRegistry


def _mission(**kw) -> MissionState:
    defaults = dict(target="192.168.1.1", goal="g", authorized=True,
                    session_id="asset-test", mission_mode="mlps")
    defaults.update(kw)
    return MissionState(**defaults)


class AssetLedgerTest(unittest.TestCase):
    def test_add_asset_dedup_and_update(self) -> None:
        mission = _mission()
        evidence = mission.add_evidence("Recon", "recon_report", "r", confidence=0.9)
        first = mission.add_asset("192.168.1.10", 80, "http",
                                  source="Ethan", evidence_ids=[evidence.id],
                                  confidence=0.9)
        second = mission.add_asset("192.168.1.10", 80, "httpd",
                                   source="Ethan", evidence_ids=[evidence.id],
                                   confidence=0.7)
        self.assertIs(first, second)                 # 同 (host,port) 更新而非新增
        self.assertEqual(first.service, "httpd")     # service 被刷新
        self.assertEqual(first.confidence, 0.9)      # confidence 取 max
        self.assertEqual(len(mission.assets), 1)
        third = mission.add_asset("192.168.1.10", 443, "https",
                                  source="Ethan", evidence_ids=[evidence.id])
        self.assertEqual(len(mission.assets), 2)
        self.assertEqual([a.id for a in mission.assets], ["as1", "as2"])
        actions = [getattr(e, "action", None) for e in mission.events]
        self.assertIn("asset_added", actions)
        self.assertIn("asset_updated", actions)

    def test_empty_host_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _mission().add_asset("  ")

    def test_roundtrip_and_legacy_migration(self) -> None:
        from dataclasses import asdict
        mission = _mission()
        evidence = mission.add_evidence("Recon", "recon_report", "r", confidence=0.9)
        mission.add_asset("10.0.0.5", 22, "ssh", source="Ethan",
                          evidence_ids=[evidence.id], confidence=0.9)
        data = mission.to_dict()
        self.assertIn("assets", data)
        restored = MissionState(**{**{k: v for k, v in data.items()
                                      if k not in ("phase", "assets")},
                                    "phase": mission.phase,
                                    "assets": [AssetRecord(**a) for a in data["assets"]]})
        self.assertEqual(restored.assets[0].host, "10.0.0.5")
        # 旧 v8 文件无 assets 键 → 默认 []（load 侧由 defaults 合并覆盖）
        legacy = asdict(mission)
        legacy.pop("assets")
        self.assertNotIn("assets", legacy)


class ExtractAssetsTest(unittest.TestCase):
    def test_nmap_httpx_table_and_hostname(self) -> None:
        report = """Nmap scan report for l1-portal (10.8.20.31)
PORT     STATE SERVICE
80/tcp   open  http
8443/tcp open  https   OpenSSL
Nmap scan report for 10.8.20.35
22/tcp open ssh
http://10.8.20.40:8080 [200] [登录页] [tomcat]
| 10.8.20.41 | 3306 | mysql | 弱口令 |
sso.corp.internal:9000 发现管理端"""
        rows = extract_assets(report)
        keys = {(r["host"], r["port"]) for r in rows}
        self.assertIn(("10.8.20.31", 80), keys)
        self.assertIn(("10.8.20.31", 8443), keys)
        self.assertIn(("10.8.20.35", 22), keys)
        self.assertIn(("10.8.20.40", 8080), keys)
        self.assertIn(("10.8.20.41", 3306), keys)
        self.assertIn(("sso.corp.internal", 9000), keys)

    def test_empty_and_limit(self) -> None:
        self.assertEqual(extract_assets(""), [])
        self.assertEqual(extract_assets(None), [])
        big = "\n".join(f"host{i}.top:80" for i in range(200))
        self.assertEqual(len(extract_assets(big, limit=20)), 20)


class ScopeAutoExpandTest(unittest.TestCase):
    def _registry(self) -> ScopeRegistry:
        registry = ScopeRegistry()
        registry.add_base_target("192.168.1.1")
        return registry

    def test_in_authorized_cidr_auto_registers(self) -> None:
        registry = self._registry()
        registry.add_network("192.168.1.0/24", evidence="任务书", approved_by="test")
        mission = _mission(auto_scope_expand=False)   # 开关关，但网段内恒开
        # 网段内 IP 本就 is_ip_allowed=True —— 无需扩容，函数返回 False
        self.assertFalse(_auto_expand_scope_for_asset(
            mission, registry, "192.168.1.50"))
        self.assertTrue(registry.is_ip_allowed("192.168.1.50"))

    def test_out_of_scope_flag_off_not_expanded(self) -> None:
        registry = self._registry()
        mission = _mission(auto_scope_expand=False)
        self.assertFalse(_auto_expand_scope_for_asset(
            mission, registry, "192.168.5.20"))
        self.assertFalse(registry.is_ip_allowed("192.168.5.20"))

    def test_flag_on_private_expands_with_audit(self) -> None:
        registry = self._registry()
        mission = _mission(auto_scope_expand=True)
        self.assertTrue(_auto_expand_scope_for_asset(
            mission, registry, "192.168.5.20", evidence_note="e=e1"))
        self.assertTrue(registry.is_ip_allowed("192.168.5.20"))
        actions = [getattr(e, "action", None) for e in mission.events]
        self.assertIn("scope_auto_expanded", actions)

    def test_public_and_hostname_never_auto(self) -> None:
        registry = self._registry()
        mission = _mission(auto_scope_expand=True)
        self.assertFalse(_auto_expand_scope_for_asset(
            mission, registry, "45.33.32.156"))          # 公网
        self.assertFalse(_auto_expand_scope_for_asset(
            mission, registry, "internal.corp.lan"))     # 主机名
        self.assertFalse(_auto_expand_scope_for_asset(
            mission, registry, "127.0.0.1"))             # 回环

    def test_ctf_mode_never_auto(self) -> None:
        registry = self._registry()
        mission = _mission(auto_scope_expand=True, mission_mode="ctf")
        self.assertFalse(_auto_expand_scope_for_asset(
            mission, registry, "192.168.5.20"))


class IntelConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        import core.intel_config as ic

        self.ic = ic
        self.tmp = Path(tempfile.mkdtemp(prefix="intel-cfg-"))
        self.patch = mock.patch.object(ic, "CONFIG_PATH", self.tmp / "intel.json")
        self.patch.start()

    def tearDown(self) -> None:
        self.patch.stop()

    def test_set_brief_get_delete(self) -> None:
        ic = self.ic
        ic.set_intel_key(13, "fofa", key="fofa_key_abcd1234", email="a@b.com")
        brief = ic.intel_keys_brief(13)
        dumped = json.dumps(brief)
        self.assertNotIn("fofa_key_abcd1234", dumped)   # 明文永不回前端
        self.assertTrue(brief["platforms"]["fofa"]["configured"])
        self.assertEqual(ic.get_intel_keys(13, "fofa")["key"], "fofa_key_abcd1234")
        # 用户池未配 → 平台池回退（本测未配平台池 → 空）
        self.assertEqual(ic.get_intel_keys(99, "fofa"), {})
        ic.delete_intel_key(13, "fofa")
        self.assertFalse(ic.intel_keys_brief(13)["platforms"]["fofa"]["configured"])

    def test_platform_pool_fallback(self) -> None:
        ic = self.ic
        ic.set_intel_key(None, "shodan", key="shodan_key_9988")
        # 用户 7 未配 → 回退平台池
        self.assertEqual(ic.get_intel_keys(7, "shodan")["key"], "shodan_key_9988")
        brief = ic.intel_keys_brief(7)
        self.assertEqual(brief["platforms"]["shodan"]["source"], "platform")

    def test_invalid_platform(self) -> None:
        with self.assertRaises(ValueError):
            self.ic.set_intel_key(13, "bogus", key="x")


class IntelEngineNormalizeTest(unittest.TestCase):
    """四引擎响应归一化（mock transport）。"""

    def test_fofa(self) -> None:
        from Tools.AssetIntel import intel_search

        payload = {"error": 0, "results": [
            ["http://1.2.3.4:8080", "1.2.3.4", 8080, "登录页", "nginx", "http"]]}
        async def handler(request: httpx.Request) -> httpx.Response:  # noqa: ANN001
            return httpx.Response(200, json=payload)
        async def call() -> list[dict]:
            async with httpx.AsyncClient(
                    transport=httpx.MockTransport(handler)) as client:
                with mock.patch("Tools.AssetIntel.get_intel_keys",
                                return_value={"key": "k", "email": "e"}):
                    _, rows, _ = await intel_search(client, 13, "fofa", "t", 10)
            return rows
        rows = asyncio_run_helper(call())
        self.assertEqual(rows[0]["ip"], "1.2.3.4")
        self.assertEqual(rows[0]["port"], 8080)
        self.assertEqual(rows[0]["source"], "fofa")

    def test_hunter(self) -> None:
        from Tools.AssetIntel import intel_search

        payload = {"code": 0, "data": {"arrange": [
            {"ip": "5.6.7.8", "port": 443, "domain": "a.com",
             "web_title": "后台", "component": "Tomcat", "protocol": "https"}]}}
        async def handler(request: httpx.Request) -> httpx.Response:  # noqa: ANN001
            return httpx.Response(200, json=payload)
        async def call() -> list[dict]:
            async with httpx.AsyncClient(
                    transport=httpx.MockTransport(handler)) as client:
                with mock.patch("Tools.AssetIntel.get_intel_keys",
                                return_value={"key": "k"}):
                    _, rows, _ = await intel_search(client, 13, "hunter", "t", 10)
            return rows
        rows = asyncio_run_helper(call())
        self.assertEqual(rows[0]["host"], "a.com")
        self.assertEqual(rows[0]["component"], "Tomcat")


def asyncio_run_helper(coro):
    import asyncio
    return asyncio.run(coro)


class MlpsModeTest(unittest.TestCase):
    def test_completion_gate(self) -> None:
        mission = _mission()
        message = mlps_completion_gate(mission, success=True)
        self.assertIsNotNone(message)
        self.assertIn("测评单元判定", message)
        # 补足：10 条 verdict + 1 台资产
        evidence = mission.add_evidence("Attack", "attack_report", "r", confidence=0.8)
        for i in range(10):
            mission.add_fact(f"测评判定[单元{i}]: 符合", "Attack", [evidence.id],
                             category="verdict", confidence=0.85)
        mission.add_asset("10.0.0.5", 22, "ssh", source="Attack",
                          evidence_ids=[evidence.id])
        self.assertIsNone(mlps_completion_gate(mission, success=True))

    def test_failure_not_gated_non_mlps_not_gated(self) -> None:
        self.assertIsNone(mlps_completion_gate(_mission(), success=False))
        m = _mission(mission_mode="authorized_pentest")
        self.assertIsNone(mlps_completion_gate(m, success=True))

    def test_extract_verdicts(self) -> None:
        report = ("身份鉴别-a: 符合，口令策略已配置\n"
                  "**访问控制-b**: 部分符合 —— 存在共享账户\n"
                  "安全审计-c: 不符合，日志留存不足\n"
                  "这行没有判定词，不应命中。")
        rows = extract_verdicts(report)
        self.assertEqual([r["verdict"] for r in rows],
                         ["符合", "部分符合", "不符合"])
        self.assertTrue(all("测评判定[" in r["content"] for r in rows))

    def test_skill_mounted(self) -> None:
        from agent.Attack import _CYBERPENDA_SKILL_MAP, _ATTACK_CATALOG_CATEGORIES
        self.assertIn("mlps-assessment", _CYBERPENDA_SKILL_MAP["mlps"])
        self.assertIn("forensics", _ATTACK_CATALOG_CATEGORIES["mlps"])
        self.assertTrue(Path(
            "Skills/cyberpenda-bundles/mlps-assessment/SKILL.md").is_file())

    def test_report_template_exists(self) -> None:
        text = Path(
            "Skills/pentest-report-template/references/mlps-report-template.md"
        ).read_text(encoding="utf-8")
        for chapter in ("一、概述", "二、测试结论", "三、测试综述",
                        "四、测试结果", "五、安全等级与建议"):
            self.assertIn(chapter, text)

    def test_mission_mode_inference(self) -> None:
        from main import _mission_mode, _default_goal_for
        spec = _mission_mode.__globals__  # noqa: F841  (占位防误删)
        from Tools.target import normalize_target
        target_spec = normalize_target(tempfile.mkdtemp())
        self.assertEqual(_mission_mode(target_spec, "对系统开展等保三级测评，基线核查"),
                         "mlps")
        self.assertIn("等保", _default_goal_for("fast", "mlps"))


if __name__ == "__main__":
    unittest.main()
