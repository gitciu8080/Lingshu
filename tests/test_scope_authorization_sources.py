"""范围授权来源分级回归测试（5e19dc2a 复盘）。

核心语义：用户在界面"网络授权目标"显式输入的地址 = 直接授权输入，
启动即注册进 ScopeRegistry，不弹范围审批；只有任务书文本里提取到、
用户没有亲手填过的目标才需要独立审批。

覆盖：
- _split_authorization_sources：用户输入目标从待审批集合中排除；
- ScopeRegistry.is_target_allowed：裸 IP / host:port / URL / 域名统一判定；
- 预授权注册后网络目标不再触发 scope 拦截的判定链路。
"""

from __future__ import annotations

import unittest

from main import _split_authorization_sources
from Tools.ScopeRegistry import ScopeRegistry


class SplitAuthorizationSourcesTest(unittest.TestCase):
    def test_user_entered_target_is_pre_authorized(self) -> None:
        # 5e19dc2a 场景：用户上传任务书并输入 10.8.128.122
        host, pending = _split_authorization_sources(
            ["10.8.128.122"], "10.8.128.122",
        )
        self.assertEqual(host, "10.8.128.122")
        self.assertEqual(pending, [])  # 无需审批 → 不弹窗

    def test_user_entered_target_with_port_matches_bare_host(self) -> None:
        # 用户输入带端口、任务书提取为带端口形式，主机部分一致即视为同一目标
        host, pending = _split_authorization_sources(
            ["10.8.128.122:22272"], "10.8.128.122:22272",
        )
        self.assertEqual(host, "10.8.128.122")
        self.assertEqual(pending, [])

    def test_taskbook_extra_targets_still_require_approval(self) -> None:
        host, pending = _split_authorization_sources(
            ["10.8.128.122", "10.8.128.200"], "10.8.128.122",
        )
        self.assertEqual(host, "10.8.128.122")
        self.assertEqual(pending, ["10.8.128.200"])

    def test_no_user_input_means_all_declared_pending(self) -> None:
        host, pending = _split_authorization_sources(
            ["10.8.128.122", "10.8.128.200"], None,
        )
        self.assertEqual(host, "")
        self.assertEqual(pending, ["10.8.128.122", "10.8.128.200"])

    def test_hostname_input_matched_against_taskbook_host(self) -> None:
        host, pending = _split_authorization_sources(
            ["node6.anna.nssctf.cn:22272"], "node6.anna.nssctf.cn",
        )
        self.assertEqual(host, "node6.anna.nssctf.cn")
        self.assertEqual(pending, [])


class ScopeRegistryTargetAllowedTest(unittest.TestCase):
    def test_ip_forms(self) -> None:
        registry = ScopeRegistry()
        registry.add_base_target("10.8.128.122")
        self.assertTrue(registry.is_target_allowed("10.8.128.122"))
        self.assertTrue(registry.is_target_allowed("10.8.128.122:22272"))
        self.assertTrue(registry.is_target_allowed("http://10.8.128.122:22272/"))
        self.assertFalse(registry.is_target_allowed("10.8.128.123"))
        self.assertFalse(registry.is_target_allowed(""))

    def test_hostname_forms(self) -> None:
        registry = ScopeRegistry()
        registry.add_base_target("node6.anna.nssctf.cn")
        self.assertTrue(registry.is_target_allowed("node6.anna.nssctf.cn"))
        self.assertTrue(registry.is_target_allowed("node6.anna.nssctf.cn:22272"))
        self.assertFalse(registry.is_target_allowed("node6.anna.nssf.cn"))

    def test_unregistered_host_not_allowed(self) -> None:
        registry = ScopeRegistry()
        self.assertFalse(registry.is_target_allowed("10.8.128.122"))

    def test_loopback_always_allowed(self) -> None:
        registry = ScopeRegistry()
        self.assertTrue(registry.is_target_allowed("127.0.0.1:8080"))

    def test_pre_authorization_unblocks_scope_gate_chain(self) -> None:
        # 复刻 dispatch_attack 的判定链：用户输入目标注册后，
        # declared 目标全部 is_target_allowed → scope_missing=False → 不拦截
        registry = ScopeRegistry()
        user_host, pending = _split_authorization_sources(
            ["10.8.128.122"], "10.8.128.122",
        )
        if user_host:
            registry.add_base_target(user_host)
        declared = ["10.8.128.122"]
        scope_missing = bool(declared) and not any(
            registry.is_target_allowed(item) for item in declared
        )
        self.assertFalse(scope_missing)
        self.assertEqual(pending, [])  # ensure_scope_approved 对其直接放行


if __name__ == "__main__":
    unittest.main()
