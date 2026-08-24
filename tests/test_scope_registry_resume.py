"""恢复会话后原始目标仍保留在 scoped_shell 授权范围的回归测试。"""

from __future__ import annotations

import unittest

from Tools.ScopeRegistry import ScopeRegistry
from Tools.tooling import _validate_scoped_command


class ScopeRegistryResumeTest(unittest.TestCase):
    def test_original_target_is_allowed_even_without_legacy_snapshot(self) -> None:
        _validate_scoped_command(
            "nmap -Pn 10.8.128.122", "10.8.128.122", ScopeRegistry(),
        )

    def test_original_target_is_allowed_after_restore(self) -> None:
        registry = ScopeRegistry()
        registry.add_base_target("10.8.128.122")
        _validate_scoped_command("nmap -Pn 10.8.128.122", "10.8.128.122", registry)

    def test_foreign_target_remains_blocked(self) -> None:
        registry = ScopeRegistry()
        registry.add_base_target("10.8.128.122")
        with self.assertRaises(PermissionError):
            _validate_scoped_command("nmap -Pn 10.8.128.123", "10.8.128.122", registry)


if __name__ == "__main__":
    unittest.main()
