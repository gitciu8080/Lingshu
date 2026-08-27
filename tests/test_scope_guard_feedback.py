"""P0-A 范围护栏反馈链路回归测试（e593054a 复盘）。

覆盖：
- 网络拒绝报错回显授权目标原文与复制指令；
- 近似拼写主机名检测（裸域名 + URL 形式），正确目标不误报；
- 同因连败熔断：连续 3 次同原因被拒后错误文本追加升级提示，成功执行后重置。
"""

from __future__ import annotations

import tempfile
import unittest

from Tools.tooling import (
    ScopedRejectionBreaker,
    _find_near_miss_host,
    _validate_scoped_command,
    create_scoped_shell_tool,
)

TARGET = "node6.anna.nssctf.cn:22272"
TYPO_HOST = "node6.anna.nssf.cn"


class ScopeGuardMessageTest(unittest.TestCase):
    def test_rejection_echoes_authorized_target(self) -> None:
        with self.assertRaises(PermissionError) as ctx:
            _validate_scoped_command(
                f"nmap -Pn -p 22272 {TYPO_HOST}", TARGET, None,
            )
        message = str(ctx.exception)
        self.assertIn("node6.anna.nssctf.cn:22272", message)
        self.assertIn("原样复制", message)

    def test_near_miss_hint_for_typoed_hostname(self) -> None:
        hint = _find_near_miss_host(f"nmap -Pn {TYPO_HOST}", [TARGET])
        self.assertEqual(hint, TYPO_HOST)
        with self.assertRaises(PermissionError) as ctx:
            _validate_scoped_command(
                f"nmap -Pn -p 22272 {TYPO_HOST}", TARGET, None,
            )
        self.assertIn("拼写错误", str(ctx.exception))
        self.assertIn(TYPO_HOST, str(ctx.exception))

    def test_near_miss_hint_inside_url_form(self) -> None:
        command = f"curl -v --connect-timeout 10 http://{TYPO_HOST}:22272/"
        hint = _find_near_miss_host(command, [TARGET])
        self.assertEqual(hint, TYPO_HOST)

    def test_correct_bare_host_is_not_flagged_as_typo(self) -> None:
        # 授权目标是 host:port；命令中出现正确的裸主机名不算拼写错误
        hint = _find_near_miss_host("nmap -Pn node6.anna.nssctf.cn", [TARGET])
        self.assertEqual(hint, "")
        try:
            _validate_scoped_command(
                "curl http://node6.anna.nssctf.cn/", TARGET, None,
            )
        except PermissionError as exc:  # 拒绝可以发生（旧行为），但不得误报
            self.assertNotIn("拼写错误", str(exc))

    def test_unrelated_host_gets_no_hint(self) -> None:
        hint = _find_near_miss_host("curl http://example.com", ["10.0.0.5:8080"])
        self.assertEqual(hint, "")

    def test_breaker_message_embedded_in_permission_error(self) -> None:
        breaker = ScopedRejectionBreaker(threshold=3)
        reason = "网络命令必须显式包含本次授权目标。授权目标原文：「x」。"
        self.assertEqual(breaker.record(reason), "")
        self.assertEqual(breaker.record(reason), "")
        third = breaker.record(reason)
        self.assertIn("[范围护栏熔断]", third)
        self.assertIn("连续出现 3 次", third)
        other = breaker.record("命令为空、过长或包含非法字符")
        self.assertNotIn("[范围护栏熔断]", other)


class ScopeGuardBreakerIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def test_consecutive_rejections_escalate_then_reset_on_success(self) -> None:
        tool = create_scoped_shell_tool(
            TARGET, cwd=tempfile.mkdtemp(prefix="lingshu-breaker-"), timeout=10, role="test",
        )
        messages: list[str] = []
        for index in range(3):
            with self.assertRaises(PermissionError) as ctx:
                await tool(command=f"nmap -Pn {TYPO_HOST} -p 22 --open | head -{index}")
            messages.append(str(ctx.exception))
        self.assertNotIn("[范围护栏熔断]", messages[0])
        self.assertNotIn("[范围护栏熔断]", messages[1])
        self.assertIn("[范围护栏熔断]", messages[2])

        # 本地命令成功执行 → 计数重置
        await tool(command="echo noop-ok")
        with self.assertRaises(PermissionError) as ctx:
            await tool(command=f"nmap -Pn {TYPO_HOST}")
        self.assertNotIn("[范围护栏熔断]", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
