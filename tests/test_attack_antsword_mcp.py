"""Attack 与 AntSword MCP 的接入契约测试。"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agent.Attack import (
    _ANTSWORD_MCP_URL,
    _ANTSWORD_READ_ONLY_TOOLS,
    _ANTSWORD_TOOLS,
    _connect_antsword_mcp,
    close_attack_agent,
    select_antsword_tools,
)


class AttackAntSwordMCPTest(unittest.IsolatedAsyncioTestCase):
    def test_complete_tool_contract(self) -> None:
        self.assertEqual(_ANTSWORD_MCP_URL, "http://127.0.0.1:30080/sse")
        self.assertEqual(len(_ANTSWORD_TOOLS), 37)
        self.assertEqual(len(set(_ANTSWORD_TOOLS)), 37)
        for required in (
            "shell_list", "shell_capabilities", "base_info", "cmd_exec",
            "file_dir", "db_query", "raw_request", "mcp_status",
        ):
            self.assertIn(required, _ANTSWORD_TOOLS)

    def test_webshell_signal_always_selects_complete_toolset(self) -> None:
        self.assertEqual(select_antsword_tools("发现 WebShell，先执行 shell_list"), _ANTSWORD_TOOLS)
        self.assertEqual(select_antsword_tools("未发现 WebShell"), ())

    async def test_connect_registers_all_tools_and_allows_existing_gate(self) -> None:
        tools = [
            SimpleNamespace(
                name=f"mcp__AntSword_Tool__{name}",
                is_read_only=False,
            )
            for name in _ANTSWORD_TOOLS
        ]
        client = SimpleNamespace(
            is_connected=False,
            connect=AsyncMock(),
            list_tools=AsyncMock(return_value=tools),
            close=AsyncMock(),
        )

        async def mark_connected() -> None:
            client.is_connected = True

        client.connect.side_effect = mark_connected
        approved = False
        with patch("agent.Attack.MCPClient", return_value=client) as factory:
            result_client, result_tools = await _connect_antsword_mcp(
                30,
                lambda: approved,
            )

        self.assertIs(result_client, client)
        self.assertEqual(result_tools, tools)
        by_name = {tool.name.rsplit("__", 1)[-1]: tool for tool in tools}
        self.assertTrue(by_name["shell_list"].is_read_only)
        self.assertFalse(by_name["cmd_exec"].is_read_only)
        read_decision = await by_name["shell_list"].check_permissions({}, None)
        denied = await by_name["cmd_exec"].check_permissions({}, None)
        self.assertEqual(read_decision.behavior.value, "allow")
        self.assertEqual(denied.behavior.value, "deny")
        approved = True
        allowed = await by_name["cmd_exec"].check_permissions({}, None)
        self.assertEqual(allowed.behavior.value, "allow")
        self.assertIn("shell_list", _ANTSWORD_READ_ONLY_TOOLS)
        kwargs = factory.call_args.kwargs
        self.assertEqual(kwargs["name"], "AntSword_Tool")
        self.assertEqual(kwargs["enable_tools"], list(_ANTSWORD_TOOLS))

    async def test_attack_cleanup_closes_only_its_mcp_session(self) -> None:
        client = SimpleNamespace(is_connected=True, close=AsyncMock())
        agent = SimpleNamespace(_antsword_mcp_client=client)
        await close_attack_agent(agent)
        client.close.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
