"""GDB MCP 静态接入契约测试（不启动外部进程）。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from agent.Reserve import (
    _GDB_MCP_SOURCE,
    _GDB_RESTRICTED_ENTRY_TOOLS,
    _resolve_gdb_mcp_command,
)


class GDBMCPConfigTest(unittest.TestCase):
    def test_project_mcp_config_is_pinned_and_safe(self) -> None:
        root = Path(__file__).resolve().parents[1]
        config = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))
        server = config["mcpServers"]["gdb-multi-mcp"]

        self.assertEqual(server["command"], "uvx")
        self.assertIn("--offline", server["args"])
        self.assertIn(_GDB_MCP_SOURCE, server["args"])
        self.assertNotIn("--unsafe", server["args"])
        self.assertEqual(
            config["mcpServers"]["antsword"]["url"],
            "http://127.0.0.1:30080/sse",
        )

    def test_scope_bypassing_session_entries_are_not_exposed_directly(self) -> None:
        self.assertTrue({
            "create_session",
            "attach",
            "load_core",
            "connect_target",
            "rr_record",
            "start_replay_session",
        }.issubset(_GDB_RESTRICTED_ENTRY_TOOLS))

    def test_uvx_launcher_exists(self) -> None:
        self.assertTrue(Path(_resolve_gdb_mcp_command()).is_file())


if __name__ == "__main__":
    unittest.main()
