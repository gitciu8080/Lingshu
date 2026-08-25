"""动态工具目录：实机发现、角色隔离和 Agent 查询工具。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from Tools.tool_catalog import ToolCatalog, create_tool_catalog_tools


def _text(result) -> str:
    blocks = getattr(result, "content", None)
    if isinstance(blocks, list):
        return "\n".join(block.text for block in blocks if hasattr(block, "text"))
    return str(result)


def _catalog() -> ToolCatalog:
    root = Path(tempfile.mkdtemp(prefix="lingshu-catalog-"))
    manifest = root / "tools.json"
    manifest.write_text(json.dumps({
        "schema_version": 1,
        "tools": [
            {
                "id": "shell-ok", "category": "local",
                "command_candidates": ["sh"], "version_args": ["--version"],
                "roles": ["recon"], "risk": "local_analysis",
                "approval_required": False, "description": "测试命令",
                "usage_hint": "仅用于测试", "alternatives": [],
            },
            {
                "id": "definitely-missing", "category": "local",
                "command_candidates": ["lingshu-command-that-does-not-exist"],
                "version_args": ["--version"], "roles": ["recon", "attack"],
                "risk": "local_analysis", "approval_required": False,
                "description": "缺失命令", "usage_hint": "不可调用", "alternatives": [],
            },
            {
                "id": "python-ok", "category": "runtime",
                "python_modules": [{"module": "json", "distribution": "json"}],
                "roles": [], "risk": "local_analysis", "approval_required": False,
                "description": "Python 运行时依赖", "usage_hint": "仅状态检查", "alternatives": [],
            },
        ],
    }), encoding="utf-8")
    return ToolCatalog(manifest, cache_ttl=3600)


class ToolCatalogTest(unittest.IsolatedAsyncioTestCase):
    def test_role_only_gets_installed_assigned_tools(self) -> None:
        catalog = _catalog()
        self.assertEqual([item["id"] for item in catalog.for_role("recon")], ["shell-ok"])
        self.assertEqual(catalog.for_role("attack"), [])
        missing = catalog.get("definitely-missing", "recon")
        self.assertIsNotNone(missing)
        self.assertEqual(missing["status"], "missing")

    def test_summary_is_generated_from_health_snapshot(self) -> None:
        summary = _catalog().capability_summary("recon")
        self.assertIn("shell-ok", summary)
        self.assertNotIn("definitely-missing", summary)

    def test_python_module_is_checked_without_shell_command(self) -> None:
        item = next(item for item in _catalog().snapshot(include_version=True) if item["id"] == "python-ok")
        self.assertEqual(item["status"], "available")
        self.assertEqual(item["kind"], "python_module")
        self.assertIn("Python", item["command"])

    async def test_agent_query_hides_unavailable_tools(self) -> None:
        tools = {tool.name: tool for tool in create_tool_catalog_tools("recon", _catalog())}
        listed = _text(await tools["list_available_tools"]())
        self.assertIn("shell-ok", listed)
        self.assertNotIn("definitely-missing", listed)
        unavailable = _text(await tools["get_tool_usage"](tool_id="definitely-missing"))
        self.assertIn("当前不可用", unavailable)

    async def test_agent_cannot_query_other_role_tool(self) -> None:
        tools = {tool.name: tool for tool in create_tool_catalog_tools("attack", _catalog())}
        result = _text(await tools["get_tool_usage"](tool_id="shell-ok"))
        self.assertIn("未分配", result)


if __name__ == "__main__":
    unittest.main()
