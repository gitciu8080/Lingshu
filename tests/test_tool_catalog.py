"""动态工具目录：实机发现、角色隔离和 Agent 查询工具。"""
from __future__ import annotations

import json
import importlib.metadata
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Tools.tool_catalog import ToolCatalog, create_tool_catalog_tools, python_environment_snapshot


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
            {
                "id": "health-check-missing", "category": "runtime",
                "command_candidates": ["sh"], "version_args": [],
                "health_check_args": ["-c", "printf available"],
                "health_check_contains": ["missing-component"],
                "roles": [], "risk": "local_analysis", "approval_required": False,
                "description": "运行组件检查", "usage_hint": "仅状态检查", "alternatives": [],
            },
            {
                "id": "required-resource-missing", "category": "runtime",
                "required_files": ["missing-resource-for-tool-catalog-test"],
                "roles": [], "risk": "local_analysis", "approval_required": False,
                "description": "项目资源检查", "usage_hint": "仅用于测试", "alternatives": [],
            },
            {
                "id": "required-command-missing", "category": "runtime",
                "command_candidates": ["sh"],
                "required_commands": ["lingshu-command-that-does-not-exist"],
                "roles": [], "risk": "local_analysis", "approval_required": False,
                "description": "组合命令检查", "usage_hint": "仅用于测试", "alternatives": [],
            },
            {
                "id": "configured-runtime", "category": "runtime",
                "command_candidates": ["sh"], "version_args": [],
                "health_check_args": ["-c", "printf \"$LINGSHU_TEST_RUNTIME\""],
                "health_check_contains": ["ready"],
                "environment": {"LINGSHU_TEST_RUNTIME": "ready"},
                "roles": [], "risk": "local_analysis", "approval_required": False,
                "description": "隔离环境检查", "usage_hint": "仅用于测试", "alternatives": [],
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

    def test_python_environment_snapshot_reports_lock_coverage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lingshu-requirements-") as root:
            requirements = Path(root) / "requirements.txt"
            requirements.write_text(
                "packaging==" + importlib.metadata.version("packaging") + "\n"
                "lingshu-package-that-does-not-exist==1.0\n",
                encoding="utf-8",
            )
            snapshot = python_environment_snapshot(requirements)
        states = {item["name"].lower(): item["status"] for item in snapshot["packages"]}
        self.assertEqual(states["packaging"], "matched")
        self.assertEqual(states["lingshu-package-that-does-not-exist"], "missing")

    def test_health_check_can_mark_existing_command_missing(self) -> None:
        item = next(item for item in _catalog().snapshot() if item["id"] == "health-check-missing")
        self.assertEqual(item["status"], "missing")
        self.assertIn("缺少运行时组件", item["error"])

    def test_required_project_resource_is_checked(self) -> None:
        item = next(item for item in _catalog().snapshot() if item["id"] == "required-resource-missing")
        self.assertEqual(item["status"], "missing")
        self.assertIn("缺少必需资源", item["error"])

    def test_required_command_is_checked(self) -> None:
        item = next(item for item in _catalog().snapshot() if item["id"] == "required-command-missing")
        self.assertEqual(item["status"], "missing")
        self.assertIn("缺少必需命令", item["error"])

    def test_catalog_applies_declared_runtime_environment(self) -> None:
        item = next(item for item in _catalog().snapshot() if item["id"] == "configured-runtime")
        self.assertEqual(item["status"], "available")

    def test_catalog_resolves_command_from_environment_path(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-catalog-env-"))
        manifest = root / "tools.json"
        manifest.write_text(json.dumps({
            "schema_version": 1,
            "tools": [{
                "id": "configured-wine", "category": "reverse",
                "command_candidates": ["${LINGSHU_TEST_WINE_CMD}"],
                "version_args": ["--version"], "roles": ["reserve", "attack"],
                "risk": "local_execution", "approval_required": True,
                "description": "测试 Wine", "usage_hint": "仅测试", "alternatives": [],
            }],
        }), encoding="utf-8")
        with patch.dict(os.environ, {"LINGSHU_TEST_WINE_CMD": "/bin/sh"}):
            item = ToolCatalog(manifest, cache_ttl=3600).snapshot()[0]
        self.assertEqual(item["status"], "available")
        self.assertEqual(item["path"], str(Path("/bin/sh").resolve()))

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
