"""Volatility 2 安全封装测试。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from Tools.Volatility import create_volatility_tools


class _Process:
    returncode = 0

    def poll(self):
        return self.returncode

    def terminate(self):
        return None

    def kill(self):
        return None

    def wait(self):
        return 0


class VolatilityToolTest(unittest.IsolatedAsyncioTestCase):
    async def test_analyze_uses_python2_without_shell_and_authorized_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "memory.raw"
            image.write_bytes(b"memory")
            tools = create_volatility_tools([root], timeout=30)
            analyze = next(tool for tool in tools if tool.name == "volatility_analyze")
            with patch("Tools.Volatility.subprocess.Popen", return_value=_Process()) as create_process:
                result = await analyze._func(
                    image_path="memory.raw",
                    plugin="pslist",
                    profile="Win7SP1x64",
                    plugin_options=["-p", "1234"],
                )
            self.assertTrue(result["ok"])
            command = create_process.call_args.args[0]
            self.assertIn("python2", Path(command[0]).name)
            self.assertIn(str(image), command)
            self.assertIn("pslist", command)
            self.assertIn("Win7SP1x64", command)

    async def test_path_escape_and_managed_options_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            image = Path(outside) / "secret.raw"
            image.write_bytes(b"memory")
            analyze = next(
                tool for tool in create_volatility_tools([root])
                if tool.name == "volatility_analyze"
            )
            escaped = await analyze._func(image_path=str(image), plugin="pslist")
            self.assertFalse(escaped["ok"])
            self.assertIn("授权工作区", escaped["error"])

            local = root / "memory.raw"
            local.write_bytes(b"memory")
            blocked = await analyze._func(
                image_path=str(local),
                plugin="pslist",
                plugin_options=["--plugins=/tmp/evil"],
            )
            self.assertFalse(blocked["ok"])
            self.assertIn("禁止传入", blocked["error"])

    async def test_interactive_plugin_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "memory.raw"
            image.write_bytes(b"memory")
            analyze = next(
                tool for tool in create_volatility_tools([tmp])
                if tool.name == "volatility_analyze"
            )
            result = await analyze._func(image_path=str(image), plugin="volshell")
            self.assertFalse(result["ok"])
            self.assertIn("交互式插件", result["error"])


if __name__ == "__main__":
    unittest.main()
