"""SageMath systemd/Conda 环境解析与执行测试。"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Tools.SageMath import _resolve_sage_command, execute_sagemath


class SageMathToolTest(unittest.TestCase):
    def test_explicit_sage_command_does_not_require_conda(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "sage"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            with patch.dict(os.environ, {"LINGSHU_SAGE_CMD": str(executable)}, clear=False):
                command, source = _resolve_sage_command()
            self.assertEqual(command, [str(executable.resolve())])
            self.assertTrue(source.startswith("direct:"))

    def test_execution_sets_isolated_dot_sage_and_uses_direct_command(self) -> None:
        captured: dict = {}

        def fake_run(command, **kwargs):
            captured["command"] = command
            captured["env"] = kwargs["env"]
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "// ** Could not find dynamic library: p_Procs_FieldIndep.so\n"
                    "// ** Singular will work properly, but much slower.\n"
                    "// ** See the INSTALL section in the Singular manual for details.\n"
                    "256\n"
                ),
                stderr="",
            )

        with patch("Tools.SageMath._resolve_sage_command", return_value=(["/opt/sage"], "direct:/opt/sage")):
            with patch("Tools.SageMath.subprocess.run", side_effect=fake_run):
                result = execute_sagemath("print(2^8)")
        self.assertEqual(result, "256")
        self.assertEqual(captured["command"][0], "/opt/sage")
        self.assertIn("DOT_SAGE", captured["env"])
        self.assertIn("lingshu-sage-", captured["env"]["DOT_SAGE"])

    def test_missing_config_reports_sage_instead_of_conda_only(self) -> None:
        with patch(
            "Tools.SageMath._resolve_sage_command",
            side_effect=FileNotFoundError("找不到 SageMath 可执行文件"),
        ):
            result = execute_sagemath("print(1)")
        self.assertIn("SageMath Config Error", result)
        self.assertIn("找不到 SageMath 可执行文件", result)

    def test_dangerous_code_is_blocked_before_execution(self) -> None:
        self.assertIn("BLOCKED", execute_sagemath("import os; os.system('id')"))

    @unittest.skipUnless(
        Path("/home/kali/miniconda3/envs/sage/bin/sage").is_file(),
        "部署环境未安装 SageMath",
    )
    def test_deployed_sage_smoke(self) -> None:
        self.assertEqual(execute_sagemath("print(2^8)", timeout=30), "256")


if __name__ == "__main__":
    unittest.main()
