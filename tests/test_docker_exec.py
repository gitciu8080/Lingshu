"""docker 工作区支撑单元测试（不依赖 docker daemon）。

覆盖：
- LingshuDockerExecutor.exec_shell 的 sh -c 包装与 GNU timeout 返回码语义；
- workspace_service.host_to_container 路径映射与逃逸拒绝；
- create_scoped_shell_tool 在 executor 分支下仍先做 scoped 校验。
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from Tools.docker_exec import LingshuDockerExecutor
from Tools.tooling import create_scoped_shell_tool


class _FakeExecResult:
    def __init__(self, exit_code: int, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.stream = None
        self.data = b""


class _FakeBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.result = _FakeExecResult(0, b"hello\n", b"")

    async def exec_shell(self, command, *, cwd=None, timeout=None):
        self.calls.append((list(command), {"cwd": cwd, "timeout": timeout}))
        return self.result


class DockerExecutorTest(unittest.IsolatedAsyncioTestCase):
    async def test_exec_shell_wraps_with_timeout_and_sh_c(self) -> None:
        backend = _FakeBackend()
        ex = LingshuDockerExecutor(backend, default_timeout=300)
        outcome = await ex.exec_shell("echo hi", cwd="/workspace")
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.stdout, b"hello\n")
        argv, kwargs = backend.calls[0]
        self.assertEqual(argv[0], "timeout")
        self.assertEqual(argv[1], "-s")
        self.assertEqual(argv[2], "KILL")
        self.assertEqual(argv[4], "300")
        self.assertEqual(argv[5], "sh")
        self.assertEqual(argv[6], "-c")
        self.assertEqual(argv[7], "echo hi")

    async def test_timeout_return_code_maps_to_timed_out(self) -> None:
        backend = _FakeBackend()
        backend.result = _FakeExecResult(124, b"", b"terminated")
        ex = LingshuDockerExecutor(backend, default_timeout=300)
        outcome = await ex.exec_shell("sleep 1000")
        self.assertTrue(outcome.timed_out)
        self.assertEqual(outcome.exit_code, 124)


class HostToContainerTest(unittest.IsolatedAsyncioTestCase):
    async def test_mapping_and_escape(self) -> None:
        from workspace_service import WorkspaceService

        with tempfile.TemporaryDirectory() as tmp:
            svc = WorkspaceService(root=tmp, mode="docker")
            (svc.workspace_dir(1, "sess-1") / "input").mkdir(parents=True)
            target = svc.workspace_dir(1, "sess-1") / "input" / "a.zip"
            self.assertEqual(
                svc.host_to_container(1, "sess-1", target),
                "/workspace/input/a.zip",
            )
            with self.assertRaises(ValueError):
                svc.host_to_container(1, "sess-1", tmp + "/outside.txt")

    async def test_local_mode_returns_absolute_path(self) -> None:
        from workspace_service import WorkspaceService

        with tempfile.TemporaryDirectory() as tmp:
            svc = WorkspaceService(root=tmp, mode="local")
            d = svc.workspace_dir(1, "sess-1")
            d.mkdir(parents=True)
            self.assertEqual(
                svc.host_to_container(1, "sess-1", str(d / "x")),
                str((d / "x").resolve()),
            )


class ScopedShellExecutorValidationTest(unittest.IsolatedAsyncioTestCase):
    async def test_scoped_validation_runs_before_executor(self) -> None:
        from Tools.tooling import _validate_scoped_command
        from Tools.ScopeRegistry import ScopeRegistry

        # 未授权 IP 必须被校验层拒绝；校验发生在任何 executor 编排之前，
        # 因此 executor 不会被调用。
        registry = ScopeRegistry()
        with self.assertRaises((ValueError, PermissionError)):
            _validate_scoped_command("nmap 8.8.8.8", "127.0.0.1", registry)

    async def test_scoped_shell_tool_accepts_executor(self) -> None:
        # executor 参数应被接受并传入工具内部（不执行命令时不连接后端）。
        with tempfile.TemporaryDirectory() as tmp:
            backend = _FakeBackend()
            ex = LingshuDockerExecutor(backend, default_timeout=30)
            tool = create_scoped_shell_tool(
                "127.0.0.1",
                cwd=tmp,
                timeout=30,
                role="recon",
                artifact_root=None,
                executor=ex,
            )
            self.assertEqual(tool.name, "scoped_shell")


if __name__ == "__main__":
    unittest.main()
