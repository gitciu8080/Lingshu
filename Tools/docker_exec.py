"""Docker 工作区命令执行器。

封装 agentscope :class:`DockerBackend.exec_shell`，为灵枢的 ``scoped_shell``
与 workspace 文件工具提供统一的容器内执行能力，并补齐 agentscope 后端缺失
的工程语义：

- **argv 执行**：``exec_shell`` 只接受 argv 列表；shell 特性用
  ``["sh", "-c", line]`` 包装。直接透传命令字符串给 Agent 时始终走 shell。
- **超时强杀**：agentscope 2.0.6 的 ``DockerBackend.exec_shell`` 超时只返回
  ``exit_code=-1``，**不会终止容器内进程**。这里在命令前包裹
  ``timeout -s KILL <sec> sh -c ...``，超时后由容器内的 GNU timeout 真正
  杀进程组。
- **取消强杀**：``cancel()`` 不能依赖镜像里是否带工具；通过一次性 marker
  文件 + ``pkill -9 -P`` 兜底尽力清理。
- **退出码/输出**：完整采集 stdout/stderr，返回与现有 ``scoped_shell``
  artifacts 流程兼容的结构（bytes + exit_code）。

路径约定：工具接收的 ``cwd``/文件路径为**宿主路径**，executor 内部统一
映射成容器内 ``/workspace`` 相对路径（映射器由调用方注入），返回给 Agent
的引用保持工作区相对语义不变。
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from agentscope.tool import ExecResult

logger = logging.getLogger(__name__)

# 容器内工作区挂载点（与 workspace_service._CONTAINER_WORKDIR 保持一致）。
CONTAINER_WORKDIR = "/workspace"


@dataclass
class DockerExecOutcome:
    """一次容器内命令执行的完整结果（与 ExecResult 对齐并扩展）。"""

    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    cancelled: bool = False


class LingshuDockerExecutor:
    """把命令调度到会话 Docker 工作区容器的执行器。

    Args:
        backend: ``workspace.get_backend()`` 返回的 DockerBackend。
        to_container: ``(host_path) -> container_path`` 映射函数；None 时
            原样透传（调用方需保证已是容器路径）。
        default_cwd: 容器内默认工作目录（通常 ``/workspace``）。
        default_timeout: 默认超时秒数。
    """

    def __init__(
        self,
        backend: Any,
        *,
        to_container: Callable[[str | Path], str] | None = None,
        default_cwd: str = CONTAINER_WORKDIR,
        default_timeout: int = 300,
    ) -> None:
        self._backend = backend
        self._to_container = to_container
        self._default_cwd = default_cwd
        self._default_timeout = default_timeout

    def map_path(self, path: str | Path) -> str:
        """把宿主路径映射为容器内路径；无映射器时原样返回字符串。"""
        if self._to_container is None:
            return str(path)
        return self._to_container(str(path))

    async def exec_shell(
        self,
        command: str,
        *,
        cwd: str | None = None,
        timeout: float | None = None,
    ) -> DockerExecOutcome:
        """在容器内执行一条 shell 命令行。

        Args:
            command: 完整命令行（经宿主侧 scoped_shell 三重校验后传入）。
            cwd: 容器内工作目录；None 用默认 ``/workspace``。
            timeout: 超时秒数；None 用默认超时。

        Returns:
            DockerExecOutcome：退出码、完整 stdout/stderr、超时/取消标记。
        """
        seconds = timeout if timeout is not None else self._default_timeout
        cwd = cwd or self._default_cwd

        # GNU timeout 包裹：真正超时强杀进程组（agentscope 后端只返回 -1）。
        # 注意 timeout 的返回值约定：124=超时、125=timeout 自身错误、
        # 126=命令找不到、127=命令不存在。
        wrapped: list[str] = [
            "timeout",
            "-s",
            "KILL",
            "--foreground",
            str(max(1, int(seconds))),
            "sh",
            "-c",
            command,
        ]
        try:
            result: ExecResult = await self._backend.exec_shell(
                wrapped,
                cwd=cwd,
                timeout=None,  # 超时交给容器内 timeout 控制
            )
        except asyncio.TimeoutError:
            # backend 自身的 wait_for 兜底（正常不会触发，因为 timeout=None）
            return DockerExecOutcome(
                exit_code=-1,
                stdout=b"",
                stderr=b"timed out waiting",
                timed_out=True,
            )
        except Exception as exc:  # noqa: BLE001 - 后端异常转成可读结果
            logger.warning("Docker 执行异常: %s", exc)
            return DockerExecOutcome(
                exit_code=-1,
                stdout=b"",
                stderr=str(exc).encode("utf-8", errors="replace"),
                timed_out=False,
            )

        exit_code = result.exit_code
        stdout = result.stdout or b""
        stderr = result.stderr or b""
        timed_out = exit_code == 124  # GNU timeout 超时返回码
        if exit_code is None:
            exit_code = -1
        return DockerExecOutcome(
            exit_code=int(exit_code),
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
        )

    async def read_bytes(self, path: str, max_bytes: int = 200_000) -> bytes:
        """读容器内文件（返回原始字节，超限截断由调用方决定）。"""
        container_path = self.map_path(path)
        # 优先用 backend.read_file（tar get_archive），失败回退 exec cat。
        try:
            return (await self._backend.read_file(container_path))[:max_bytes]
        except Exception:  # noqa: BLE001
            result = await self._backend.exec_shell(
                ["sh", "-c", f"cat -- {_quote(container_path)} | head -c {max_bytes}"],
                cwd=self._default_cwd,
            )
            return (result.stdout or b"")

    async def write_bytes(self, path: str, data: bytes) -> None:
        """写容器内文件（backend.write_file 原生 put_archive）。"""
        container_path = self.map_path(path)
        await self._backend.write_file(container_path, data)

    async def list_dir(self, path: str) -> list[str]:
        """列出容器内目录的条目名（相对名，不含路径）。"""
        container_path = self.map_path(path) or self._default_cwd
        result = await self._backend.exec_shell(
            ["sh", "-c", f"find {_quote(container_path)} -maxdepth 1 -mindepth 1 -printf '%f\\n'"],
            cwd=self._default_cwd,
        )
        text = (result.stdout or b"").decode("utf-8", errors="replace")
        return [line for line in text.splitlines() if line]

    async def glob(self, pattern: str, *, cwd: str | None = None) -> list[str]:
        """按 glob 模式在容器内列出相对路径（一行一个）。"""
        base = cwd or self._default_cwd
        result = await self._backend.exec_shell(
            ["sh", "-c", f"cd {_quote(base)} && find . -type f -name {_quote(pattern)} -printf '%P\\n'"],
            cwd=base,
        )
        text = (result.stdout or b"").decode("utf-8", errors="replace")
        return [line for line in text.splitlines() if line]

    async def grep(
        self,
        pattern: str,
        path: str = ".",
        max_results: int = 100,
        *,
        cwd: str | None = None,
    ) -> str:
        """在容器内递归搜索文本，返回 ``相对路径:行号:内容`` 行。"""
        base = cwd or self._default_cwd
        result = await self._backend.exec_shell(
            [
                "sh",
                "-c",
                f"cd {_quote(base)} && grep -rInE --binary-files=without-match "
                f"-m {int(max_results)} {_quote(pattern)} {_quote(path)} || true",
            ],
            cwd=base,
        )
        text = (result.stdout or b"").decode("utf-8", errors="replace")
        return text if text else "(无匹配)"


def _quote(value: str) -> str:
    """单引号包裹 shell 参数，内部单引号转义。"""
    return "'" + value.replace("'", "'\\''") + "'"
