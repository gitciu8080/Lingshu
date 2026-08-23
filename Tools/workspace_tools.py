"""限定在 Workspace 根目录内的 Read / Glob / Grep 工具。

安全约束（对应计划第 1 节）：
- 所有路径先 ``Path.resolve()`` 后必须仍在工作区根目录内，绝对路径逃逸
  与符号链接逃逸都会被拒绝（symlink 指向外部时 resolve 后露出真实路径）。
- 不向 Agent 暴露无限制 Bash；scoped_shell 继续由 Tools/tooling.py 负责。
- 所有读写均在会话 Docker 容器内执行（路径自动映射到 /workspace）。
"""

from __future__ import annotations

import itertools
import re
import shlex
from pathlib import Path
from typing import Any

from agentscope.permission import PermissionBehavior, PermissionDecision

from Tools.tooling import AllowedFunctionTool


def _resolve_within(root: Path, candidate: str) -> Path:
    """把相对/绝对路径解析为工作区内绝对路径；逃逸则抛 PermissionError。"""
    if not candidate or "\x00" in candidate:
        raise ValueError("路径为空或包含非法字符")
    root_resolved = root.resolve()
    resolved = (root_resolved / candidate).resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        raise PermissionError(
            f"路径超出工作区范围: {candidate!r}（拒绝绝对路径/符号链接逃逸）"
        ) from None
    return resolved


def create_workspace_tools(
    root: str | Path,
    *,
    executor: "Any",
) -> list[AllowedFunctionTool]:
    """创建绑定到指定工作区根目录的受限文件工具。

    Args:
        root: 工作区根目录（宿主路径）。
        executor: LingshuDockerExecutor 实例。read/glob/grep 在 Docker
            容器内执行（路径自动映射到 /workspace）。
    """
    workdir = Path(root).resolve()

    async def workspace_read(path: str, max_bytes: int = 200_000) -> str:
        """读取工作区内文本文件。

        Args:
            path: 工作区相对路径（支持 input/xxx.zip 等子目录路径）。
            max_bytes: 最多读取的字节数（默认 200KB，超出截断并提示）。

        Returns:
            文件内容；超出 max_bytes 时返回截断内容与提示。
        """
        target = _resolve_within(workdir, path)
        container_path = executor.map_path(str(target))
        data = await executor.read_bytes(container_path, max_bytes=max_bytes + 1)
        if len(data) > max_bytes:
            return (
                data[:max_bytes].decode("utf-8", errors="replace")
                + f"\n...[已截断，完整文件 {len(data)} 字节，可通过 scoped_shell 读取]"
            )
        return data.decode("utf-8", errors="replace")

    async def workspace_glob(pattern: str, max_results: int = 200) -> str:
        """在工作区内按 glob 模式列出文件（相对路径，一行一个）。

        Args:
            pattern: glob 模式，如 "**/*.txt"、"input/*.zip"。
            max_results: 最多返回的条目数。

        Returns:
            匹配的相对路径列表；为空时返回 "(无匹配)"。
        """
        # 只允许相对模式：拒绝绝对路径与 .. 逃逸
        pattern_path = Path(pattern)
        if pattern_path.is_absolute() or ".." in pattern_path.parts:
            raise PermissionError("glob 模式必须是工作区内的相对路径")
        hits = await executor.glob(pattern)
        matches = hits[:max_results]
        if not matches:
            return "(无匹配)"
        return "\n".join(matches)

    async def workspace_grep(
        pattern: str,
        path: str = ".",
        max_results: int = 100,
    ) -> str:
        """在工作区内递归搜索文本（按行返回 相对路径:行号:内容）。

        Args:
            pattern: 正则表达式（RE2 语法）。
            path: 起始目录（默认工作区根，必须是工作区内相对路径）。
            max_results: 最多返回的匹配行数。

        Returns:
            匹配行列表；为空时返回 "(无匹配)"。
        """
        # 正则合法性先校验
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"非法正则: {exc}") from exc

        # 保持「工作区相对路径」输出语义：grep 在 /workspace 下执行，
        # path 直接用工作区相对路径（先做逃逸防护校验）。
        _resolve_within(workdir, path)
        return await executor.grep(
            pattern,
            path=path,
            max_results=max_results,
        )

    def _build(tool: Any) -> AllowedFunctionTool:
        return AllowedFunctionTool(
            tool,
            name=tool.__name__,
            description=tool.__doc__,
            is_concurrency_safe=True,
        )

    return [
        _build(workspace_read),
        _build(workspace_glob),
        _build(workspace_grep),
    ]

def create_gdb_tool(
    root: str | Path,
    *,
    executor: "Any",
    max_timeout: int = 600,
) -> list[AllowedFunctionTool]:
    """创建容器内 GDB 批量调试工具（替代原宿主侧 GDB MCP）。

    安全约束：
    - 待调试二进制必须位于工作区内（容器内 ``/workspace`` 下的真实路径，
      经 ``readlink -f`` 归一化后仍需在工作区前缀内，防 symlink 逃逸）；
    - 调试脚本由工具写入工作区 ``tmp/`` 后经 ``--command`` 加载，不经过
      shell 解析，无注入面；
    - gdb 与目标进程同权运行于一次性会话容器内，容器本身即隔离边界。
    """
    workdir = Path(root).resolve()
    container_root = executor.map_path(str(workdir)).rstrip("/")
    seq = itertools.count(1)

    async def gdb_debug(
        program: str,
        commands: str = "",
        run_args: list[str] | None = None,
        timeout: int = 300,
    ) -> str:
        """在容器内以 batch 模式运行一次 GDB 调试（无交互会话，每次独立执行）。

        Args:
            program: 待调试二进制的绝对路径（必须在 /workspace 下，即任务
                工作区内，如 /workspace/input/tmp/UniverseFinalAnswer）。
            commands: GDB 命令脚本（多行字符串），按顺序执行，如：
                "b *0x12a0\nrun < /workspace/input/payload.txt\ninfo registers\nx/s $rdi"
                支持断点(b)、运行(run，可带 shell 重定向)、单步(si/ni/finish)、
                查看(print/x/info registers/info frame)、反汇编(disassemble)、
                内存写入(set {int}0x404000=1)、核心转储(core-file xxx) 等。
            run_args: 传给目标程序的参数列表（等价 set args）。
            timeout: 超时秒数（默认 300，上限 600；超时进程被强杀并标记）。

        Returns:
            GDB 完整输出（stdout+stderr）。完整输出同时落盘到
            ``tmp/gdb-NNNN.out``，可用 workspace_read 查看。注意 batch 模式下
            退出码即被调试程序的退出码。
        """
        if not program or not program.startswith(container_root + "/"):
            raise PermissionError(
                f"program 必须是工作区内绝对路径（{container_root}/…）: {program!r}"
            )
        if "\x00" in (commands or ""):
            raise ValueError("commands 含非法字符")

        # 写入调试脚本到工作区 tmp/（宿主写入 → 容器可见），避免 shell 注入。
        script_host = workdir / "tmp" / f"gdb-{next(seq):04d}.gdb"
        script_host.parent.mkdir(parents=True, exist_ok=True)
        script_lines = ["set pagination off", "set confirm off"]
        if run_args:
            script_lines.append("set args " + shlex.join(run_args))
        if commands and commands.strip():
            script_lines.extend(commands.splitlines())
        await executor.write_bytes(
            str(script_host),
            ("\n".join(script_lines) + "\n").encode("utf-8"),
        )
        script_c = executor.map_path(str(script_host))

        # readlink -f 归一化后二次校验前缀，阻断 symlink 逃逸到工作区外。
        command = (
            f"prog=$(readlink -f -- {_quote(program)}) || exit 127; "
            f"case \"$prog\" in {_quote(container_root + '/')}*) ;; * ) "
            f"echo 'gdb_debug: 拒绝工作区外路径' >&2; exit 126;; esac; "
            f"exec gdb -q -batch -nx "
            f"--command={_quote(script_c)} --args \"$prog\""
        )
        outcome = await executor.exec_shell(command, timeout=min(max(1, int(timeout)), max_timeout))

        out = outcome.stdout or b""
        err = outcome.stderr or b""
        text = out.decode("utf-8", errors="replace")
        if err:
            text += "\n[stderr]\n" + err.decode("utf-8", errors="replace")
        if outcome.timed_out:
            text += f"\n[gdb_debug] 已超时被强杀（>{min(max(1,int(timeout)),max_timeout)}s），可缩小断点范围或提高 timeout 重试"
        header = f"[gdb_debug] exit_code={outcome.exit_code}\n"
        # 完整输出落盘到工作区，供 workspace_read 后续查看。
        out_host = script_host.with_suffix(".out")
        try:
            await executor.write_bytes(str(out_host), text.encode("utf-8"))
        except Exception:
            pass
        return header + text

    return [
        AllowedFunctionTool(
            gdb_debug,
            name="gdb_debug",
            description=gdb_debug.__doc__,
            is_read_only=False,
            is_concurrency_safe=False,
        ),
    ]


def _quote(value: str) -> str:
    """单引号包裹 shell 参数，内部单引号转义。"""
    return "'" + value.replace("'", "'\\''") + "'"


