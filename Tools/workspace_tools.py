"""限定在 Workspace 根目录内的 Read / Glob / Grep 工具。

安全约束（对应计划第 1 节）：
- 所有路径先 ``Path.resolve()`` 后必须仍在工作区根目录内，绝对路径逃逸
  与符号链接逃逸都会被拒绝（symlink 指向外部时 resolve 后露出真实路径）。
- 不向 Agent 暴露无限制 Bash；scoped_shell 继续由 Tools/tooling.py 负责。
"""

from __future__ import annotations

import re
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


def _rel(root: Path, path: Path) -> str:
    """返回工作区相对路径（不含根），用于给 Agent 的引用。"""
    return str(path.resolve().relative_to(root.resolve()))


def create_workspace_tools(root: str | Path) -> list[AllowedFunctionTool]:
    """创建绑定到指定工作区根目录的受限文件工具。"""
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
        if not target.is_file():
            raise FileNotFoundError(f"文件不存在: {path}")
        data = target.read_bytes()
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
        matches: list[str] = []
        # 只允许相对模式：拒绝绝对路径与 .. 逃逸
        pattern_path = Path(pattern)
        if pattern_path.is_absolute() or ".." in pattern_path.parts:
            raise PermissionError("glob 模式必须是工作区内的相对路径")
        for hit in workdir.glob(pattern):
            if hit.is_file():
                matches.append(_rel(workdir, hit))
            if len(matches) >= max_results:
                break
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
        start = _resolve_within(workdir, path)
        if not start.is_dir():
            raise NotADirectoryError(f"路径不是目录: {path}")
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"非法正则: {exc}") from exc

        results: list[str] = []
        for hit in start.rglob("*"):
            if not hit.is_file():
                continue
            try:
                # 只读文本探测：二进制文件跳过（含 NUL 字节）
                data = hit.read_bytes()[:1024 * 1024]
                if b"\x00" in data:
                    continue
                text = data.decode("utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    results.append(f"{_rel(workdir, hit)}:{lineno}:{line[:200]}")
                    if len(results) >= max_results:
                        return "\n".join(results) + "\n...(结果已截断)"
        if not results:
            return "(无匹配)"
        return "\n".join(results)

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
