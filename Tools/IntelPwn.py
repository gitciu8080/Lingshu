"""IntelPwn 二进制静态分析工具适配。"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from Tools.tooling import AllowedFunctionTool


_INTELPWN_SCRIPT = Path(__file__).with_name("intelpwn") / "intelpwn.py"
_MAX_OUTPUT_CHARS = 20000


def create_intelpwn_tool(timeout: int) -> AllowedFunctionTool:
    """创建仅执行 IntelPwn 静态分析的工具。"""

    async def intelpwn_analyze(binary_path: str) -> str:
        """分析本地二进制文件的保护机制和潜在漏洞。

        固定使用 JSON 报告且禁用 exploit 生成；不支持远程利用和 fuzz。

        Args:
            binary_path: 待分析的本地二进制文件绝对路径。
        """
        binary = Path(binary_path).expanduser().resolve()
        if not binary.is_file():
            return f"[错误] 二进制文件不存在或不是普通文件: {binary}"
        if not _INTELPWN_SCRIPT.is_file():
            return f"[错误] IntelPwn 脚本不存在: {_INTELPWN_SCRIPT}"

        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            str(_INTELPWN_SCRIPT),
            "analyze",
            str(binary),
            "--json",
            "--no-exploit",
            cwd=str(_INTELPWN_SCRIPT.parent),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return f"[错误] IntelPwn 分析超过 {timeout} 秒，已终止"

        output = stdout.decode("utf-8", errors="replace").strip()
        error = stderr.decode("utf-8", errors="replace").strip()
        if proc.returncode != 0:
            return f"[错误] IntelPwn 分析失败 (退出码 {proc.returncode})\n{error[:2000]}"
        if not output:
            return f"[错误] IntelPwn 未返回分析结果\n{error[:2000]}"
        if len(output) > _MAX_OUTPUT_CHARS:
            output = f"{output[:_MAX_OUTPUT_CHARS]}\n... (输出已截断)"
        return output

    return AllowedFunctionTool(
        intelpwn_analyze,
        name="intelpwn_analyze",
        description="使用 IntelPwn 对本地二进制执行只读静态分析，返回 JSON 漏洞与保护机制报告。",
        is_read_only=True,
        is_concurrency_safe=False,
    )
