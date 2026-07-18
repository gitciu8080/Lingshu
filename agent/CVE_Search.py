"""CVE 情报查询工具 — AgentScope 2.0 标准。

提供 cve_search 核心函数和 create_cve_search_tool 工厂函数。
所有网络边界校验在函数内部完成，通过 AllowedFunctionTool 注册到 Agent。
"""
from __future__ import annotations

import asyncio
import os
import re
import sys

from agent.tooling import AllowedFunctionTool


_CVE_SEARCH_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "Skills",
    "cve-search",
    "scripts",
    "cve_search.py",
)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_MAX_OUTPUT_CHARS = 5000
_QUERY_TIMEOUT = 90


async def cve_search(cve_id: str) -> str:
    """查询指定 CVE 编号的公开安全情报。

    从 MITRE 等公开源获取漏洞描述、严重程度、CVSS 评分和已知利用信息。

    Args:
        cve_id: 标准 CVE 编号，例如 CVE-2021-41773。格式严格为 CVE-YYYY-NNNNN。

    Returns:
        CVE 情报文本（最大 5000 字符），或在错误时返回以 [错误] 开头的诊断信息。
    """
    normalized = cve_id.strip().upper()
    if not _CVE_RE.fullmatch(normalized):
        return f"[错误] 无效的 CVE 编号格式: {normalized}"
    if not os.path.isfile(_CVE_SEARCH_SCRIPT):
        return f"[错误] CVE 查询脚本不存在: {_CVE_SEARCH_SCRIPT}"

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        _CVE_SEARCH_SCRIPT,
        "-c",
        normalized,
        "-s",
        "mitre",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_QUERY_TIMEOUT,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return f"[错误] CVE 查询超过 {_QUERY_TIMEOUT} 秒，已终止"

    output = stdout.decode("utf-8", errors="replace").strip()
    error = stderr.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 and not output:
        return f"[错误] CVE 查询失败 (退出码 {proc.returncode})\n{error[:500]}"
    truncated = output[:_MAX_OUTPUT_CHARS]
    if len(output) > _MAX_OUTPUT_CHARS:
        truncated += "\n... (输出已截断)"
    return truncated


def create_cve_search_tool() -> AllowedFunctionTool:
    """创建 CVE 情报查询工具（AgentScope 2.0 标准）。

    返回一个 AllowedFunctionTool 实例，可直接加入 Agent 的 Toolkit。
    工具为只读、并发安全，所有校验在函数内部完成。

    Returns:
        配置好的 AllowedFunctionTool，名称为 cve_search。
    """
    return AllowedFunctionTool(
        cve_search,
        name="cve_search",
        description="查询指定 CVE 编号的公开安全情报，返回漏洞描述、严重程度和已知利用信息。",
        is_read_only=True,
        is_concurrency_safe=True,
    )
