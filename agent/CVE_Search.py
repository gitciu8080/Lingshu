"""CVE 情报查询工具。"""
import asyncio
import os
import re
import sys


_CVE_SEARCH_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "Skills",
    "cve-search",
    "scripts",
    "cve_search.py",
)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


async def cve_search(cve_id: str) -> str:
    """查询指定 CVE 的公开情报。

    Args:
        cve_id: 标准 CVE 编号，例如 CVE-2021-41773。
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
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=90)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return "[错误] CVE 查询超过 90 秒，已终止"

    output = stdout.decode("utf-8", errors="replace").strip()
    error = stderr.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 and not output:
        return f"[错误] CVE 查询失败 (退出码 {proc.returncode})\n{error[:500]}"
    return output[:5000] + ("\n... (输出已截断)" if len(output) > 5000 else "")
