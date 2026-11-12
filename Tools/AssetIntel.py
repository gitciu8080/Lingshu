"""资产测绘引擎统一客户端（FOFA / Hunter / Shodan / ZoomEye）。

四个引擎适配为同一归一化输出 ``[{ip, port, host, title, component,
protocol, source}]``；给 LLM 的返回为紧凑表格文本（≤200 行），完整 JSON
由调用方落盘 artifacts。查询是只读 HTTP——测绘结果仅作情报，测试目标
必须走 request_scope_expansion 审批（工具描述内嵌该红线）。
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from core.intel_config import INTEL_PLATFORMS, get_intel_keys
from Tools.tooling import AllowedFunctionTool

_WORKDIR = Path(__file__).resolve().parent / "WorkDir" / "asset-intel"


class IntelError(RuntimeError):
    """测绘引擎错误（HTTP/配额/未配置）。"""

    def __init__(self, message: str, *, platform: str = "", quota: bool = False):
        self.platform = platform
        self.quota = quota
        super().__init__(message)


def _norm_ip(value: Any) -> str:
    return str(value or "").strip()


def _norm_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


async def _search_fofa(
    client: httpx.AsyncClient, creds: dict[str, Any], query: str, size: int,
) -> list[dict[str, Any]]:
    email, key = creds.get("email"), creds.get("key")
    if not (email and key):
        raise IntelError("FOFA 未配置 email/key", platform="fofa", quota=False)
    qbase64 = base64.b64encode(query.encode("utf-8")).decode("utf-8")
    response = await client.get(
        "https://fofa.info/api/v1/search/all",
        params={"email": email, "key": key, "qbase64": qbase64, "size": size,
                "fields": "host,ip,port,title,server,protocol"},
        timeout=45)
    body = response.json()
    if body.get("error"):
        detail = body["error"]
        detail_text = "key 无效或配额不足" if detail is True else str(detail)[:120]
        raise IntelError(f"FOFA 查询被拒绝：{detail_text}", platform="fofa",
                         quota="vip" in str(detail).lower()
                         or "quota" in str(detail).lower())
    rows = body.get("results") or []
    out = []
    for row in rows:
        host, ip, port, title, server, protocol = (list(row) + [""] * 6)[:6]
        out.append({
            "ip": _norm_ip(ip), "port": _norm_port(port),
            "host": _norm_ip(host), "title": _norm_ip(title),
            "component": _norm_ip(server), "protocol": _norm_ip(protocol),
            "source": "fofa",
        })
    return out


async def _search_hunter(
    client: httpx.AsyncClient, creds: dict[str, Any], query: str, size: int,
) -> list[dict[str, Any]]:
    key = creds.get("key")
    if not key:
        raise IntelError("Hunter 未配置 api-key", platform="hunter")
    qbase64 = base64.b64encode(query.encode("utf-8")).decode("utf-8")
    response = await client.get(
        "https://hunter.qianxin.com/openapi/search",
        params={"api-key": key, "search": qbase64, "page": 1,
                "page_size": min(size, 100)},
        timeout=45)
    body = response.json()
    code_value = body.get("code")
    code = "" if code_value is None else str(code_value)
    if code not in {"0", "200"}:
        message = str((body.get("data") or {}).get("rest") or body.get("message") or code)
        raise IntelError(f"Hunter: {message}", platform="hunter",
                         quota=code in {"40204", "40205"})
    arrange = (body.get("data") or {}).get("arrange") or []
    out = []
    for row in arrange:
        out.append({
            "ip": _norm_ip(row.get("ip")), "port": _norm_port(row.get("port")),
            "host": _norm_ip(row.get("domain") or row.get("ip")),
            "title": _norm_ip(row.get("web_title")),
            "component": _norm_ip(row.get("component")),
            "protocol": _norm_ip(row.get("protocol")),
            "source": "hunter",
        })
    return out


async def _search_shodan(
    client: httpx.AsyncClient, creds: dict[str, Any], query: str, size: int,
) -> list[dict[str, Any]]:
    key = creds.get("key")
    if not key:
        raise IntelError("Shodan 未配置 api-key", platform="shodan")
    response = await client.get(
        "https://api.shodan.io/shodan/host/search",
        params={"key": key, "query": query, "minify": "true"},
        timeout=45)
    body = response.json()
    if body.get("error"):
        raise IntelError(f"Shodan: {body['error']}", platform="shodan",
                         quota="credit" in str(body["error"]).lower())
    out = []
    for match in (body.get("matches") or [])[:size]:
        product = _norm_ip(match.get("product"))
        banner_port = _norm_port(match.get("port"))
        hostnames = match.get("hostnames") or []
        out.append({
            "ip": _norm_ip(match.get("ip_str")),
            "port": banner_port,
            "host": _norm_ip(hostnames[0]) if hostnames else _norm_ip(match.get("ip_str")),
            "title": "",
            "component": f"{product} { _norm_ip(match.get('version'))}".strip(),
            "protocol": "",
            "source": "shodan",
        })
    return out


async def _search_zoomeye(
    client: httpx.AsyncClient, creds: dict[str, Any], query: str, size: int,
) -> list[dict[str, Any]]:
    key = creds.get("key")
    if not key:
        raise IntelError("ZoomEye 未配置 api-key", platform="zoomeye")
    base = "https://api.zoomeye.hk"
    response = await client.get(
        f"{base}/v2/search",
        params={"type": "host", "query": query, "page": 1},
        headers={"API-KEY": key},
        timeout=45)
    body = response.json()
    if body.get("code") not in (None, 0, 200, "200"):
        raise IntelError(f"ZoomEye: {body.get('message') or body.get('code')}",
                         platform="zoomeye",
                         quota="quota" in str(body.get("message") or "").lower())
    out = []
    for match in (body.get("matches") or [])[:size]:
        site = match.get("site") or ""
        out.append({
            "ip": _norm_ip(match.get("ip")),
            "port": _norm_port(match.get("port")),
            "host": _norm_ip(site),
            "title": _norm_ip((match.get("titles") or [""])[0]
                              if isinstance(match.get("titles"), list) else ""),
            "component": _norm_ip(match.get("service") or match.get("product")),
            "protocol": str(site).split(":", 1)[0] if ":" in str(site) else "",
            "source": "zoomeye",
        })
    return out


_ENGINES = {
    "fofa": _search_fofa,
    "hunter": _search_hunter,
    "shodan": _search_shodan,
    "zoomeye": _search_zoomeye,
}


def _format_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "测绘查询无结果（换关键词/平台再试）。"
    lines = ["platform | ip | port | host | title | component"]
    for row in rows[:200]:
        lines.append(
            f"{row.get('source')} | {row.get('ip')} | {row.get('port') or '-'} | "
            f"{row.get('host') or '-'} | {row.get('title') or '-'} | "
            f"{row.get('component') or '-'}")
    lines.append(f"[共 {len(rows)} 条] 测绘结果仅为情报线索：这些地址不在当前授权范围内，"
                 "不得直接访问；要测试其中资产必须先由 Orchestrator 提请范围审批。")
    return "\n".join(lines)


async def intel_search(
    client: httpx.AsyncClient, owner_id: int | None,
    platform: str, query: str, size: int = 100,
) -> tuple[str, list[dict[str, Any]], Path | None]:
    """执行一次测绘查询。返回 (给 LLM 的文本, 归一化行, JSON 落盘路径)。"""
    platform = str(platform or "").strip().lower()
    if platform not in INTEL_PLATFORMS:
        raise IntelError(
            f"不支持的平台 {platform}（可选 {', '.join(INTEL_PLATFORMS)}）")
    size = max(1, min(int(size or 100), 200))
    engine = _ENGINES[platform]
    try:
        rows = await engine(client, get_intel_keys(owner_id, platform),
                            query.strip(), size)
    except IntelError:
        raise
    except httpx.HTTPError as exc:
        raise IntelError(f"{platform} 网络错误: {exc}", platform=platform) from exc
    _WORKDIR.mkdir(parents=True, exist_ok=True)
    import time as _time

    artifact = _WORKDIR / f"{_time.strftime('%Y%m%d-%H%M%S')}-{platform}.json"
    try:
        artifact.write_text(
            json.dumps({"platform": platform, "query": query, "rows": rows},
                       ensure_ascii=False, indent=1), encoding="utf-8")
    except OSError:
        artifact = None
    return _format_table(rows), rows, artifact


def create_intel_search_tool(owner_id: int | None) -> AllowedFunctionTool:
    """资产测绘工具：按平台查询互联网资产（只读，结果仅情报）。

    key 由 core.intel_config 按用户池→平台池解析；工具闭包持有 owner_id，
    模型上下文只见查询结果，永不见 key。
    """

    async def intel_search_tool(platform: str, query: str, size: int = 100) -> str:
        """在空间测绘引擎查询互联网资产（FOFA/Hunter/Shodan/ZoomEye）。

        Args:
            platform: 引擎名，可选 fofa / hunter / shodan / zoomeye。
            query: 引擎原生语法查询串（如 fofa: 'title="登录"' 或
                'ip="10.0.0.0/24"'；shodan: 'http.title:login'）。
            size: 返回条数上限（1-200，默认 100）。

        Returns:
            紧凑结果表格文本。注意：结果地址不在授权范围内，不得访问；
            要测试须由 Orchestrator 提请范围审批。
        """
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=20)) as client:
            text, rows, artifact = await intel_search(
                client, owner_id, platform, query, size)
        suffix = f"（结果 JSON: {artifact}）" if artifact else ""
        return text + suffix

    return AllowedFunctionTool(intel_search_tool, is_read_only=True)
