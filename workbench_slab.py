#!/usr/bin/env python3
"""slab-match CTF Agent 工作台脚本（Web API 版）。

不再直接调用 main.run_mission，而是通过灵枢 Web 后端（api.py 的
FastAPI + SSE）创建会话并消费事件流，从而在前端控制台实时看到
完整的攻击流程（Brain → Orchestrator → Recon → Attack → 提交）。

流程：
  1. slab-match API：exercise-list 取已开放且未解出的题目
  2. exercise 取详情（附件/靶机 endpoints）；isNeedInit 时 build-exercise-env
     并轮询详情直到 isNeedCheck=false 且 endpoints 可用
  3. 有靶机用连接说明作目标（优先代理连接），有附件则下载附件，皆无则把题面写成文本
  4. 调用灵枢 Web API：登录 → /api/session/start 创建会话（携带 slab_context，
     使 Orchestrator 可通过 submit_slab_flag 在线提交 Flag）
  5. 订阅 /api/session/{id}/stream 的 SSE，实时打印阶段/Agent/工具事件；
     收到 approval_required 时自动向 /api/session/{id}/message 发送"批准"
  6. 工作台从会话取 flag（DASCTF{...}/flag{...}，仅提交花括号内内容）提交到平台；
     解出或放弃后 recover-exercise-env 回收环境

依赖 Web 后端已启动：
    python api.py          # 默认 0.0.0.0:8080

用法示例:
    # slab-match 自动工作台
    SLAB_ACCESS_KEY=ak_xxx python workbench_slab.py
    SLAB_ACCESS_KEY=ak_xxx python workbench_slab.py --rounds 3
    SLAB_ACCESS_KEY=ak_xxx python workbench_slab.py --loop --api-url http://localhost:8080
    # 默认使用 Web 管理中启用的 zhipu / GLM，推理强度 Max
    SLAB_ACCESS_KEY=ak_xxx python workbench_slab.py --provider zhipu
    # 仍可显式覆盖模型和强度
    SLAB_ACCESS_KEY=ak_xxx python workbench_slab.py --provider deepseek --model Min

    # 指定题目攻击（可多题）+ 并发
    SLAB_ACCESS_KEY=ak_xxx python workbench_slab.py --exercise-id 1001,1002 --concurrency 2
    SLAB_ACCESS_KEY=ak_xxx python workbench_slab.py -i --rounds 5 --concurrency 3   # 交互选题

    # slab-match API 人工调用
    python workbench_slab.py slab match-info
    python workbench_slab.py slab exercise-list
    python workbench_slab.py slab exercise --exercise-id 1001
    python workbench_slab.py slab build-env --exercise-id 1001
    python workbench_slab.py slab recover-env --exercise-id 1001
    python workbench_slab.py slab answer --exercise-id 1001 --flag DASCTF{xxx}
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx


# ── 灵枢 Web 后端 ──
DEFAULT_API_URL = os.environ.get("LINGSHU_API_URL", "http://localhost:8080")
# 默认 Web 登录账号（auth.py 中创建的用户）
DEFAULT_USERNAME = os.environ.get("LINGSHU_USER", "xihulunjian")
DEFAULT_PASSWORD = os.environ.get("LINGSHU_PASS", "Gdjt@2026")
# Workbench 默认使用 GLM。可由 CLI 或环境变量覆盖；当未显式指定
# --model 时，zhipu 使用 Max，其它 Provider 使用 Min。
DEFAULT_PROVIDER = os.environ.get("SLAB_LLM_PROVIDER", "zhipu").strip().lower() or "zhipu"
DEFAULT_MODEL = os.environ.get("SLAB_MODEL_LEVEL", "").strip()

# 解题相对 TTL 的提前量（秒），避免超时结算前还在跑
TTL_MARGIN = 120

# ── slab-match 平台 ──
SLAB_API_BASE = os.environ.get("SLAB_API_BASE", "https://pro.dasctf.com")
# AccessKey 不硬编码：优先环境变量 SLAB_ACCESS_KEY，其次 --access-key 参数
SLAB_ACCESS_KEY = os.environ.get("SLAB_ACCESS_KEY", "")
SLAB_WORKDIR = Path(__file__).resolve().parent / "WorkDir" / "arena_slab"
SLAB_WORKDIR.mkdir(parents=True, exist_ok=True)

# slab-match 平台 flag 格式：DASCTF{...} 或 flag{...}，提交时仅需花括号内内容
SLAB_FLAG_PATTERN = re.compile(r"(?:DASCTF|flag)\{([^{}\r\n]+)\}")
_EXERCISE_SCORE_CACHE: dict[int, float | None] = {}
_SCORE_FIELD_NAMES = (
    "score", "points", "point", "exerciseScore", "questionScore",
    "totalScore", "baseScore", "fraction",
)


def _resolve_model_level(provider: str, requested: str | None) -> str:
    """解析 Workbench 推理强度；GLM/Zhipu 默认 Max，其它模型默认 Min。"""
    if requested:
        if requested not in {"Low", "Min", "Max"}:
            raise ValueError("推理强度仅支持 Low、Min、Max")
        return requested
    return "Max" if provider.strip().lower() == "zhipu" else "Min"


def _coerce_score(value: Any) -> float | None:
    """把题目详情中的数字/数字字符串安全转换为分数。"""
    if isinstance(value, bool) or value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if score >= 0 else None


def _exercise_score(*sources: Any) -> float | None:
    """从题目详情/列表项中提取分数，兼容平台常见字段命名。"""
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in _SCORE_FIELD_NAMES:
            score = _coerce_score(source.get(key))
            if score is not None:
                return score
        # 部分平台会把计分信息包在 scoreInfo/exercise/corpusInfo 中。
        for key in ("scoreInfo", "exercise", "corpusInfo"):
            nested = source.get(key)
            if isinstance(nested, dict):
                score = _exercise_score(nested)
                if score is not None:
                    return score
    return None


def _format_score(score: float | None) -> str:
    if score is None:
        return "分数未知"
    return f"{score:g} 分"


def _mask_token(token: str) -> str:
    """脱敏展示 Token，避免日志泄露完整令牌。"""
    if len(token) <= 12:
        return token[:3] + "****" + token[-3:]
    return token[:6] + "****" + token[-4:]


def _extract_slab_flag(value: Any) -> str | None:
    """从 Agent 输出中提取 slab-match 平台 flag 的花括号内内容。

    平台格式为 DASCTF{...} 或 flag{...}，提交时仅需花括号内内容；
    若输入本身不含花括号前缀（如已是纯内容），则原样返回去除首尾空白。
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    match = SLAB_FLAG_PATTERN.search(stripped)
    if match:
        return match.group(1).strip()
    # 无前缀格式：视为已提交纯内容（如 Agent 直接输出 xxx）；含空白说明是整句，不提取
    if stripped and "{" not in stripped and "}" not in stripped and not any(ch.isspace() for ch in stripped):
        return stripped
    return None


# ── slab-match API 客户端 ──

def _apply_slab_host(host: str) -> None:
    """运行时切换 slab 平台地址（供 --host / SLAB_API_BASE 覆盖）。"""
    global SLAB_API_BASE
    SLAB_API_BASE = host


async def _slab_request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    access_key: str,
    payload: dict | None = None,
) -> dict[str, Any]:
    """统一 slab-match API 请求：认证头 + code=='00000' 成功校验。

    平台 WAF 会拦截 python-httpx 默认 UA，统一伪装为 curl。
    """
    headers = {
        "X-Agent-AccessKey": access_key,
        "Content-Type": "application/json",
        "User-Agent": "curl/8.5.0",
    }
    resp = await client.request(
        method, f"{SLAB_API_BASE}{path}", headers=headers, json=payload,
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("code") != "00000":
        raise RuntimeError(
            f"slab API 错误 {body.get('code')}: {body.get('message', body)}"
        )
    return body.get("data", {})


async def _slab_match_info(client: httpx.AsyncClient, access_key: str) -> dict[str, Any]:
    """查询竞赛注意事项和竞赛规则。"""
    return await _slab_request(client, "GET", "/slab-match/api/v1/agent/match/notice/match-info", access_key)


async def _slab_overview(client: httpx.AsyncClient, access_key: str) -> dict[str, Any]:
    """查询得分与排名。"""
    return await _slab_request(client, "GET", "/slab-match/api/v1/agent/answer-panel/overview", access_key)


async def _slab_exercise_list(client: httpx.AsyncClient, access_key: str) -> list[dict[str, Any]]:
    """查询题目列表（分类 → corpus）。"""
    return await _slab_request(client, "GET", "/slab-match/api/v1/agent/ctf/exercise-list", access_key)


async def _slab_exercise(client: httpx.AsyncClient, access_key: str, exercise_id: int) -> dict[str, Any]:
    """查询题目详情（附件 / endpoints / isNeedInit / isNeedCheck）。"""
    return await _slab_request(
        client, "GET",
        f"/slab-match/api/v1/agent/ctf/exercise?exerciseId={exercise_id}",
        access_key,
    )


async def _slab_build_env(client: httpx.AsyncClient, access_key: str, exercise_id: int) -> dict[str, Any]:
    """启动题目环境（异步，之后需轮询详情直到 isNeedCheck=false）。"""
    return await _slab_request(
        client, "POST", "/slab-match/api/v1/agent/ctf/build-exercise-env",
        access_key, {"exerciseId": exercise_id},
    )


async def _slab_recover_env(client: httpx.AsyncClient, access_key: str, exercise_id: int) -> dict[str, Any]:
    """回收题目环境。"""
    return await _slab_request(
        client, "POST", "/slab-match/api/v1/agent/ctf/recover-exercise-env",
        access_key, {"exerciseId": exercise_id},
    )


async def _slab_answer(
    client: httpx.AsyncClient, access_key: str, exercise_id: int, flag: str,
) -> dict[str, Any]:
    """提交答案，返回 {"isCorrect": bool}。flag 传花括号内内容即可。"""
    return await _slab_request(
        client, "POST", "/slab-match/api/v1/agent/answer-panel/answer",
        access_key, {"exerciseId": exercise_id, "flag": flag},
    )


async def _slab_notice_list(client: httpx.AsyncClient, access_key: str) -> list[dict[str, Any]]:
    """查询公告列表。"""
    return await _slab_request(client, "GET", "/slab-match/api/v1/agent/match/notice/now-list", access_key)


async def _slab_notice_detail(client: httpx.AsyncClient, access_key: str, notice_id: int) -> dict[str, Any]:
    """查询公告详情。"""
    return await _slab_request(
        client, "GET",
        f"/slab-match/api/v1/agent/match/notice/detail?id={notice_id}",
        access_key,
    )


def _normalize_annex_url(url: str) -> str:
    """规范化附件下载 URL，兼容平台返回的多种形态。

    - "//oss.xx/...zip"            → "https://oss.xx/...zip"（补协议）
    - "/slab-match/oss/...zip"     → "{SLAB_API_BASE}/slab-match/..."（相对路径拼接平台地址）
    - "oss.aliyuncs.com/xx/y.zip"  → "https://oss.aliyuncs.com/..."（裸域名补协议）
    - "https://..."                → 原样
    """
    url = url.strip()
    if not url:
        return url
    if url.startswith("//"):
        return f"https:{url}"
    if url.startswith("/"):
        return f"{SLAB_API_BASE}{url}"
    if "://" not in url and "/" in url and "." in url:
        # 形如裸域名（如 "oss-cn-hangzhou.aliyuncs.com/xx/yy.zip"）；要求带路径分隔符，
        # 避免把 "challenge.zip" 这类纯文件名误判为域名
        return f"https://{url}"
    return url


def _annex_url(annex: dict) -> str | None:
    """从附件条目提取下载 URL，兼容常见字段名。"""
    for key in ("url", "annexUrl", "downloadUrl", "ossUrl", "fileUrl", "src"):
        v = annex.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _annex_name(annex: dict, index: int) -> str:
    """从附件条目提取文件名，兼容常见字段名。"""
    for key in ("name", "fileName", "annexName", "filename"):
        v = annex.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return f"annex_{index}"


async def _download_slab_annex(
    client: httpx.AsyncClient,
    annex: dict,
    workdir: Path,
    index: int,
    access_key: str,
) -> Path | None:
    """下载单个 slab 附件到 workdir。附件通常为 OSS 公开链接，先试带认证。"""
    url = _annex_url(annex)
    if not url:
        return None
    url = _normalize_annex_url(url)
    if not url.startswith(("http://", "https://")):
        # 规范化后仍不是可下载地址（如纯文件名），打印诊断后跳过，避免浪费请求
        print(f"[slab] 附件 URL 无法规范化，跳过: {url[:100]}")
        return None
    raw_name = _annex_name(annex, index)
    dest = workdir / (Path(raw_name).name or f"annex_{index}")
    headers = {"X-Agent-AccessKey": access_key, "User-Agent": "curl/8.5.0"}
    try:
        async with client.stream("GET", url, headers=headers) as resp:
            if resp.status_code in (401, 403):
                async with client.stream("GET", url) as resp2:
                    resp2.raise_for_status()
                    with dest.open("wb") as f:
                        async for chunk in resp2.aiter_bytes():
                            f.write(chunk)
            else:
                resp.raise_for_status()
                with dest.open("wb") as f:
                    async for chunk in resp.aiter_bytes():
                        f.write(chunk)
    except Exception as exc:
        print(f"[slab] 附件下载失败（继续）: {raw_name}: {exc}")
        return None
    return dest


def _endpoint_connect_addr(ep: dict[str, Any]) -> str | None:
    """提取 endpoint 的可连接地址（优先代理入口，其次直连）。

    返回如 "1.14.76.59:26837" 的 IP:端口，供 target 规范化（normalize_target）
    解析并登记到授权范围；无法提取时返回 None（调用方退回说明文本）。
    """
    proxy_ips = ep.get("proxyIps") or []
    mappings = ep.get("portMappings") or []
    expose_ips = ep.get("exposeIps") or []
    ports = ep.get("ports") or []
    is_proxy = bool(ep.get("isProxy", False))

    if is_proxy and proxy_ips and mappings:
        proxy = mappings[0].get("proxy")
        if proxy:
            return f"{proxy_ips[0]}:{proxy}"

    if expose_ips:
        ip = str(expose_ips[0]).strip()
        is_ipv6 = ip.count(":") > 1
        # exposeIps 可能已含端口（如 "1.14.76.59:26837"）；仅 IPv4 形式才拆分端口，
        # 避免把含多个冒号的 IPv6 地址误判为 IPv4:端口
        if not is_ipv6 and ":" in ip and ip.rsplit(":", 1)[1].isdigit():
            return ip
        if is_ipv6:
            # IPv6 无法用 "ip:port" 形式表达，交由调用方回退到连接说明文本
            return None
        for port in ports:
            p = str(port).strip()
            if p.isdigit():
                return f"{ip}:{p}"
            if "/" in p and p.rsplit("/", 1)[1].isdigit():
                return f"{ip}:{p.rsplit('/', 1)[1]}"
        if ip:
            return ip
    return None


def _format_endpoint(ep: dict[str, Any]) -> str:
    """把单个 endpoint 结构转成 Agent 可读的连接说明（优先代理连接）。"""
    parts: list[str] = []
    proxy_ips = ep.get("proxyIps") or []
    mappings = ep.get("portMappings") or []
    expose_ips = ep.get("exposeIps") or []
    ports = ep.get("ports") or []
    is_proxy = bool(ep.get("isProxy", False))
    if is_proxy and proxy_ips and mappings:
        parts.append("【连接方式】优先使用代理（isProxy=true），经平台代理访问靶机：")
        for m in mappings:
            mtype = m.get("type", "tcp")
            port = m.get("port")
            proxy = m.get("proxy")
            parts.append(f"  - {mtype} {proxy_ips[0]}:{proxy} → 靶机端口 {port}")
        parts.append(f"代理出口 IP: {', '.join(proxy_ips)}")
    if expose_ips:
        parts.append(f"直连 IP: {', '.join(expose_ips)} | 开放端口: {', '.join(ports)}")
    users = ep.get("users") or []
    if users:
        parts.append(
            "账号密码: "
            + "; ".join(
                f"{u.get('username')}/{u.get('password')}" for u in users if u.get("username")
            )
        )
    if ep.get("expireTime"):
        parts.append(f"环境过期时间戳(ms): {ep.get('expireTime')}")
    return "\n".join(parts) if parts else json.dumps(ep, ensure_ascii=False)


def _slab_ttl_seconds(detail: dict[str, Any], default: int = 3600) -> int:
    """根据 expireTime/currentTime 计算会话超时（秒），留出 TTL 提前量。"""
    eps = detail.get("endpoints") or []
    expire = None
    if eps and eps[0].get("expireTime"):
        expire = int(eps[0]["expireTime"])
    if not expire:
        return default
    now = int(detail.get("currentTime") or time.time() * 1000)
    remaining = max(0, (expire - now) // 1000)
    return max(120, remaining - TTL_MARGIN)


async def _poll_slab_env(
    client: httpx.AsyncClient,
    access_key: str,
    exercise_id: int,
    wait_seconds: int = 180,
) -> dict[str, Any]:
    """build-exercise-env 后轮询题目详情，直到 isNeedCheck=false 且 endpoints 可用。

    超时返回最后一次详情（由调用方决定是否回退附件/题面）。
    """
    deadline = asyncio.get_event_loop().time() + wait_seconds
    detail: dict[str, Any] = {}
    while asyncio.get_event_loop().time() < deadline:
        try:
            detail = await _slab_exercise(client, access_key, exercise_id)
            if not detail.get("isNeedCheck") and detail.get("endpoints"):
                return detail
        except Exception as exc:
            print(f"[slab] 轮询环境状态异常: {exc}")
        await asyncio.sleep(5)
    print("[slab] 等待环境就绪超时")
    return detail


def _extract_annex_entries(attachment: Any) -> list[dict]:
    """从 exercise 详情的 attachment 字段提取附件条目列表（兼容多种结构）。

    平台 API 的 attachment 可能为：
      - 单对象 {"url","name"}          → [条目]
      - 列表 [{"url","name"}, ...]     → 原样返回条目
      - 包装对象 {"files": [条目]}     → 取 files
    无法识别时返回 []（调用方可打印诊断信息排查真实结构）。
    """
    if not attachment:
        return []
    if isinstance(attachment, str):
        # attachment 直接是下载 URL 字符串
        if attachment.strip():
            return [{"url": attachment.strip()}]
        return []
    if isinstance(attachment, list):
        return [a for a in attachment if isinstance(a, dict)]
    if not isinstance(attachment, dict):
        return []
    files = attachment.get("files")
    if files is not None:
        if isinstance(files, list):
            return [a for a in files if isinstance(a, dict)]
        if isinstance(files, dict):
            return [files]
    # 单附件直接挂在 attachment 下（无 files 包装）
    if "url" in attachment or "name" in attachment:
        return [attachment]
    return []


async def _prepare_slab_target(
    client: httpx.AsyncClient,
    access_key: str,
    detail: dict[str, Any],
) -> tuple[str, str, list[Path]]:
    """把题目详情转成灵枢目标与说明。

    返回 (target, note, annex_paths):
      - 有 endpoints: target = 连接说明文本，note = "endpoint"（容器/靶机）
      - 有附件:       target = 第一个附件路径，note = "annex"
      - 皆无:         题面 description 写成文本文件，note = "content"
    """
    exercise_id = detail.get("id", 0)
    workdir = SLAB_WORKDIR / f"exercise_{exercise_id}"
    workdir.mkdir(parents=True, exist_ok=True)

    # 附件全部下载（pwn/逆向类常需本地分析）；attachment 结构兼容单对象/列表/files 包装
    annex_files = _extract_annex_entries(detail.get("attachment"))
    if annex_files:
        print(f"[slab] 附件 {len(annex_files)} 个: "
              f"{', '.join(str(a.get('name') or f'annex_{i}') for i, a in enumerate(annex_files))}")
    else:
        # 诊断：无附件时打印 attachment 字段截断形态，便于排查平台结构变化
        raw_attach = detail.get("attachment")
        print(f"[slab] 无附件（attachment 字段形态: {str(raw_attach)[:120] or '缺失'}）")
    annex_paths: list[Path] = []
    for i, annex in enumerate(annex_files):
        p = await _download_slab_annex(client, annex, workdir, i, access_key)
        if p:
            annex_paths.append(p)

    endpoints = detail.get("endpoints") or []
    if endpoints:
        addr = _endpoint_connect_addr(endpoints[0])
        if addr:
            # target 用可解析的 IP:端口（授权范围登记 / scoped_shell 放行）；
            # 完整连接说明由调用方拼入 goal（_format_endpoint）。
            return addr, "endpoint", annex_paths
        desc = "\n\n".join(_format_endpoint(ep) for ep in endpoints)
        return desc, "endpoint", annex_paths

    if annex_paths:
        return str(annex_paths[0]), "annex", annex_paths

    txt = workdir / "problem.txt"
    txt.write_text(
        f"题目: {detail.get('name', '')}\n\n{detail.get('description', '')}",
        encoding="utf-8",
    )
    return str(txt), "content", annex_paths


# ── 灵枢 Web 后端客户端 ──

async def _login(api_url: str, username: str, password: str) -> str:
    """登录灵枢 Web 后端，返回 Bearer token。"""
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{api_url}/auth/login",
            json={"username": username, "password": password},
        )
        resp.raise_for_status()
        body = resp.json()
        return body["access_token"]


async def _enabled_model_providers(api_url: str, token: str) -> set[str]:
    """读取 Web 管理中启用的模型 Provider，启动解题前快速校验。"""
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{api_url}/api/model-providers", headers=headers)
        resp.raise_for_status()
        return {
            str(item.get("id") or "").strip().lower()
            for item in resp.json().get("providers", [])
            if str(item.get("id") or "").strip()
        }


async def _start_session(
    api_url: str,
    token: str,
    target: str,
    goal: str,
    provider: str,
    model: str,
    slab_context: dict | None = None,
) -> dict:
    """通过 /api/session/start 创建会话，返回 {session_id, ...}。"""
    headers = {"Authorization": f"Bearer {token}"}
    # 打印时对 slab_context 中的 access_key 脱敏，避免日志泄露完整令牌
    safe_slab = None
    if slab_context:
        safe_slab = dict(slab_context)
        if safe_slab.get("access_key"):
            safe_slab["access_key"] = _mask_token(safe_slab["access_key"])
    print({
        "target": target,
        "goal": goal,
        "provider": provider,
        "model": model,
        "slab_context": safe_slab,
    })
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{api_url}/api/session/start",
            headers=headers,
            json={
                "target": target,
                "goal": goal,
                "provider": provider,
                "model": model,
                "slab_context": slab_context,
            },
        )
        resp.raise_for_status()
        return resp.json()


async def _send_message(api_url: str, token: str, session_id: str, content: str) -> dict:
    """向会话发送用户消息（审批决策 / 运行时指令）。"""
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{api_url}/api/session/{session_id}/message",
            headers=headers,
            json={"content": content},
        )
        resp.raise_for_status()
        return resp.json()


async def _get_session_detail(api_url: str, token: str, session_id: str) -> dict:
    """获取会话详情（含 flag / phase / target_info）。"""
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{api_url}/api/session/{session_id}", headers=headers)
        resp.raise_for_status()
        return resp.json()


async def _stream_events(
    api_url: str,
    token: str,
    session_id: str,
    timeout: int,
):
    """订阅会话 SSE 事件流并实时打印，自动批准攻击阶段。

    Yields:
        (event_type, payload) 直到任务结束或超时。
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/event-stream",
    }
    print(f"[workbench] 已创建 Web 会话 {session_id}，开始订阅攻击流程...\n")
    deadline = asyncio.get_event_loop().time() + timeout
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout + 30.0, connect=30.0)) as client:
        async with client.stream(
            "GET", f"{api_url}/api/session/{session_id}/stream",
            headers=headers,
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if asyncio.get_event_loop().time() > deadline:
                    print("[workbench] 会话观察超时")
                    break
                if not line.startswith("data:"):
                    continue
                raw = line[5:].strip()
                if not raw:
                    continue
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                etype = event.get("type", "")
                yield etype, event


async def _consume_mission_events(
    api_url: str,
    web_token: str,
    session_id: str,
    timeout: int,
) -> tuple[str | None, str, bool]:
    """订阅会话 SSE 事件流：实时打印阶段/Agent/工具事件并自动批准攻击阶段。

    返回 (mission_flag, mission_phase, ended)。
    """
    mission_flag: str | None = None
    mission_phase = "unknown"
    ended = False
    approved = False
    try:
        async for etype, event in _stream_events(api_url, web_token, session_id, timeout):
            agent = event.get("agent", "")
            if etype == "mission_start":
                print(f"[Web:{session_id}] 🚀 任务启动")
            elif etype == "phase_change":
                mission_phase = event.get("phase", "unknown")
                print(f"[Web:{session_id}] 🔄 阶段 → {mission_phase}")
            elif etype in ("text_start", "thinking_start"):
                print(f"\n[{agent}][{'🧠' if etype.startswith('thinking') else '💬'}] ", end="", flush=True)
            elif etype in ("text_delta", "thinking_delta"):
                delta = event.get("delta") or event.get("content") or ""
                print(delta, end="", flush=True)
            elif etype in ("text_end", "thinking_end"):
                print()
            elif etype == "tool_call_start":
                print(f"\n🔧 [{agent}] 调用工具: {event.get('tool_name')} ...")
            elif etype == "tool_call_delta":
                pass
            elif etype == "tool_call_end":
                print(f"   ✅ [{agent}] 工具完成")
            elif etype == "plan_updated":
                items = event.get("items", [])
                print(f"[Web:{session_id}] 📋 计划更新 ({len(items)} 项, phase={event.get('phase')})")
            elif etype == "approval_required":
                if not approved:
                    print(f"\n[Web:{session_id}] ⛔ 请求攻击阶段批准 → 自动批准")
                    try:
                        await _send_message(api_url, web_token, session_id, "批准")
                        approved = True
                    except Exception as exc:
                        print(f"[workbench] 自动批准失败: {exc}")
            elif etype == "approval_resolved":
                print(f"[Web:{session_id}] ✅ 审批结果: {event.get('decision')}")
            elif etype == "target_info":
                if event.get("flag"):
                    mission_flag = event["flag"]
                print(f"[Web:{session_id}] 🎯 目标信息: 阶段={event.get('phase')} "
                      f"flag={event.get('flag') or '未发现'}")
            elif etype == "flag_found":
                mission_flag = event.get("flag") or event.get("content")
                print(f"[Web:{session_id}] 🏁 发现 Flag: {mission_flag}")
            elif etype == "slab_submit":
                sub_ok = event.get("correct")
                print(f"[Web:{session_id}] 🎌 slab-match 提交: flag={event.get('flag')} "
                      f"（提交内容={event.get('submitted')}）"
                      f"{'✅正确' if sub_ok else '❌错误'}")
                if sub_ok:
                    mission_flag = event.get("flag") or mission_flag
            elif etype == "message":
                if event.get("content"):
                    print(f"[{agent}] {event['content']}")
            elif etype == "mission_end":
                mission_phase = event.get("status") or mission_phase
                print(f"[Web:{session_id}] 🏁 任务结束: {event.get('status')}")
                ended = True
            elif etype == "mission_cancelled":
                print(f"[Web:{session_id}] ⛔ 任务取消: {event.get('message')}")
                ended = True
            elif etype == "error":
                print(f"[Web:{session_id}] ❌ 错误: {event.get('message')}")
            if ended:
                break
    except asyncio.TimeoutError:
        print("[workbench] SSE 观察超时")
    except httpx.HTTPStatusError as exc:
        print(f"[workbench] SSE 请求失败: {exc}")
    except Exception as exc:
        print(f"[workbench] 会话异常: {exc}")
    return mission_flag, mission_phase, ended


# ── slab-match 单题处理 ──

def _rejected_flags_path(exercise_id: int) -> Path:
    """错误候选持久化文件：WorkDir/arena_slab/exercise_{id}/rejected_flags.json。"""
    return SLAB_WORKDIR / f"exercise_{exercise_id}" / "rejected_flags.json"


def _load_rejected_flags(exercise_id: int) -> set[str]:
    """加载历史错误 flag 集合（跨运行去重，避免重复消耗平台提交次数）。"""
    try:
        data = json.loads(_rejected_flags_path(exercise_id).read_text(encoding="utf-8"))
        return {str(f) for f in data} if isinstance(data, list) else set()
    except (OSError, ValueError):
        return set()


def _save_rejected_flags(exercise_id: int, flags: set[str]) -> None:
    """原子写入错误 flag 集合（临时文件 + os.replace，参照项目持久化约定）。"""
    path = _rejected_flags_path(exercise_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(sorted(flags), ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _parse_exercise_ids(raw: str) -> list[int] | None:
    """解析 --exercise-id 逗号/空白分隔的 ID 列表；空输入返回 None。"""
    if not raw or not raw.strip():
        return None
    ids: list[int] = []
    for token in re.split(r"[,\s]+", raw.strip()):
        if not token:
            continue
        try:
            ids.append(int(token))
        except ValueError:
            print(f"[slab] ⚠️ 忽略非法题目 ID: {token}")
    ids = list(dict.fromkeys(ids))  # 去重保序
    return ids or None


def _parse_choice_ranges(raw: str) -> list[int]:
    """解析交互选择输入 '1,3,5-7' / '1 3 5-7' → [1,3,5,6,7]（去重保序）。"""
    out: list[int] = []
    for token in re.split(r"[,\s]+", raw.strip()):
        if not token:
            continue
        if "-" in token:
            a, _, b = token.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            if lo <= hi:
                out.extend(range(lo, hi + 1))
        else:
            try:
                out.append(int(token))
            except ValueError:
                continue
    return list(dict.fromkeys(out))


async def _pick_exercises(
    client: httpx.AsyncClient,
    access_key: str,
    count: int,
    exercise_ids: list[int] | None = None,
) -> list[dict]:
    """取一批题目。

    exercise_ids 指定时按 ID 匹配（已解出/未开放仍按指定处理，仅打警告）；
    否则取已开放且未解出的前 count 道。
    """
    try:
        categories = await _slab_exercise_list(client, access_key)
    except Exception as exc:
        print(f"[slab] 获取题目列表失败: {exc}")
        return []
    all_ex = [ex for cat in categories or [] for ex in (cat.get("corpus") or [])]

    if exercise_ids:
        wanted: list[dict] = []
        for eid in exercise_ids:
            ex = next((e for e in all_ex if e.get("id") == eid), None)
            if ex is None:
                print(f"[slab] ⚠️ 题目 #{eid} 不在题目列表中（可能已下架或 ID 错误），跳过")
                continue
            if ex.get("hasSolved"):
                print(f"[slab] ⚠️ 题目 #{eid} 已解出，仍按指定继续尝试")
            if not ex.get("isOpen"):
                print(f"[slab] ⚠️ 题目 #{eid} 未开放，仍按指定继续尝试")
            wanted.append(ex)
        return wanted

    open_unsolved = [ex for ex in all_ex if ex.get("isOpen") and not ex.get("hasSolved")]
    return open_unsolved[:count]


async def _interactive_pick_exercises(
    client: httpx.AsyncClient,
    access_key: str,
    count: int,
) -> list[dict] | None:
    """列出已开放未解出题，让用户在终端选择（编号/逗号/范围，回车全选，q 退出）。

    返回 None 表示无可选题或输入无效；[] 表示用户主动退出。
    """
    open_unsolved = await _pick_exercises(client, access_key, 10**9)
    if not open_unsolved:
        print("[slab] 当前无已开放且未解出的题目")
        return None
    print(f"\n可选题目（已开放且未解出，共 {len(open_unsolved)} 道）:")
    for i, ex in enumerate(open_unsolved, 1):
        print(f"  {i:>3}. #{ex.get('id')}  {ex.get('name')}")
    raw = (await asyncio.to_thread(
        input, "选择编号（如 1,3 / 1-3，回车全选，q 退出）: ",
    )).strip()
    if raw.lower() in ("q", "quit"):
        return []
    if not raw:
        return open_unsolved[:count]
    picked = [open_unsolved[i - 1] for i in _parse_choice_ranges(raw) if 1 <= i <= len(open_unsolved)]
    if not picked:
        print("[slab] 未选择有效编号")
        return None
    return picked


async def _solve_slab_attempt(
    api_url: str,
    web_token: str,
    client: httpx.AsyncClient,
    access_key: str,
    exercise: dict,
    provider: str,
    model: str,
    retries: int,
    prefix: str = "",
) -> bool:
    """对一道 slab 题做完整流程：详情 → (build+轮询) → 灵枢会话 → 提取提交 → 回收环境。

    prefix 用于并发场景区分题目输出（如 "[slab:#1001] "）。
    返回 True 解出 / False 未解出。平台每题最多提交 50 次（竞赛规则），
    rejected_flags 持久化到 WorkDir/arena_slab/exercise_{id}/rejected_flags.json，
    多轮运行间避免重复提交同一错误 flag；flag 提交仅用花括号内内容。
    """
    exercise_id = exercise.get("id")
    name = exercise.get("name", "")

    print(f"\n{prefix}{'='*60}")
    print(f"{prefix}题目 #{exercise_id}: {name}")
    print(f"{prefix}{'='*60}")

    try:
        detail = await _slab_exercise(client, access_key, exercise_id)
    except Exception as exc:
        print(f"{prefix}查询题目详情失败: {exc}")
        return False

    # 环境启动（如需）：异步，需轮询详情直到 isNeedCheck=false 且 endpoints 可用
    built = False
    if detail.get("isNeedInit"):
        print(f"{prefix}需要启动环境（build-exercise-env）...")
        try:
            await _slab_build_env(client, access_key, exercise_id)
            built = True
            detail = await _poll_slab_env(client, access_key, exercise_id)
        except Exception as exc:
            print(f"{prefix}启动环境失败: {exc}")

    target, note, annex_paths = await _prepare_slab_target(client, access_key, detail)
    print(f"{prefix}目标来源: {note}")
    if note == "endpoint":
        print(f"{prefix}目标地址: {target}")
        print(f"{prefix}靶机连接:\n{_format_endpoint(detail.get('endpoints')[0])}")
    if annex_paths:
        print(f"{prefix}附件: {', '.join(str(p) for p in annex_paths)}")

    timeout = _slab_ttl_seconds(detail)
    print(f"{prefix}会话超时预算: {timeout}s")

    # 平台 flag 格式、连接方式必须进入 goal，确保 Brain/Orchestrator/Attack 可见
    base_goal = (
        "获取 Flag\n\n"
        "【FLAG 提交硬性要求】平台接受 DASCTF{...} 或 flag{...} 格式，提交时仅需花括号内内容。"
        "工作台会自动从你的输出中提取 DASCTF{...}/flag{...} 并提交；发现 flag 后请以完整的 "
        "DASCTF{...} 或 flag{...} 格式明确输出，禁止输出裸文本或带解释的整句。\n\n"
        f"【题目】{detail.get('description', '')}"
    )
    if note == "endpoint":
        ep_desc = "\n\n".join(_format_endpoint(ep) for ep in (detail.get("endpoints") or []))
        base_goal += (
            f"\n\n【远程目标】{target}\n（授权目标地址，访问前先看下面的连接方式）\n"
            f"【连接方式】\n{ep_desc}"
        )
    if annex_paths:
        base_goal += f"\n\n【本地附件】{', '.join(str(p) for p in annex_paths)}（可结合本地文件分析）"

    goal = base_goal
    max_attempts = max(1, retries)
    completed_sessions = 0
    rejected_flags = _load_rejected_flags(exercise_id)
    transient_failures = 0
    if rejected_flags:
        print(f"{prefix}本题最多分析 {max_attempts} 轮，已排除历史错误候选 {len(rejected_flags)} 个")
    else:
        print(f"{prefix}本题按配置最多分析 {max_attempts} 轮")

    # 携带 slab_context，使 Orchestrator 可通过 submit_slab_flag 在线提交 Flag
    slab_context = {
        "exercise_id": exercise_id,
        "access_key": access_key,
        "api_base": SLAB_API_BASE,
    }

    try:
        for run_idx in range(max_attempts):
            print(f"\n{prefix}解题第 {run_idx + 1} 轮...")
            try:
                start = await _start_session(
                    api_url, web_token, target, goal, provider, model,
                    slab_context=slab_context,
                )
            except Exception as exc:
                print(f"{prefix}创建 Web 会话失败: {exc}")
                if "401" in str(exc):
                    print(f"{prefix}请检查 --username/--password 或后端 JWT 配置")
                transient_failures += 1
                continue
            session_id = start.get("session_id")
            if not session_id:
                print(f"{prefix}未返回 session_id: {start}")
                transient_failures += 1
                continue

            # 订阅 SSE，实时展示攻击流程 + 自动批准（复用公共消费函数）
            mission_flag, mission_phase, ended = await _consume_mission_events(
                api_url, web_token, session_id, timeout,
            )
            try:
                session_detail = await _get_session_detail(api_url, web_token, session_id)
            except Exception:
                session_detail = {}
            mission_state = session_detail.get("mission_state") or {}
            slab_submit = mission_state.get("slab_submit")
            if not mission_flag:
                mission_flag = (
                    session_detail.get("flag")
                    or (session_detail.get("target_info") or {}).get("flag")
                )
            if not mission_phase or mission_phase == "unknown":
                mission_phase = session_detail.get("phase") or "unknown"

            terminal_phases = {"COMPLETED", "FAILED", "CANCELLED", "completed", "failed", "cancelled"}
            if ended or mission_phase in terminal_phases or mission_flag:
                completed_sessions += 1
            else:
                transient_failures += 1
                print(f"{prefix}本轮会话未确认终态，不计入有效分析")

            print(f"\n{prefix}Web 会话结束: 阶段={mission_phase}")

            # Orchestrator 已在线提交（submit_slab_flag）并判定正确 → 直接成功，不再重复提交
            if slab_submit and slab_submit.get("correct"):
                print(f"{prefix}✅ Orchestrator 已在线提交正确 Flag: {slab_submit.get('flag')}")
                return True

            raw_flag = mission_flag or ""
            flag = _extract_slab_flag(raw_flag)
            if raw_flag and not flag:
                preview = str(raw_flag).strip()[:80]
                print(f"{prefix}⚠️ 候选 FLAG 无法解析为 DASCTF{{...}}/flag{{...}}，不提交: {preview}")
                goal = (
                    f"{base_goal}\n\n【第 {run_idx + 1} 轮反馈】上轮候选『{preview}』不符合平台格式，"
                    "未提交。必须继续求解，并以 DASCTF{...} 或 flag{...} 完整格式输出。"
                )
                continue

            if flag:
                # Orchestrator 已在本会话提交过同一错误 flag → 避免重复消耗提交次数
                if flag in rejected_flags or (
                    slab_submit
                    and not slab_submit.get("correct")
                    and slab_submit.get("submitted") == flag
                ):
                    print(f"{prefix}⏭ 该 flag 已判定错误（本会话或平台），跳过重复提交: {flag[:16]}...")
                else:
                    print(f"{prefix}提交答案: {flag[:24]}...")
                    try:
                        data = await _slab_answer(client, access_key, exercise_id, flag)
                    except Exception as exc:
                        print(f"{prefix}提交失败: {exc}")
                        transient_failures += 1
                        goal = (
                            f"{base_goal}\n\n【第 {run_idx + 1} 轮反馈】候选『{flag}』提交接口异常，"
                            "请复核候选并继续分析，不要放弃题目。"
                        )
                        continue
                    if data.get("isCorrect"):
                        print(f"{prefix}✅ Flag 正确！")
                        return True
                    print(f"{prefix}❌ Flag 错误。")
                rejected_flags.add(flag)
                _save_rejected_flags(exercise_id, rejected_flags)
                goal = (
                    f"{base_goal}\n\n【第 {run_idx + 1} 轮反馈】候选『{flag}』已被平台判为错误，"
                    "禁止重复提交。"
                    f"目前已排除: {', '.join(sorted(rejected_flags))}。请换思路重新分析。"
                )
                continue

            print(f"{prefix}任务未产出可用 flag")
    finally:
        # 无论成败都回收已启动的环境（平台按题计环境资源）
        if built:
            try:
                await _slab_recover_env(client, access_key, exercise_id)
                print(f"{prefix}已回收环境")
            except Exception as exc:
                print(f"{prefix}回收环境失败: {exc}")

    if completed_sessions == 0:
        print(
            f"{prefix}未完成有效分析（瞬态故障 {transient_failures} 次），"
            "本题保留供下次继续"
        )
    return False


async def _run_slab_batch(
    api_url: str,
    web_token: str,
    client: httpx.AsyncClient,
    access_key: str,
    exercises: list[dict],
    provider: str,
    model: str,
    retries: int,
    concurrency: int,
) -> tuple[int, int]:
    """并发处理一批题目（最多 concurrency 个），返回 (solved, failed)。

    每题的输出带 "[slab:#id]" 前缀便于区分；异常计入 failed。
    """
    tasks = [
        asyncio.create_task(
            _solve_slab_attempt(
                api_url, web_token, client, access_key, ex,
                provider, model, retries,
                prefix=f"[slab:#{ex.get('id')}] ",
            ),
            name=f"slab-{ex.get('id')}",
        )
        for ex in exercises[:concurrency]
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    solved = 0
    failed = 0
    for ex, res in zip(exercises[:concurrency], results):
        if isinstance(res, BaseException):
            print(f"[slab:#{ex.get('id')}] 任务异常: {type(res).__name__}: {res}")
            failed += 1
        elif res:
            solved += 1
        else:
            failed += 1
    return solved, failed


async def _slab_workbench_main(args: argparse.Namespace) -> None:
    """slab 自动工作台主循环：支持 --exercise-id 指定题目、-i 交互选题、--concurrency 并发。"""
    if not args.access_key:
        raise SystemExit(
            "[配置错误] slab 自动工作台需要 AccessKey："
            "设置环境变量 SLAB_ACCESS_KEY 或传 --access-key"
        )
    _apply_slab_host(args.host)
    print(f"[slab] 平台: {SLAB_API_BASE} | AccessKey: {_mask_token(args.access_key)}")
    print(f"[slab] 灵枢模型: provider={args.provider} | 推理强度={args.model}")

    try:
        web_token = await _login(args.api_url, args.username, args.password)
    except Exception as exc:
        raise SystemExit(f"[配置错误] 登录灵枢 Web 后端失败: {exc}") from exc
    print(f"[slab] 已登录 Web 后端（用户: {args.username}）")
    try:
        enabled_providers = await _enabled_model_providers(args.api_url, web_token)
    except Exception as exc:
        raise SystemExit(f"[配置错误] 无法读取灵枢模型列表: {exc}") from exc
    if args.provider not in enabled_providers:
        enabled = "、".join(sorted(enabled_providers)) or "无"
        raise SystemExit(
            f"[配置错误] Provider '{args.provider}' 未在 Web 管理中启用；"
            f"当前可用：{enabled}"
        )

    concurrency = max(1, args.concurrency)
    exercise_ids = _parse_exercise_ids(args.exercise_id)

    async with httpx.AsyncClient(timeout=httpx.Timeout(180.0, connect=30.0)) as client:
        # ── 指定题目：处理完即结束（忽略 rounds/loop） ──
        if exercise_ids:
            if args.loop:
                print("[slab] 已指定 --exercise-id，忽略 --loop")
            print(f"[slab] 指定题目: {exercise_ids}")
            exercises = await _pick_exercises(
                client, args.access_key, len(exercise_ids), exercise_ids,
            )
            if not exercises:
                print("[slab] 指定题目均无效，结束")
                return
            solved, failed = await _run_slab_batch(
                args.api_url, web_token, client, args.access_key,
                exercises, args.provider, args.model, args.retries, concurrency,
            )
            print(f"\n[slab] 指定题目处理完成: 解出 {solved} 题，未解出 {failed} 题")
            return

        # ── 自动取题 / 交互选题 ──
        solved = 0
        failed = 0
        processed = 0
        round_i = 0
        batch_total = None if args.loop else (args.rounds + concurrency - 1) // concurrency
        while args.loop or processed < args.rounds:
            round_i += 1
            remaining = None if args.loop else args.rounds - processed
            want = concurrency if remaining is None else min(concurrency, remaining)

            exercises = await _pick_exercises(client, args.access_key, want)
            if not exercises:
                print("[slab] 当前无已开放且未解出的题目")
                break
            if args.interactive:
                picked = await _interactive_pick_exercises(client, args.access_key, want)
                if picked is None:
                    break
                if not picked:
                    print("[slab] 用户退出选择")
                    break
                exercises = picked

            label = f"第 {round_i} 轮" if args.loop else f"第 {round_i}/{batch_total} 轮"
            print(f"\n===== [slab] {label}（本批 {len(exercises)} 题，并发 {concurrency}）=====")
            s, f = await _run_slab_batch(
                args.api_url, web_token, client, args.access_key,
                exercises, args.provider, args.model, args.retries, concurrency,
            )
            solved += s
            failed += f
            processed += len(exercises)

        if processed == 0:
            print("[slab] 无题目可处理")
            return
        print(f"\n[slab] 完成 {round_i} 轮: 解出 {solved} 题，未解出 {failed} 题")


async def _slab_manual(args: argparse.Namespace) -> None:
    """slab 子命令：逐个调用平台 API（人工调用）。"""
    if not args.access_key:
        raise SystemExit("[配置错误] 请设置环境变量 SLAB_ACCESS_KEY 或传 --access-key")
    _apply_slab_host(args.host)
    print(f"[slab] 平台: {SLAB_API_BASE} | AccessKey: {_mask_token(args.access_key)}")

    async with httpx.AsyncClient(timeout=60.0) as client:
        cmd = args.cmd
        try:
            if cmd == "match-info":
                data = await _slab_match_info(client, args.access_key)
            elif cmd == "overview":
                data = await _slab_overview(client, args.access_key)
            elif cmd == "exercise-list":
                data = await _slab_exercise_list(client, args.access_key)
            elif cmd == "exercise":
                data = await _slab_exercise(client, args.access_key, args.exercise_id)
            elif cmd == "build-env":
                data = await _slab_build_env(client, args.access_key, args.exercise_id)
                print(json.dumps({"code": "00000", "data": data}, ensure_ascii=False, indent=2))
                print("[slab] 环境启动为异步操作，可再查详情确认 isNeedCheck=false 且 endpoints 可用")
                return
            elif cmd == "recover-env":
                data = await _slab_recover_env(client, args.access_key, args.exercise_id)
            elif cmd == "answer":
                inner = _extract_slab_flag(args.flag) or args.flag.strip()
                print(f"[slab] 提交答案 exerciseId={args.exercise_id} "
                      f"flag={inner[:24]}...（原输入: {args.flag[:40]}）")
                data = await _slab_answer(client, args.access_key, args.exercise_id, inner)
                print(f"[slab] 提交结果: isCorrect={data.get('isCorrect')}")
                return
            elif cmd == "notice-list":
                data = await _slab_notice_list(client, args.access_key)
            elif cmd == "notice-detail":
                data = await _slab_notice_detail(client, args.access_key, args.id)
            else:
                raise SystemExit(f"[slab] 未知命令: {cmd}")
        except RuntimeError as exc:
            print(f"[slab] ❌ {exc}")
            return
        print(json.dumps({"code": "00000", "data": data}, ensure_ascii=False, indent=2))


# ── 主入口 ──

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="灵枢 × slab-match CTF Agent 工作台（Web API 版）：领题 → 前端实时看攻击流程 → 提交",
    )
    parser.add_argument(
        "--host", default=SLAB_API_BASE,
        help=f"slab 平台地址（默认 {SLAB_API_BASE}）",
    )
    parser.add_argument(
        "--access-key", default=SLAB_ACCESS_KEY,
        help="slab Agent AccessKey（默认读环境变量 SLAB_ACCESS_KEY）",
    )
    parser.add_argument(
        "--api-url", default=DEFAULT_API_URL,
        help=f"灵枢 Web 后端地址（默认 {DEFAULT_API_URL}）",
    )
    parser.add_argument(
        "--username", default=DEFAULT_USERNAME,
        help=f"Web 登录用户名（默认 {DEFAULT_USERNAME}）",
    )
    parser.add_argument(
        "--password", default=DEFAULT_PASSWORD,
        help="Web 登录密码",
    )
    parser.add_argument(
        "--rounds", type=int, default=1,
        help="要解的题目数量（默认 1）",
    )
    parser.add_argument(
        "--loop", action="store_true",
        help="无限循环领题解题（忽略 --rounds）",
    )
    parser.add_argument(
        "--retries", type=int, default=1,
        help="单题最多解题轮数（最少 1 轮，默认 1；提交错误后可按配置重跑）",
    )
    parser.add_argument(
        "--exercise-id", default="",
        help="直接攻击指定题目（逗号分隔多个 ID，如 1001,1002），处理完即结束（忽略 --rounds/--loop）",
    )
    parser.add_argument(
        "--concurrency", "-c", type=int, default=1,
        help="并发解题数（默认 1；--rounds 为题目总数，按并发分批执行）",
    )
    parser.add_argument(
        "--interactive", "-i", action="store_true",
        help="交互选择题目（列出已开放未解出题，支持多选：编号/逗号/范围）",
    )
    parser.add_argument(
        "--model", "-m", default=DEFAULT_MODEL or None, choices=["Low", "Min", "Max"],
        help="思考级别：Zhipu/GLM 默认 Max，其它 Provider 默认 Min；也可用 SLAB_MODEL_LEVEL 设置",
    )
    parser.add_argument(
        "--provider", "-p", default=DEFAULT_PROVIDER,
        help="模型提供商（默认 zhipu；支持 deepseek、qwen 及 Web 管理中启用的自定义 Provider）",
    )

    # slab-match API 人工调用子命令组
    sub = parser.add_subparsers(dest="slab_command")
    slab = sub.add_parser(
        "slab",
        help="slab-match API 人工调用：python workbench_slab.py slab <cmd>",
        description="逐个调用 slab-match 平台 API（match-info/overview/exercise-list/exercise/"
                    "build-env/recover-env/answer/notice-list/notice-detail）。",
    )
    slab.add_argument(
        "--host", default=SLAB_API_BASE,
        help=f"平台地址（默认 {SLAB_API_BASE}）",
    )
    slab.add_argument(
        "--access-key", default=SLAB_ACCESS_KEY,
        help="Agent AccessKey（默认读环境变量 SLAB_ACCESS_KEY）",
    )
    scmd = slab.add_subparsers(dest="cmd", required=True)
    scmd.add_parser("match-info", help="查询竞赛注意事项和竞赛规则")
    scmd.add_parser("overview", help="查询得分与排名")
    scmd.add_parser("exercise-list", help="查询题目列表")
    p = scmd.add_parser("exercise", help="查询题目详情")
    p.add_argument("--exercise-id", type=int, required=True, help="题目 ID")
    p = scmd.add_parser("build-env", help="启动题目环境（异步，需轮询详情确认就绪）")
    p.add_argument("--exercise-id", type=int, required=True, help="题目 ID")
    p = scmd.add_parser("recover-env", help="回收题目环境")
    p.add_argument("--exercise-id", type=int, required=True, help="题目 ID")
    p = scmd.add_parser("answer", help="提交答案")
    p.add_argument("--exercise-id", type=int, required=True, help="题目 ID")
    p.add_argument("--flag", required=True, help="答案：DASCTF{...}/flag{...} 或花括号内内容")
    scmd.add_parser("notice-list", help="查询公告列表")
    p = scmd.add_parser("notice-detail", help="查询公告详情")
    p.add_argument("--id", type=int, required=True, help="公告 ID")
    return parser


async def main() -> None:
    args = build_parser().parse_args()

    # slab-match API 人工调用
    if getattr(args, "slab_command", None) == "slab":
        await _slab_manual(args)
        return

    # slab-match 自动工作台（默认）
    args.provider = str(args.provider).strip().lower()
    args.model = _resolve_model_level(args.provider, args.model)
    await _slab_workbench_main(args)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[workbench] 用户中断")
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(f"[配置错误] {exc}") from exc
