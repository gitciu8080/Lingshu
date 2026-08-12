#!/usr/bin/env python3
"""NSSCTF Agent Arena 工作台脚本（Web API 版）。

不再直接调用 main.run_mission，而是通过灵枢 Web 后端（api.py 的
FastAPI + SSE）创建会话并消费事件流，从而在前端控制台实时看到
完整的攻击流程（Brain → Orchestrator → Recon → Attack → 提交）。

流程：
  1. NSSCTF API：current → next 领取/复用一道题
  2. 有容器用容器地址作目标，有附件则下载附件，皆无则把题面写成文本
  3. 调用灵枢 Web API：登录 → /api/session/start 创建会话
  4. 订阅 /api/session/{id}/stream 的 SSE，实时打印阶段/Agent/工具事件；
     收到 approval_required 时自动向 /api/session/{id}/message 发送"批准"
  5. 等 mission_end 后从会话详情取 flag，提交到 NSSCTF；解不出则放弃

依赖 Web 后端已启动：
    python api.py          # 默认 0.0.0.0:8080

用法示例:
    python workbench_nss.py
    python workbench_nss.py --rounds 3
    python workbench_nss.py --loop --api-url http://localhost:8080
    python workbench_nss.py --model Max
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

# ── NSSCTF Agent Arena API ──
NSS_API_BASE = "https://www.nssctf.cn/api"

# 默认 Agent Token：优先读环境变量 NSSCTF_AGENT_TOKEN，否则使用此默认值
DEFAULT_TOKEN = "nss_agent_qLvExRxvLtSUIDiRkQToFedw2RZf9OHcZ0b5S8t5lqI"

# ── 灵枢 Web 后端 ──
DEFAULT_API_URL = os.environ.get("LINGSHU_API_URL", "http://localhost:8080")
# 默认 Web 登录账号（auth.py 中创建的用户）
DEFAULT_USERNAME = os.environ.get("LINGSHU_USER", "admin")
DEFAULT_PASSWORD = os.environ.get("LINGSHU_PASS", "admin123")

# 附件 / 题面工作目录
ARENA_WORKDIR = Path(__file__).resolve().parent / "WorkDir" / "arena"
ARENA_WORKDIR.mkdir(parents=True, exist_ok=True)

# 解题相对 TTL 的提前量（秒），避免超时结算前还在跑
TTL_MARGIN = 120


def _mask_token(token: str) -> str:
    """脱敏展示 Token，避免日志泄露完整令牌。"""
    if len(token) <= 12:
        return token[:3] + "****" + token[-3:]
    return token[:6] + "****" + token[-4:]


# ── NSSCTF API 客户端 ──

async def _nss_request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    token: str,
    payload: dict | None = None,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    resp = await client.request(method, f"{NSS_API_BASE}{path}", headers=headers, json=payload)
    resp.raise_for_status()
    body = resp.json()
    if body.get("code") not in (200, None):
        raise RuntimeError(f"NSS API 错误 {body.get('code')}: {body.get('message', body)}")
    return body.get("data", {})


async def _download_annex(
    client: httpx.AsyncClient,
    token: str,
    attempt_id: int,
    annex: dict,
) -> Path:
    annex_url = annex.get("url")
    if not annex_url:
        raise ValueError("附件缺少 url")
    raw_name = annex.get("name") or f"annex_{attempt_id}"
    safe_name = Path(raw_name).name or f"annex_{attempt_id}"
    workdir = ARENA_WORKDIR / f"attempt_{attempt_id}"
    workdir.mkdir(parents=True, exist_ok=True)
    dest = workdir / safe_name

    headers = {"Authorization": f"Bearer {token}"}
    async with client.stream("GET", annex_url, headers=headers) as resp:
        if resp.status_code in (401, 403):
            async with client.stream("GET", annex_url) as resp2:
                resp2.raise_for_status()
                with dest.open("wb") as f:
                    async for chunk in resp2.aiter_bytes():
                        f.write(chunk)
        else:
            resp.raise_for_status()
            with dest.open("wb") as f:
                async for chunk in resp.aiter_bytes():
                    f.write(chunk)
    return dest


async def _poll_container_url(
    client: httpx.AsyncClient,
    token: str,
    attempt_id: int,
    wait_seconds: int = 120,
) -> str | None:
    """等待容器就绪并返回可访问 URL。

    有些题目容器是延迟创建的，领取时 url 可能为空，需要轮询
    attempt 详情直到 container.url 出现。
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    deadline = asyncio.get_event_loop().time() + wait_seconds
    while asyncio.get_event_loop().time() < deadline:
        try:
            resp = await client.get(
                f"{NSS_API_BASE}/skill/agent/arena/attempt/{attempt_id}/",
                headers=headers,
            )
            resp.raise_for_status()
            attempt = resp.json().get("data", {}).get("attempt", {})
            problem = attempt.get("problem") or {}
            container = problem.get("container") or {}
            urls = container.get("url") or []
            if urls:
                return urls[0]
        except Exception as exc:
            print(f"[workbench] 轮询容器状态异常: {exc}")
        await asyncio.sleep(5)
    return None


async def _prepare_target(
    client: httpx.AsyncClient,
    token: str,
    attempt: dict,
) -> tuple[str, str, Path | None]:
    """为题目准备灵枢目标与说明。

    返回 (target, note, annex_path):
      - 有容器: target = 容器地址（host:port 或 URL），note = "container"
      - 有附件: target = 下载后的文件路径，note = "annex"
      - 皆无:   把题面写成文本文件作目标，note = "content"

    对 pwn/网络题目优先使用容器地址，确保 nc/连接目标传给灵枢；
    若领取时容器未就绪则轮询等待，超时才回退附件。
    使用容器时若同时有附件（如 pwn 二进制），也一并下载，
    annex_path 供注入 goal 供 Agent 本地分析。
    """
    problem = attempt.get("problem") or {}
    container = problem.get("container") or {}
    annex = problem.get("annex") or {}
    attempt_id = attempt.get("id", 0)

    container_urls = container.get("url") or []
    container_enabled = problem.get("container_enabled", False)

    # 附件（如 pwn 二进制）通常仍需本地分析，先尝试下载
    annex_path: Path | None = None
    if annex.get("url"):
        try:
            annex_path = await _download_annex(client, token, attempt_id, annex)
        except Exception as exc:
            print(f"[workbench] 附件下载失败（继续）: {exc}")

    if container_urls:
        return container_urls[0], "container", annex_path

    # 题目声明有容器但 url 尚未出现：轮询等待容器就绪
    if container_enabled:
        print(f"[workbench] 容器未就绪，等待分配（attempt {attempt_id}）...")
        url = await _poll_container_url(client, token, attempt_id)
        if url:
            return url, "container", annex_path
        print("[workbench] 等待超时，回退使用附件")

    if annex_path:
        return str(annex_path), "annex", annex_path

    workdir = ARENA_WORKDIR / f"attempt_{attempt_id}"
    workdir.mkdir(parents=True, exist_ok=True)
    txt = workdir / "problem.txt"
    txt.write_text(
        f"题目: {problem.get('title', '')}\n\n{problem.get('content', '')}",
        encoding="utf-8",
    )
    return str(txt), "content", None


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


async def _start_session(
    api_url: str,
    token: str,
    target: str,
    goal: str,
    provider: str,
    model: str,
    nss_context: dict | None = None,
) -> dict:
    """通过 /api/session/start 创建会话，返回 {session_id, ...}。"""
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{api_url}/api/session/start",
            headers=headers,
            json={
                "target": target,
                "goal": goal,
                "provider": provider,
                "model": model,
                "nss_context": nss_context,
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


# ── 单题处理 ──

async def _solve_attempt(
    api_url: str,
    web_token: str,
    nss_client: httpx.AsyncClient,
    nss_token: str,
    attempt: dict,
    provider: str,
    model: str,
    retries: int,
) -> bool:
    attempt_id = attempt.get("id")
    problem = attempt.get("problem") or {}
    remaining = attempt.get("remaining_seconds") or 3600
    timeout = max(120, remaining - TTL_MARGIN)

    print(f"\n{'='*60}")
    print(f"[workbench] 题目 #{attempt_id}: {problem.get('title', '未知')}")
    print(f"[workbench] 类型: {problem.get('type_label', '?')} | "
          f"难度分: {problem.get('rating', '?')} | 剩余: {remaining}s")
    print(f"{'='*60}")

    target, note, annex_path = await _prepare_target(nss_client, nss_token, attempt)
    print(f"[workbench] 目标来源: {note} | 目标: {target}")
    if annex_path:
        print(f"[workbench] 附件: {annex_path}")

    # 目标描述：容器（nc/pwn 连接地址）+ 附件（本地二进制分析）
    goal = f"获取 Flag\n\n【题目】{problem.get('content', '')}"
    if note == "container":
        goal += f"\n\n【远程目标】{target}（可用 nc 连接/HTTP 访问）"
    if annex_path:
        goal += f"\n\n【本地附件】{annex_path}（pwn/逆向类可结合本地文件分析）"

    nss_context = {
        "attempt_id": attempt_id,
        "token": nss_token,
        "api_base": NSS_API_BASE,
    }

    for run_idx in range(max(1, retries)):
        print(f"\n[workbench] 解题第 {run_idx + 1} 轮...")
        # 创建 Web 会话（携带 nss_context，使 Orchestrator 可在线提交 Flag）
        try:
            start = await _start_session(
                api_url, web_token, target, goal, provider, model,
                nss_context=nss_context,
            )
        except Exception as exc:
            print(f"[workbench] 创建 Web 会话失败: {exc}")
            if "401" in str(exc):
                print("[workbench] 请检查 --username/--password 或后端 JWT 配置")
            break
        session_id = start.get("session_id")
        if not session_id:
            print(f"[workbench] 未返回 session_id: {start}")
            break

        # 订阅 SSE，实时展示攻击流程 + 自动批准
        mission_flag: str | None = None
        mission_success: bool | None = None
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
                elif etype == "nss_submit":
                    sub_ok = event.get("correct")
                    print(f"[Web:{session_id}] 🎌 NSSCTF 提交: flag={event.get('flag')} "
                          f"{'✅正确' if sub_ok else '❌错误'} "
                          f"剩余错误次数={event.get('remaining_wrong_attempts')}")
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

        # 从会话详情补齐 flag 与提交结果（SSE 可能提前断线）
        try:
            detail = await _get_session_detail(api_url, web_token, session_id)
        except Exception:
            detail = {}
        mission_state = detail.get("mission_state") or {}
        nss_submit = mission_state.get("nss_submit")
        if not mission_flag:
            mission_flag = detail.get("flag") or (detail.get("target_info") or {}).get("flag")
        if mission_success is None:
            mission_success = detail.get("success")
        if not mission_phase or mission_phase == "unknown":
            mission_phase = detail.get("phase") or "unknown"

        print(f"\n[workbench] Web 会话结束: 阶段={mission_phase} success={mission_success}")

        # Orchestrator 已在线提交并判定正确 → 直接成功，不再重复提交
        if nss_submit and nss_submit.get("correct"):
            print(f"[workbench] ✅ Orchestrator 已提交正确 Flag: {nss_submit.get('flag')}")
            return True

        flag = (mission_flag or "").strip()
        if flag:
            # Orchestrator 已提交过同一错误 flag → 避免重复消耗错误次数
            if nss_submit and nss_submit.get("flag") == flag and not nss_submit.get("correct"):
                print(f"[workbench] ⏭ Orchestrator 已判定该 flag 错误，跳过重复提交: {flag[:16]}...")
            else:
                print(f"[workbench] 提交 flag: {flag[:16]}...")
                try:
                    data = await _nss_request(
                        nss_client, "POST",
                        f"/skill/agent/arena/attempt/{attempt_id}/submit/",
                        nss_token, {"flag": flag},
                    )
                except Exception as exc:
                    print(f"[workbench] 提交失败: {exc}")
                    break
                if data.get("correct"):
                    print(f"[workbench] ✅ Flag 正确！"
                          f"剩余错误次数: {data.get('remaining_wrong_attempts', '?')}")
                    return True
                print(f"[workbench] ❌ Flag 错误。"
                      f"剩余错误次数: {data.get('remaining_wrong_attempts', '?')}")
            # 重试时通过 goal 追加提示，避免重复提交同一 flag
            goal = (
                f"获取 Flag\n\n【题目】{problem.get('content', '')}\n\n"
                f"【提示】上一次提交 flag『{flag}』被判为错误，请换思路重新分析。"
            )
            continue

        if not mission_success:
            print("[workbench] 任务未成功，未能捕获 flag")
        else:
            print("[workbench] 任务标记成功但未捕获 flag")

    # 多次尝试仍未解出：主动放弃
    print("[workbench] 未能解出，主动放弃本题")
    try:
        await _nss_request(nss_client, "POST", f"/skill/agent/arena/attempt/{attempt_id}/abandon/", nss_token)
        print("[workbench] 已提交放弃")
    except Exception as exc:
        print(f"[workbench] 放弃请求失败: {exc}")
    return False


async def _play_round(
    api_url: str,
    web_token: str,
    nss_client: httpx.AsyncClient,
    nss_token: str,
    provider: str,
    model: str,
    retries: int,
) -> bool | None:
    """领取/复用一道题并处理。返回 True 解出 / False 未解出 / None 无题。"""
    headers = {"Authorization": f"Bearer {nss_token}", "Content-Type": "application/json"}
    try:
        resp = await nss_client.get(f"{NSS_API_BASE}/skill/agent/arena/current/", headers=headers)
        resp.raise_for_status()
        data = resp.json().get("data", {})
    except Exception as exc:
        print(f"[workbench] 查询当前题目失败: {exc}")
        return None

    attempt = data.get("attempt")
    state = (attempt or {}).get("state_label", "active")
    if attempt is None or state != "active":
        try:
            resp = await nss_client.post(f"{NSS_API_BASE}/skill/agent/arena/next/", headers=headers)
            resp.raise_for_status()
            data = resp.json().get("data", {})
        except Exception as exc:
            print(f"[workbench] 领取题目失败: {exc}")
            return None
        attempt = data.get("attempt")
        state = (attempt or {}).get("state_label", "active")
        if attempt is None or state != "active":
            print("[workbench] 当前无进行中 / 可领取的题目")
            return None

    print(f"[workbench] 当前题目状态: {state} (reused={data.get('reused', False)})")
    return await _solve_attempt(
        api_url, web_token, nss_client, nss_token,
        attempt, provider, model, retries,
    )


# ── 主入口 ──

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="灵枢 × NSSCTF Agent Arena 工作台（Web API 版）：领题 → 前端实时看攻击流程 → 提交",
    )
    parser.add_argument(
        "--token", default="",
        help="NSSCTF Agent Token（默认读环境变量 NSSCTF_AGENT_TOKEN，其次用内置默认值）",
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
        help="单题最多解题轮数（提交错误 flag 后带提示重跑，默认 1）",
    )
    parser.add_argument(
        "--model", "-m", default="Min", choices=["Low", "Min", "Max"],
        help="思考级别：Low(快速) / Min(默认) / Max(深度推理)",
    )
    parser.add_argument(
        "--provider", "-p", default="deepseek", choices=["deepseek", "qwen"],
        help="模型提供商（deepseek 或 qwen）",
    )
    return parser


async def main() -> None:
    args = build_parser().parse_args()
    nss_token = args.token or os.environ.get("NSSCTF_AGENT_TOKEN") or DEFAULT_TOKEN
    print(f"[workbench] NSSCTF Agent Token: {_mask_token(nss_token)}")
    print(f"[workbench] 灵枢 Web API: {args.api_url} | 模型: {args.provider}/{args.model}")

    # 登录灵枢 Web 后端
    try:
        web_token = await _login(args.api_url, args.username, args.password)
    except Exception as exc:
        raise SystemExit(f"[配置错误] 登录灵枢 Web 后端失败: {exc}") from exc
    print(f"[workbench] 已登录 Web 后端（用户: {args.username}）")

    solved = 0
    failed = 0
    round_i = 0
    timeout_cfg = httpx.Timeout(180.0, connect=30.0)
    async with httpx.AsyncClient(timeout=timeout_cfg) as nss_client:
        while args.loop or round_i < args.rounds:
            round_i += 1
            label = f"第 {round_i} 轮" if args.loop else f"第 {round_i}/{args.rounds} 轮"
            print(f"\n===== {label} =====")
            outcome = await _play_round(
                args.api_url, web_token, nss_client, nss_token,
                args.provider, args.model, args.retries,
            )
            if outcome is None:
                break
            if outcome:
                solved += 1
            else:
                failed += 1

    print(f"\n[workbench] 完成 {round_i} 轮: 解出 {solved} 题，未解出 {failed} 题")
    if args.loop and round_i == 0:
        print("[workbench] 无题目可处理")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[workbench] 用户中断")
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(f"[配置错误] {exc}") from exc
