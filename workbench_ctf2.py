#!/usr/bin/env python3
"""灵枢 × CTF2 Practice 工作台（Web API 版）。

通过 CTF2 User Open API 在当前用户授权范围内：选择练习题、启动/复用环境、
下载附件，再经灵枢 Web + SSE 调度多 Agent 解题。

CTF2 平台要求提交 Flag 前必须确认“题目 + 精确 Flag”。因此本脚本不会猜测性
自动提交：Agent 发现候选后会打印 ``--confirm-flag`` 命令；只有该参数与本轮
候选完全一致才会调用 CTF2 submit API（confirmation=true）。

示例：
    export CTF2_API_TOKEN='...'
    python workbench_ctf2.py --list
    python workbench_ctf2.py --practice-id <UUID> --challenge-id <UUID>
    python workbench_ctf2.py --practice-id <UUID> --challenge-id <UUID> \\
        --confirm-flag 'flag{confirmed_value}'
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, AsyncIterator

import httpx


CTF2_API_BASE = "https://ctf2.dasctf.com/api/open/v1/user"
DEFAULT_API_URL = os.environ.get("LINGSHU_API_URL", "http://localhost:8080")
DEFAULT_USERNAME = os.environ.get("LINGSHU_USER", "admin")
DEFAULT_PASSWORD = os.environ.get("LINGSHU_PASS", "gdcp@2026")
DEFAULT_PROVIDER = os.environ.get("CTF2_LLM_PROVIDER", "deepseek").strip().lower() or "deepseek"
DEFAULT_MODEL = os.environ.get("CTF2_MODEL_LEVEL", "").strip()
WORKDIR = Path(__file__).resolve().parent / "WorkDir" / "ctf2"
WORKDIR.mkdir(parents=True, exist_ok=True)

# 平台题目的 Flag 前缀未在 OpenAPI 中限定；只提取一对花括号内、无换行的候选。
FLAG_PATTERN = re.compile(r"(?:[A-Za-z][A-Za-z0-9_-]{0,31})\{[^{}\r\n]{1,4096}\}")


def _mask_secret(value: str) -> str:
    if len(value) <= 10:
        return value[:2] + "****"
    return value[:5] + "****" + value[-3:]


def _model_level(provider: str, requested: str | None) -> str:
    if requested:
        if requested not in {"Low", "Min", "Max"}:
            raise ValueError("推理强度仅支持 Low、Min、Max")
        return requested
    return "Max" if provider == "zhipu" else "Min"


def _items(body: dict[str, Any]) -> list[dict[str, Any]]:
    data = body.get("data") or {}
    value = data.get("items") if isinstance(data, dict) else []
    return [item for item in value or [] if isinstance(item, dict)]


def _id(value: dict[str, Any]) -> str:
    return str(value.get("id") or value.get("uuid") or "").strip()


def _challenge_files(challenge: dict[str, Any]) -> list[dict[str, Any]]:
    """兼容 CTF2 challenge 返回中的 files / attachments 字段。"""
    files: list[dict[str, Any]] = []
    for key in ("files", "attachments", "attachment_files"):
        value = challenge.get(key)
        if isinstance(value, list):
            files.extend(item for item in value if isinstance(item, dict) and _id(item))
    return list({ _id(item): item for item in files }.values())


def _challenge_text(challenge: dict[str, Any]) -> str:
    return str(
        challenge.get("content") or challenge.get("description") or challenge.get("body") or ""
    ).strip()


def _auto_challenge(grounds: list[dict[str, Any]]) -> tuple[str, str, str] | None:
    """从 Practice 列表中选择首个可见 challenge；兼容常见的嵌套字段。"""
    for ground in grounds:
        practice_id = _id(ground)
        if not practice_id:
            continue
        for key in ("challenges", "items", "problems"):
            candidates = ground.get(key)
            if not isinstance(candidates, list):
                continue
            for challenge in candidates:
                if not isinstance(challenge, dict) or not _id(challenge):
                    continue
                status = str(challenge.get("status") or challenge.get("state") or "").lower()
                if status in {"disabled", "hidden", "closed"}:
                    continue
                return practice_id, _id(challenge), str(
                    challenge.get("title") or challenge.get("name") or _id(challenge),
                )
    return None


async def _ctf2_request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    token: str,
    *,
    payload: dict[str, Any] | None = None,
    retry_429: bool = True,
) -> dict[str, Any]:
    """调用 CTF2 Open API；429 时仅按 Retry-After 等待并重试一次。"""
    headers = {"X-CTF2-API-Key": token, "Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    response = await client.request(method, f"{CTF2_API_BASE}{path}", headers=headers, json=payload)
    if response.status_code == 429 and retry_429:
        wait = max(1, min(60, int(response.headers.get("Retry-After", "1") or "1")))
        print(f"[ctf2] 触发限流，等待 {wait}s 后重试一次")
        await asyncio.sleep(wait)
        return await _ctf2_request(client, method, path, token, payload=payload, retry_429=False)
    if response.status_code in {401, 403}:
        try:
            error = response.json().get("error", {})
        except Exception:  # noqa: BLE001
            error = {}
        raise PermissionError(
            f"CTF2 权限请求失败 HTTP {response.status_code}: "
            f"{error.get('code', 'unknown')} / {error.get('key', 'unknown')}",
        )
    response.raise_for_status()
    body = response.json()
    if body.get("success") is False:
        raise RuntimeError(f"CTF2 API 错误: {body.get('error', body)}")
    return body


async def _download_file(
    client: httpx.AsyncClient,
    token: str,
    practice_id: str,
    challenge_id: str,
    file_info: dict[str, Any],
    destination: Path,
) -> Path:
    file_id = _id(file_info)
    raw_name = str(file_info.get("name") or file_info.get("filename") or file_id)
    target = destination / Path(raw_name).name
    headers = {"X-CTF2-API-Key": token}
    url = f"{CTF2_API_BASE}/practice/{practice_id}/challenges/{challenge_id}/files/{file_id}/"
    async with client.stream("GET", url, headers=headers) as response:
        response.raise_for_status()
        with target.open("wb") as output:
            async for chunk in response.aiter_bytes():
                output.write(chunk)
    return target


async def _login(api_url: str, username: str, password: str) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{api_url}/auth/login", json={"username": username, "password": password},
        )
        response.raise_for_status()
        return str(response.json()["access_token"])


async def _enabled_providers(api_url: str, web_token: str) -> set[str]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{api_url}/api/model-providers", headers={"Authorization": f"Bearer {web_token}"},
        )
        response.raise_for_status()
        return {
            str(item.get("id") or "").strip().lower()
            for item in response.json().get("providers", [])
            if str(item.get("id") or "").strip()
        }


async def _start_lingshu_session(
    api_url: str, web_token: str, *, target: str, goal: str, provider: str, model: str,
) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{api_url}/api/session/start",
            headers={"Authorization": f"Bearer {web_token}"},
            json={"target": target, "goal": goal, "provider": provider, "model": model},
        )
        response.raise_for_status()
        return response.json()


async def _get_session(api_url: str, web_token: str, session_id: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{api_url}/api/session/{session_id}", headers={"Authorization": f"Bearer {web_token}"},
        )
        response.raise_for_status()
        return response.json()


async def _send_message(api_url: str, web_token: str, session_id: str, content: str) -> None:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{api_url}/api/session/{session_id}/message",
            headers={"Authorization": f"Bearer {web_token}"}, json={"content": content},
        )
        response.raise_for_status()


async def _stream(
    api_url: str, web_token: str, session_id: str, timeout: int,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    headers = {"Authorization": f"Bearer {web_token}", "Accept": "text/event-stream"}
    deadline = asyncio.get_running_loop().time() + timeout
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout + 30, connect=30)) as client:
        async with client.stream("GET", f"{api_url}/api/session/{session_id}/stream", headers=headers) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if asyncio.get_running_loop().time() >= deadline:
                    return
                if not line.startswith("data:"):
                    continue
                try:
                    event = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
                yield str(event.get("type") or ""), event


def _extract_flag(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = FLAG_PATTERN.search(value)
    return match.group(0) if match else None


async def _run_agent(
    args: argparse.Namespace,
    web_token: str,
    challenge: dict[str, Any],
    access_url: str,
    attachments: list[Path],
) -> str | None:
    title = str(challenge.get("title") or challenge.get("name") or args.challenge_id)
    goal = (
        "获取 CTF2 Practice Flag。\n\n"
        "【授权范围】仅测试本题启动后提供的环境地址及本地附件；不得扩展到其他目标。\n"
        "【提交约束】仅输出已验证的精确 Flag；不要调用外部平台提交接口，"
        "工作台将在获得操作者对精确 Flag 的确认后提交。\n\n"
        f"【CTF2 Practice】{title}\n【题目】{_challenge_text(challenge)}\n"
        f"【远程环境】{access_url}"
    )
    if attachments:
        goal += "\n【本地附件】" + "、".join(str(path) for path in attachments)

    session = await _start_lingshu_session(
        args.api_url, web_token, target=access_url, goal=goal,
        provider=args.provider, model=args.model,
    )
    session_id = str(session.get("session_id") or "")
    if not session_id:
        raise RuntimeError(f"灵枢未返回 session_id: {session}")
    print(f"[workbench] 灵枢会话 {session_id} 已启动")

    flag: str | None = None
    approved = False
    try:
        async for event_type, event in _stream(args.api_url, web_token, session_id, args.timeout):
            agent = str(event.get("agent") or "system")
            if event_type == "phase_change":
                print(f"[Web:{session_id}] 阶段 → {event.get('phase')}")
            elif event_type in {"text_delta", "thinking_delta"}:
                print(event.get("delta") or event.get("content") or "", end="", flush=True)
            elif event_type in {"text_end", "thinking_end"}:
                print()
            elif event_type == "tool_call_start":
                print(f"[Web:{session_id}] 🔧 {agent}: {event.get('tool_name')}")
            elif event_type == "approval_required" and not approved:
                # 用户已在本次命令明确要求对其选择的 CTF2 题目进行解题与环境验证。
                await _send_message(args.api_url, web_token, session_id, "批准")
                approved = True
                print(f"[Web:{session_id}] 已批准灵枢的利用验证阶段")
            elif event_type == "flag_found":
                flag = _extract_flag(event.get("flag") or event.get("content")) or flag
                if flag:
                    print(f"[Web:{session_id}] 候选 Flag: {flag}")
            elif event_type == "mission_end":
                print(f"[Web:{session_id}] 任务结束: {event.get('status')}")
                break
            elif event_type == "error":
                print(f"[Web:{session_id}] 错误: {event.get('message')}", file=sys.stderr)
    finally:
        detail = await _get_session(args.api_url, web_token, session_id)
        flag = flag or _extract_flag(detail.get("flag"))
        flag = flag or _extract_flag((detail.get("target_info") or {}).get("flag"))
    return flag


async def _submit_confirmed_flag(
    client: httpx.AsyncClient, token: str, practice_id: str, challenge_id: str, flag: str,
) -> bool:
    body = await _ctf2_request(
        client, "POST", f"/practice/{practice_id}/challenges/{challenge_id}/submit/", token,
        payload={"flag": flag, "confirmation": True},
    )
    data = body.get("data") or {}
    accepted = bool(data.get("accepted"))
    print(f"[ctf2] 提交结果: {'✅ 正确' if accepted else '❌ 未通过'} | attempt={data.get('attempt', '?')}")
    return accepted


async def main() -> None:
    args = build_parser().parse_args()
    args.provider = str(args.provider).strip().lower()
    args.model = _model_level(args.provider, args.model)
    token = args.token or os.environ.get("CTF2_API_TOKEN", "")
    if not token:
        raise SystemExit("缺少 CTF2 凭据：使用 --token 或环境变量 CTF2_API_TOKEN（不会持久化）。")

    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as ctf2:
        grounds: list[dict[str, Any]] = []
        if args.list or args.auto:
            grounds = _items(await _ctf2_request(ctf2, "GET", "/practice/?limit=100", token))
        if args.list:
            for ground in grounds:
                print(f"{_id(ground)}\t{ground.get('title') or ground.get('name') or '未命名'}")
            return
        if args.auto:
            selected = _auto_challenge(grounds)
            if selected is None:
                raise SystemExit(
                    "Practice 列表未提供可自动选择的 challenge ID；"
                    "请使用 --practice-id 和 --challenge-id 明确选择。",
                )
            args.practice_id, args.challenge_id, title = selected
            print(f"[ctf2] 自动选择题目: {title} ({args.practice_id}/{args.challenge_id})")
        if not args.practice_id or not args.challenge_id:
            raise SystemExit("需要 --practice-id 和 --challenge-id；可先运行 --list 查看练习场。")

        challenge_body = await _ctf2_request(
            ctf2, "GET", f"/practice/{args.practice_id}/challenges/{args.challenge_id}/", token,
        )
        challenge = (challenge_body.get("data") or {}).get("challenge") or (challenge_body.get("data") or {})
        if not isinstance(challenge, dict):
            raise RuntimeError("CTF2 未返回有效 challenge 对象")
        title = str(challenge.get("title") or challenge.get("name") or args.challenge_id)
        print(f"[ctf2] 题目: {title}")

        environment = await _ctf2_request(
            ctf2, "POST", f"/practice/{args.practice_id}/challenges/{args.challenge_id}/environment/start/", token,
            payload={},
        )
        env = environment.get("data") or {}
        for _ in range(args.environment_polls):
            if env.get("access_ready"):
                break
            await asyncio.sleep(args.environment_poll_interval)
            environment = await _ctf2_request(
                ctf2, "POST", f"/practice/{args.practice_id}/challenges/{args.challenge_id}/environment/start/", token,
                payload={},
            )
            env = environment.get("data") or {}
        access_url = str(env.get("access_url") or "")
        if not access_url:
            urls = env.get("access_urls") or []
            if urls and isinstance(urls[0], dict):
                access_url = str(urls[0].get("url") or "")
        if not access_url:
            raise RuntimeError(f"环境尚未就绪: status={env.get('status')}；请稍后重试")
        print(f"[ctf2] 环境已就绪: {access_url}")

        destination = WORKDIR / args.challenge_id
        destination.mkdir(parents=True, exist_ok=True)
        attachments = [
            await _download_file(ctf2, token, args.practice_id, args.challenge_id, info, destination)
            for info in _challenge_files(challenge)
        ]
        for path in attachments:
            print(f"[ctf2] 已下载附件: {path}")

        if args.confirm_flag:
            # --confirm-flag 本身就是操作者对“本题 + 精确值”的明确确认。
            await _submit_confirmed_flag(ctf2, token, args.practice_id, args.challenge_id, args.confirm_flag)
            return

        web_token = await _login(args.api_url, args.username, args.password)
        enabled = await _enabled_providers(args.api_url, web_token)
        if args.provider not in enabled:
            raise SystemExit(f"Provider '{args.provider}' 未启用；可用：{'、'.join(sorted(enabled)) or '无'}")
        candidate = await _run_agent(args, web_token, challenge, access_url, attachments)
        if candidate:
            print("\n[ctf2] 已验证候选（尚未提交）。确认后执行：")
            print(
                f"python workbench_ctf2.py --practice-id {args.practice_id} "
                f"--challenge-id {args.challenge_id} --confirm-flag {candidate!r}",
            )
        else:
            print("[ctf2] 灵枢未返回可识别 Flag，本轮未提交。")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="灵枢 × CTF2 Practice 工作台")
    parser.add_argument("--token", help="CTF2 PAT（或使用环境变量 CTF2_API_TOKEN；不会写入文件）")
    parser.add_argument("--list", action="store_true", help="列出可见 Practice 场地（只读）")
    parser.add_argument("--auto", action="store_true", help="从 Practice 列表自动选择首个可见题目")
    parser.add_argument("--practice-id", help="CTF2 Practice ground UUID")
    parser.add_argument("--challenge-id", help="CTF2 challenge UUID")
    parser.add_argument("--confirm-flag", help="确认提交的精确 Flag；仅此模式会提交到 CTF2")
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--provider", "-p", default=DEFAULT_PROVIDER)
    parser.add_argument("--model", "-m", default=DEFAULT_MODEL or None, choices=["Low", "Min", "Max"])
    parser.add_argument("--timeout", type=int, default=1800, help="单次灵枢会话观察秒数")
    parser.add_argument("--environment-polls", type=int, default=24, help="环境就绪轮询上限")
    parser.add_argument("--environment-poll-interval", type=int, default=5, help="环境轮询间隔秒数")
    return parser


if __name__ == "__main__":
    asyncio.run(main())
