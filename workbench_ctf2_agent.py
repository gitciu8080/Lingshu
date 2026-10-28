#!/usr/bin/env python3
"""灵枢 × CTF2 Agent 竞技场工作台。

基于 CTF2 Agent Skill（Open API，Agent 凭据）实现的三种使用方式：

1. 交互工作台（默认，无参数）——命令式工作台：status / list / solve / watch / auto / note / submit；
2. 脚本化单题：``solve <challenge-id> --mode fast|standard``；
3. 全自动循环：``auto``——自动选题（Agent 推荐 easiest/most-solved first）→ 启动环境 →
   灵枢解题 → 自动提交精确 Flag → 成功销毁环境并选择下一题。

凭据（均通过环境变量，不落盘）：
    CTF2_API_TOKEN     CTF2 Agent PAT（Agent 竞技场签发）
    LINGSHU_API_URL    灵枢 Web 地址（默认 http://localhost:8080）
    LINGSHU_USER/_PASS 灵枢登录账户（工作台以该用户身份创建会话）
    CTF2_LLM_PROVIDER  灵枢模型供应商运行时键（默认 deepseek）
    CTF2_MODEL_LEVEL   Low|Min|Max（默认 Min）
    CTF2_MODE          默认解题模式（fast|standard，默认 fast）

合规约束（与 CTF2 Agent Skill 一致）：
    - 只玩 Agent 有权限的公开练习题与对 Agent 开放的竞赛；
    - 不爆破 Flag、不攻击平台与他人环境；
    - 每题仅在提取到精确 Flag 后提交一次（confirmation=true）；
    - 解题过程以 plan/finding/result 笔记记录（构建 Agent 解题回放）。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shlex
import sys
import time
from pathlib import Path
from typing import Any, AsyncIterator

import httpx

try:  # 控制台渲染增强（可选）
    from rich.console import Console
    from rich.table import Table as RichTable

    _RICH = Console()
except Exception:  # noqa: BLE001
    _RICH = None

CTF2_API_BASE = os.environ.get("CTF2_API_BASE", "https://ctf2.dasctf.com/api/open/v1/user")
DEFAULT_API_URL = os.environ.get("LINGSHU_API_URL", "http://localhost:8080")
DEFAULT_USERNAME = os.environ.get("LINGSHU_USER", "admin")
DEFAULT_PASSWORD = os.environ.get("LINGSHU_PASS", "gdcp@2026")
DEFAULT_PROVIDER = os.environ.get("CTF2_LLM_PROVIDER", "deepseek").strip().lower() or "deepseek"
DEFAULT_MODEL = os.environ.get("CTF2_MODEL_LEVEL", "Min").strip() or "Min"
DEFAULT_MODE = os.environ.get("CTF2_MODE", "fast").strip().lower() or "fast"
WORKDIR = Path(__file__).resolve().parent / "WorkDir" / "ctf2-agent"
WORKDIR.mkdir(parents=True, exist_ok=True)

FLAG_PATTERN = re.compile(r"(?:[A-Za-z][A-Za-z0-9_-]{0,31})\{[^{}\r\n]{1,4096}\}")
PLAN_STATUSES = ("pending", "in_progress", "completed", "failed", "skipped")


def out(*args: Any) -> None:
    """统一输出（rich 可用时走 rich，保持表格对齐）；flush 保证 nohup 日志实时可见。"""
    if _RICH is not None and len(args) == 1 and isinstance(args[0], str) and "\n" in args[0]:
        _RICH.print(args[0])
    else:
        print(*args, flush=True)


def out_table(title: str, columns: list[str], rows: list[list[Any]]) -> None:
    if _RICH is not None:
        table = RichTable(title=title, header_style="bold cyan")
        for col in columns:
            table.add_column(col, overflow="fold")
        for row in rows:
            table.add_row(*[str(c) for c in row])
        _RICH.print(table)
        return
    widths = [max(len(str(col)), *(len(str(r[i])) for r in rows)) if rows else len(str(col))
              for i, col in enumerate(columns)]
    out(title)
    out("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(columns)))
    out("  ".join("-" * w for w in widths))
    for row in rows:
        out("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))


# ────────────────────────────────────────────────────────────────
# CTF2 Agent Open API 客户端
# ────────────────────────────────────────────────────────────────

class CTF2Error(RuntimeError):
    """平台返回的结构化错误（code/message/retryable/retry_after_ms/hint）。"""

    def __init__(self, payload: dict[str, Any]):
        self.code = str(payload.get("code") or "unknown")
        self.message = str(payload.get("message") or "")
        self.retryable = bool(payload.get("retryable"))
        self.retry_after_ms = int(payload.get("retry_after_ms") or 0)
        self.hint = str(payload.get("hint") or "")
        super().__init__(f"[{self.code}] {self.message or self.hint}")


class CTF2Client:
    """CTF2 Agent Open API：X-CTF2-API-Key 认证；429/可重试错误自动等待重试。"""

    def __init__(self, token: str, base: str = CTF2_API_BASE, timeout: float = 60.0):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def _headers(self, token: str) -> dict[str, str]:
        return {"X-CTF2-API-Key": token, "Accept": "application/json"}

    async def request(
        self, client: httpx.AsyncClient, method: str, path: str, token: str,
        payload: dict[str, Any] | None = None, *, retries: int = 3,
    ) -> dict[str, Any]:
        headers = self._headers(token)
        if payload is not None:
            headers["Content-Type"] = "application/json"
        response = await client.request(
            method, f"{self.base}{path}", headers=headers, json=payload)
        if response.status_code == 429 and retries > 0:
            wait = max(1, min(60, int(response.headers.get("Retry-After", "2") or "2")))
            out(f"[ctf2] 限流，等待 {wait}s 重试")
            await asyncio.sleep(wait)
            return await self.request(client, method, path, token, payload, retries - 1)
        if response.status_code in {401, 403}:
            raise PermissionError(
                f"CTF2 认证/授权失败 HTTP {response.status_code}：检查 CTF2_API_TOKEN 是否为 Agent 凭据")
        if response.status_code >= 400:
            try:
                body = response.json()
                error = body.get("error") if isinstance(body.get("error"), dict) else (
                    body.get("data") if isinstance(body.get("data"), dict)
                    and body["data"].get("code") else None)
                if error and error.get("code"):
                    raise CTF2Error(error)
            except ValueError:  # noqa: BLE001 — 非 JSON 响应体
                pass
            response.raise_for_status()
        body = response.json()
        if body.get("success") is False or (isinstance(body.get("error"), dict) and body["error"]):
            error = body.get("error") or body
            if isinstance(error, dict) and error.get("code"):
                raise CTF2Error(error)
            raise RuntimeError(f"CTF2 API 错误: {body}")
        data = body.get("data")
        if isinstance(data, dict) and data.get("code") and data.get("retryable") is not None:
            raise CTF2Error(data)   # 部分端点把错误放 data 内
        return body

    # ── Agent 元信息 ──
    async def whoami(self, client: httpx.AsyncClient, token: str) -> dict[str, Any]:
        return (await self.request(client, "GET", "/agent/me/", token)).get("data") or {}

    async def next_challenges(
        self, client: httpx.AsyncClient, token: str, *, source: str = "all",
        category: str = "", difficulty: str = "", limit: int = 50,
    ) -> list[dict[str, Any]]:
        query = f"?source={source}&limit={min(100, max(1, limit))}"
        if category:
            query += f"&category={category}"
        if difficulty:
            query += f"&difficulty={difficulty}"
        body = await self.request(client, "GET", f"/agent/next-challenges/{query}", token)
        return [item for item in (body.get("data") or {}).get("items") or [] if isinstance(item, dict)]

    async def log_note(
        self, client: httpx.AsyncClient, token: str, challenge_id: str,
        kind: str, content: str,
    ) -> bool:
        """记录 plan/finding/result 笔记；失败（如竞赛题不允许）仅告警。"""
        try:
            await self.request(client, "POST", "/agent/notes/", token, payload={
                "challenge_id": challenge_id, "kind": kind,
                "content": content[:2000],
            })
            return True
        except (CTF2Error, httpx.HTTPError) as exc:
            out(f"[ctf2] 笔记记录失败（忽略）: {exc}")
            return False

    # ── Practice ──
    async def practice_grounds(self, client: httpx.AsyncClient, token: str) -> list[dict[str, Any]]:
        body = await self.request(client, "GET", "/practice/?limit=100", token)
        data = body.get("data") or {}
        return [g for g in (data.get("items") if isinstance(data, dict) else data) or []
                if isinstance(g, dict)]

    async def practice_challenges(
        self, client: httpx.AsyncClient, token: str, practice_id: str,
        *, unsolved_only: bool = False, page: int = 1,
    ) -> list[dict[str, Any]]:
        query = f"?limit=100&page={max(1, int(page))}"
        if unsolved_only:
            query += "&unsolved_only=true"
        body = await self.request(
            client, "GET", f"/practice/{practice_id}/challenges/{query}", token)
        data = body.get("data") or {}
        value = data.get("items") if isinstance(data, dict) else data
        if value is None and isinstance(data, dict):
            value = data.get("challenges")
        return [c for c in value or [] if isinstance(c, dict)]

    async def practice_challenge(
        self, client: httpx.AsyncClient, token: str, practice_id: str, challenge_id: str,
    ) -> dict[str, Any]:
        body = await self.request(
            client, "GET", f"/practice/{practice_id}/challenges/{challenge_id}/", token)
        data = body.get("data") or {}
        challenge = data.get("challenge") if isinstance(data, dict) else None
        return challenge if isinstance(challenge, dict) else data

    async def start_environment(
        self, client: httpx.AsyncClient, token: str, practice_id: str, challenge_id: str,
    ) -> dict[str, Any]:
        body = await self.request(
            client, "POST",
            f"/practice/{practice_id}/challenges/{challenge_id}/environment/start/",
            token, payload={},
        )
        return body.get("data") or {}

    async def get_environment(
        self, client: httpx.AsyncClient, token: str, practice_id: str, challenge_id: str,
    ) -> dict[str, Any]:
        body = await self.request(
            client, "GET",
            f"/practice/{practice_id}/challenges/{challenge_id}/environment/", token)
        return body.get("data") or {}

    async def destroy_environment(
        self, client: httpx.AsyncClient, token: str, practice_id: str, challenge_id: str,
    ) -> None:
        # 销毁失败会占死环境配额（max_environments 默认 1），瞬时错误多试一次
        last: Exception | None = None
        for _ in range(2):
            try:
                await self.request(
                    client, "DELETE",
                    f"/practice/{practice_id}/challenges/{challenge_id}/environment/", token)
                return
            except (httpx.HTTPError, CTF2Error) as exc:
                last = exc
                await asyncio.sleep(3)
        out(f"[ctf2] 环境销毁失败（忽略）: {last}")

    async def attachment_url(
        self, client: httpx.AsyncClient, token: str, practice_id: str,
        challenge_id: str, file_id: str,
    ) -> str:
        body = await self.request(
            client, "GET",
            f"/practice/{practice_id}/challenges/{challenge_id}/files/{file_id}/download/",
            token)
        data = body.get("data") or {}
        return str(data.get("url") or data.get("download_url") or "")

    async def submit_flag(
        self, client: httpx.AsyncClient, token: str, practice_id: str,
        challenge_id: str, flag: str,
    ) -> dict[str, Any]:
        body = await self.request(
            client, "POST",
            f"/practice/{practice_id}/challenges/{challenge_id}/submit/",
            token, payload={"flag": flag, "confirmation": True},
        )
        return body.get("data") or {}

    # ── Competition（Agent 竞赛）──
    async def competition_challenge(
        self, client: httpx.AsyncClient, token: str,
        competition_id: str, stage_id: str, challenge_id: str,
    ) -> dict[str, Any]:
        body = await self.request(
            client, "GET",
            f"/agent/competitions/{competition_id}/stages/{stage_id}/challenges/{challenge_id}/",
            token)
        data = body.get("data") or {}
        return data.get("challenge") if isinstance(data.get("challenge"), dict) else data

    async def start_competition_environment(
        self, client: httpx.AsyncClient, token: str,
        competition_id: str, stage_id: str, challenge_id: str,
    ) -> dict[str, Any]:
        body = await self.request(
            client, "POST",
            f"/agent/competitions/{competition_id}/stages/{stage_id}/challenges/"
            f"{challenge_id}/environment/start/", token, payload={},
        )
        return body.get("data") or {}

    async def submit_competition_flag(
        self, client: httpx.AsyncClient, token: str, competition_id: str,
        stage_id: str, challenge_id: str, flag: str,
    ) -> dict[str, Any]:
        body = await self.request(
            client, "POST",
            f"/agent/competitions/{competition_id}/stages/{stage_id}/challenges/"
            f"{challenge_id}/submit/", token,
            payload={"flag": flag, "confirmation": True},
        )
        return body.get("data") or {}


# ────────────────────────────────────────────────────────────────
# 灵枢 Web 客户端
# ────────────────────────────────────────────────────────────────

class LingshuClient:
    def __init__(self, api_url: str, username: str, password: str):
        self.api_url = api_url.rstrip("/")
        self.username = username
        self.password = password
        self.token = ""

    async def login(self) -> str:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.api_url}/auth/login",
                json={"username": self.username, "password": self.password},
            )
            response.raise_for_status()
            self.token = str(response.json()["access_token"])
            return self.token

    async def enabled_providers(self) -> set[str]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self.api_url}/api/model-providers",
                headers={"Authorization": f"Bearer {self.token}"},
            )
            response.raise_for_status()
            return {
                str(item.get("id") or "").strip().lower()
                for item in response.json().get("providers", [])
                if str(item.get("id") or "").strip()
            }

    async def providers_detail(self) -> list[dict[str, Any]]:
        """可用模型池明细：[{id, label, models}]（供 WebUI 下拉菜单）。"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self.api_url}/api/model-providers",
                headers={"Authorization": f"Bearer {self.token}"},
            )
            response.raise_for_status()
            return [{
                "id": str(item.get("id") or ""),
                "label": str(item.get("label") or item.get("id") or ""),
                "models": [str(m) for m in (item.get("models") or [])],
            } for item in response.json().get("providers", [])
                if str(item.get("id") or "").strip()]

    async def start_session(self, *, target: str, goal: str, provider: str,
                            model: str, mode: str) -> str:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.api_url}/api/session/start",
                headers={"Authorization": f"Bearer {self.token}"},
                json={
                    "target": target, "goal": goal, "provider": provider,
                    "model": model, "mode": mode,
                },
            )
            response.raise_for_status()
            session_id = str(response.json().get("session_id") or "")
            if not session_id:
                raise RuntimeError(f"灵枢未返回 session_id: {response.text[:200]}")
            return session_id

    async def detail(self, session_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self.api_url}/api/session/{session_id}",
                headers={"Authorization": f"Bearer {self.token}"},
            )
            response.raise_for_status()
            return response.json()

    async def send(self, session_id: str, content: str) -> None:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.api_url}/api/session/{session_id}/message",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"content": content},
            )
            response.raise_for_status()

    async def stream(self, session_id: str, timeout: int) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "text/event-stream"}
        deadline = asyncio.get_running_loop().time() + timeout
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout + 30, connect=30)) as client:
            async with client.stream(
                "GET", f"{self.api_url}/api/session/{session_id}/stream", headers=headers,
            ) as response:
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


# ────────────────────────────────────────────────────────────────
# 纯函数（可单测）
# ────────────────────────────────────────────────────────────────

def extract_flag(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = FLAG_PATTERN.search(value)
    return match.group(0) if match else None


def challenge_files(challenge: dict[str, Any]) -> list[dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    for key in ("files", "attachments", "attachment_files"):
        for item in challenge.get(key) or []:
            if isinstance(item, dict) and str(item.get("id") or item.get("file_id") or ""):
                files[str(item.get("id") or item.get("file_id"))] = item
    return list(files.values())


def file_id_of(item: dict[str, Any]) -> str:
    return str(item.get("id") or item.get("file_id") or "")


def file_name_of(item: dict[str, Any]) -> str:
    inner = item.get("file") if isinstance(item.get("file"), dict) else {}
    return str(
        item.get("name") or item.get("filename")
        or inner.get("original_name") or inner.get("name")
        or file_id_of(item)
    )


def challenge_text(challenge: dict[str, Any]) -> str:
    return str(
        challenge.get("content") or challenge.get("description")
        or challenge.get("body") or ""
    ).strip()


def challenge_title(item: dict[str, Any], fallback: str = "") -> str:
    return str(item.get("title") or item.get("name") or fallback)


def source_of(item: dict[str, Any]) -> tuple[str, str, str]:
    """返回 (source_type, competition_id, stage_id)。"""
    source = item.get("source") if isinstance(item.get("source"), dict) else {}
    return (
        str(source.get("type") or "practice"),
        str(source.get("competition_id") or ""),
        str(source.get("stage_id") or ""),
    )


def build_goal(title: str, description: str, access_url: str,
               attachments: list[Path], mode: str) -> str:
    if access_url:
        scope = (f"【授权范围】仅测试本题启动的远程环境（{access_url}）与本地附件；"
                 "不得扩展到其他目标。\n")
    else:
        scope = ("【授权范围】本题无远程环境，仅分析本地附件；"
                 "不得访问任何网络目标。\n")
    goal = (
        f"获取本题 Flag（CTF2 Agent 竞技场）。\n\n"
        f"{scope}"
        "【提交约束】只输出并验证精确 Flag；不要调用任何外部平台提交接口，"
        "工作台负责提交。\n"
        f"【解题模式】{mode}\n\n"
        f"【题目】{title}\n【题面】{description[:6000]}\n"
    )
    if access_url:
        goal += f"【远程环境】{access_url}"
    if attachments:
        goal += "\n【本地附件】" + "、".join(str(p) for p in attachments)
    return goal


def pick_next(
    items: list[dict[str, Any]], exclude: set[str],
    cooldown: dict[str, float] | None = None,
) -> dict[str, Any] | None:
    """全自动选题：跳过已解/已排除/冷却中/选择题题型，取第一个可解项。"""
    now = time.monotonic()
    for item in items:
        cid = str(item.get("id") or "")
        if not cid or cid in exclude or item.get("is_solved"):
            continue
        if cooldown and cooldown.get(cid, 0) > now:
            continue
        if str(item.get("submission_type") or "flag").lower() == "choice":
            continue  # 选择题需要独立答题通道，自动模式跳过
        return item
    return None


# ────────────────────────────────────────────────────────────────
# 解题执行
# ────────────────────────────────────────────────────────────────

async def prepare_environment(
    ctf2: CTF2Client, client: httpx.AsyncClient, token: str, args: argparse.Namespace,
    item: dict[str, Any], challenge: dict[str, Any],
) -> tuple[str, Path, str | None]:
    """启动/复用环境并下载附件；返回 (access_url, 本地附件目录, 环境销毁回调所需键)。

    附件题（has_container=false）没有远程环境可启动——平台对这类题的环境
    接口直接返回 NOT_FOUND；此时仅下载附件，access_url 返回空串。
    """
    source_type, competition_id, stage_id = source_of(item)
    challenge_id = str(item.get("id") or "")
    destination = WORKDIR / challenge_id
    destination.mkdir(parents=True, exist_ok=True)
    has_container = bool(challenge.get("has_container", item.get("has_container", True)))

    access_url = ""
    if has_container:
        if source_type == "competition":
            env = await ctf2.start_competition_environment(
                client, token, competition_id, stage_id, challenge_id)
            for _ in range(args.environment_polls):
                if env.get("access_ready"):
                    break
                await asyncio.sleep(args.environment_poll_interval)
                env = await ctf2.start_competition_environment(
                    client, token, competition_id, stage_id, challenge_id)
        else:
            practice_id = str(item.get("practice_id") or args.practice_id or "")
            if not practice_id:
                raise RuntimeError("缺少 practice_id；请先执行 list 或显式指定 --practice-id")
            env = await ctf2.start_environment(client, token, practice_id, challenge_id)
            for _ in range(args.environment_polls):
                if env.get("access_ready"):
                    break
                await asyncio.sleep(args.environment_poll_interval)
                env = await ctf2.start_environment(client, token, practice_id, challenge_id)

        access_url = str(env.get("access_url") or "")
        if not access_url:
            urls = env.get("access_urls") or []
            if urls and isinstance(urls[0], dict):
                access_url = str(urls[0].get("url") or "")
        if not access_url:
            raise RuntimeError(f"环境未就绪: status={env.get('status')}")

    attachments: list[Path] = []
    for info in challenge_files(challenge):
        fid = file_id_of(info)
        target = destination / Path(file_name_of(info)).name
        try:
            # 详情常自带直链；缺失再走签名 URL 接口
            url = str(info.get("download_url") or info.get("file_url") or "")
            if not url:
                if source_type == "competition":
                    body = await ctf2.request(
                        client, "GET",
                        f"/agent/competitions/{competition_id}/stages/{stage_id}/"
                        f"challenges/{challenge_id}/attachments/{fid}/url/", token)
                    url = str((body.get("data") or {}).get("url") or "")
                else:
                    practice_id = str(item.get("practice_id") or args.practice_id or "")
                    url = await ctf2.attachment_url(client, token, practice_id, challenge_id, fid)
            if url:
                async with client.stream("GET", url) as response:
                    response.raise_for_status()
                    with target.open("wb") as output:
                        async for chunk in response.aiter_bytes():
                            output.write(chunk)
                attachments.append(target)
        except httpx.HTTPError as exc:
            out(f"[ctf2] 附件下载失败（跳过 {file_name_of(info)}）: {exc}")
    return access_url, destination, None


async def run_lingshu(
    lingshu: LingshuClient, args: argparse.Namespace, *,
    title: str, description: str, access_url: str, attachments: list[Path],
    mode: str, watch_quiet: bool = False, on_event=None,
    auto_approve: bool = False, target: str = "", watchdog_interval: float = 45.0,
) -> tuple[str | None, str]:
    """启动灵枢会话并实时观察；返回 (flag 候选, session_id)。

    on_event 提供时（Web 工作台）事件以规范化 dict 回调且不再打印；
    为 None 时保持 CLI 实时打印行为。target 为会话目标：默认用远程环境
    access_url；附件题无环境时传本地附件目录（走文件分析路由）。
    """
    say = (lambda message: on_event({"type": "log", "message": message})
           if on_event else out)
    provider = args.provider
    enabled = await lingshu.enabled_providers()
    if provider not in enabled and enabled:
        provider = sorted(enabled)[0]
        out(f"[lingshu] 供应商 {args.provider} 未启用，回退为 {provider}")
    goal = build_goal(title, description, access_url, attachments, mode)
    session_id = await lingshu.start_session(
        target=target or access_url, goal=goal, provider=provider,
        model=args.model, mode=mode,
    )
    say(f"[lingshu] 会话 {session_id} 已启动（mode={mode}, provider={provider}, model={args.model}）")
    if on_event:
        on_event({"type": "session_started", "session_id": session_id})

    def emit_event(kind: str, agent: str, event: dict[str, Any], message: str = "") -> None:
        if on_event:
            on_event({"type": kind, "agent": agent, "message": message, **{
                k: v for k, v in event.items() if k in {"phase", "status", "tool_name", "flag"}
            }})
            return
        prefix = "\n[lingshu] " if kind in {"tool", "phase", "flag", "approval", "error", "mission_end"} else ""
        if kind == "delta":
            print(event.get("delta") or event.get("content") or "", end="", flush=True)
            return
        if kind in {"text_end", "thinking_end"}:
            print()
            return
        out(f"{prefix}{{{'🔧 ' + agent + ': ' if kind == 'tool' else ''}"
            f"{{message or event.get('phase') or event.get('status') or event.get('flag') or event.get('message') or ''}}}}")

    flag: str | None = None
    approved = False
    if watch_quiet:
        # watch 子命令：仅透传事件
        async for event_type, event in lingshu.stream(session_id, args.timeout):
            agent = str(event.get("agent") or "system")
            if event_type in {"text_delta", "thinking_delta"}:
                emit_event("delta", agent, event)
            elif event_type in {"text_end", "thinking_end"}:
                emit_event("text_end", agent, event)
            elif event_type == "tool_call_start":
                emit_event("tool", agent, event, str(event.get("tool_name") or ""))
            elif event_type == "mission_end":
                emit_event("mission_end", agent, event, str(event.get("status") or ""))
                break
        return flag, session_id

    async def _consume() -> None:
        nonlocal flag, approved
        async for event_type, event in lingshu.stream(session_id, args.timeout):
            agent = str(event.get("agent") or "system")
            if event_type == "phase_change":
                emit_event("phase", agent, event, str(event.get("phase") or ""))
            elif event_type in {"text_delta", "thinking_delta"}:
                emit_event("delta", agent, event)
            elif event_type in {"text_end", "thinking_end"}:
                emit_event("text_end", agent, event)
            elif event_type == "tool_call_start":
                emit_event("tool", agent, event, str(event.get("tool_name") or ""))
            elif event_type == "approval_required" and auto_approve and approved < 3:
                approved += 1
                await lingshu.send(session_id, "批准")
                emit_event("approval", agent, event,
                           f"已自动批准（第 {approved} 次，工作台自动审批）")
            elif event_type == "approval_required" and not approved and mode == "standard":
                await lingshu.send(session_id, "批准")
                approved = True
                emit_event("approval", agent, event, "已自动批准利用验证阶段（选题时已授权）")
            elif event_type == "flag_found":
                flag = extract_flag(event.get("flag") or event.get("content")) or flag
                if flag:
                    emit_event("flag", agent, event, flag)
            elif event_type == "mission_end":
                emit_event("mission_end", agent, event, str(event.get("status") or ""))
                break
            elif event_type == "error":
                emit_event("error", agent, event, str(event.get("message") or ""))

    async def _watchdog() -> None:
        # SSE 流在会话结束后可能悬挂不发事件（deadline 只在收到行时才检查）；
        # 静默期轮询会话详情，终态即收流，flag 走 detail 兜底提取
        while not consumer.done():
            await asyncio.sleep(watchdog_interval)
            if consumer.done():
                return
            try:
                detail = await lingshu.detail(session_id)
            except Exception:  # noqa: BLE001 — 详情拉取失败继续等待
                continue
            phase = str((detail.get("mission_state") or {}).get("phase")
                        or detail.get("phase") or "")
            if phase in {"completed", "failed", "aborted", "cancelled"}:
                return

    consumer = asyncio.ensure_future(_consume())
    watcher = asyncio.ensure_future(_watchdog())
    _done, pending = await asyncio.wait(
        {consumer, watcher}, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)

    if not flag:
        await asyncio.sleep(1)
        detail = await lingshu.detail(session_id)
        flag = extract_flag(detail.get("flag"))
        flag = flag or extract_flag((detail.get("target_info") or {}).get("flag"))
        mission = detail.get("mission_state") or {}
        flag = flag or extract_flag(json.dumps(mission.get("facts") or [], ensure_ascii=False))
    return flag, session_id


async def _submit_with_retry(say, submit_call, *, attempts: int = 3) -> dict[str, Any]:
    """提交 flag：瞬时失败（平台 5xx / 网络抖动 / 可重试错误）自动重试。

    flag 提交是整条解题链路唯一产生积分的动作，不允许被瞬时错误吞掉——
    平台未收到请求时不会消耗 attempt，重试是安全的。
    """
    last: Exception | None = None
    for i in range(attempts):
        try:
            return await submit_call()
        except CTF2Error as exc:
            last = exc
            if not exc.retryable:
                raise
            wait = min(max(exc.retry_after_ms / 1000, 2.0), 15.0)
        except httpx.HTTPStatusError as exc:
            last = exc
            if exc.response.status_code < 500:
                raise
            wait = 5.0
        except httpx.HTTPError as exc:          # 超时 / 连接中断等网络层瞬时错误
            last = exc
            wait = 5.0
        say(f"提交暂时失败（第 {i + 1}/{attempts} 次）：{last}，{wait:.0f}s 后重试")
        await asyncio.sleep(wait)
    assert last is not None
    raise last


async def solve_challenge(
    ctf2: CTF2Client, client: httpx.AsyncClient, token: str,
    lingshu: LingshuClient, args: argparse.Namespace, item: dict[str, Any],
    challenge: dict[str, Any], mode: str, *, auto: bool = False, on_event=None,
    auto_approve: bool = False,
) -> dict[str, Any]:
    def say(message: str, **extra: Any) -> None:
        if on_event:
            on_event({"type": "log", "message": message, **extra})
        else:
            out(message)
    """单题完整流程：环境 → 附件 → 灵枢 → 提交 → 环境回收。返回结果摘要。"""
    challenge_id = str(item.get("id") or "")
    title = challenge_title(item, challenge_id)
    source_type, competition_id, stage_id = source_of(item)
    description = challenge_text(challenge)
    result: dict[str, Any] = {
        "challenge_id": challenge_id, "title": title, "mode": mode,
        "source": source_type, "flag": None, "submitted": False,
        "accepted": False, "session_id": None, "error": None,
    }
    await ctf2.log_note(client, token, challenge_id, "plan",
                        f"[lingshu-{mode}] 开始解题：{title[:200]}")
    env_key = (source_type, competition_id, stage_id, challenge_id)
    has_container = bool(challenge.get("has_container", item.get("has_container", True)))
    try:
        access_url, attach_dir, _ = await prepare_environment(
            ctf2, client, token, args, item, challenge)
        if access_url:
            say(f"环境就绪: {access_url}", type="env_ready", url=access_url)
        else:
            say("附件模式：本题无远程环境，仅分析本地附件", type="env_ready", url="")
        attachments = sorted((WORKDIR / challenge_id).glob("*")) if (WORKDIR / challenge_id).exists() else []
        flag, session_id = await run_lingshu(
            lingshu, args, title=title, description=description,
            access_url=access_url, target=str(attach_dir),
            attachments=attachments, mode=mode,
            on_event=on_event, auto_approve=auto_approve)
        result["session_id"] = session_id
        result["flag"] = flag
        if flag:
            await ctf2.log_note(client, token, challenge_id, "finding",
                                f"候选 Flag: {flag}")
        if not flag:
            result["error"] = "未提取到 Flag"
            return result
        if args.no_submit:
            say(f"--no-submit 生效，不提交。Flag: {flag}")
            return result
        if source_type == "competition":
            data = await _submit_with_retry(say, lambda: ctf2.submit_competition_flag(
                client, token, competition_id, stage_id, challenge_id, flag))
        else:
            practice_id = str(item.get("practice_id") or args.practice_id or "")
            if not practice_id:
                # 条目缺场地归属时兜底定位（进程内缓存/全量索引），避免提交 500 且环境泄漏
                practice_id = str(
                    await locate_practice_id(ctf2, client, token, challenge_id) or "")
            if not practice_id:
                raise RuntimeError("缺少 practice_id，无法提交；请从题目列表/队列重新发起")
            data = await _submit_with_retry(say, lambda: ctf2.submit_flag(
                client, token, practice_id, challenge_id, flag))
        accepted = bool(data.get("accepted"))
        result["submitted"] = True
        result["accepted"] = accepted
        result["attempt"] = data.get("attempt")
        say(f"提交结果: {'✅ 正确' if accepted else '❌ 未通过'}"
            + (f" | attempt={data.get('attempt')}" if data.get("attempt") else ""),
            type="submit", accepted=accepted)
        await ctf2.log_note(
            client, token, challenge_id, "result",
            f"提交{'成功' if accepted else '未通过'}: {flag}")
    except CTF2Error as exc:
        result["error"] = f"{exc.code}: {exc}"
        say(f"平台错误: {exc}"
            + (f"（{exc.retry_after_ms}ms 后可重试）" if exc.retryable else ""))
    except (httpx.HTTPError, RuntimeError) as exc:
        result["error"] = str(exc)
        say(f"执行失败: {exc}")
    finally:
        # 环境回收：默认销毁以释放配额（--keep-env 保留）；结果显式记录。
        # 附件题（无容器）本就没有环境，跳过回收调用。
        if not args.keep_env and has_container:
            source_type, competition_id, stage_id, _cid = env_key
            challenge_id = result["challenge_id"]
            try:
                if source_type == "competition":
                    await ctf2.request(
                        client, "DELETE",
                        f"/agent/competitions/{competition_id}/stages/{stage_id}/"
                        f"challenges/{challenge_id}/environment/", token)
                    out(f"[ctf2] ✅ 环境已销毁（竞赛 {challenge_id[:8]}）")
                else:
                    practice_id = str(item.get("practice_id") or args.practice_id or "")
                    if not practice_id:
                        try:
                            practice_id = str(await locate_practice_id(
                                ctf2, client, token, challenge_id) or "")
                        except Exception:  # noqa: BLE001 — 定位失败按缺失处理
                            practice_id = ""
                    if practice_id:
                        await ctf2.destroy_environment(
                            client, token, practice_id, challenge_id)
                        out(f"[ctf2] ✅ 环境已销毁（{challenge_id[:8]}）")
                    else:
                        out("[ctf2] ⚠ 环境回收跳过：practice_id 缺失（配额将占用至到期）")
            except Exception as exc:  # noqa: BLE001
                out(f"[ctf2] ❌ 环境销毁失败（配额将占用至到期）: {exc}")
    return result


# ────────────────────────────────────────────────────────────────
# 工作台命令
# ────────────────────────────────────────────────────────────────

async def cmd_status(ctf2: CTF2Client, client: httpx.AsyncClient, token: str) -> None:
    me = await ctf2.whoami(client, token)
    profile = me.get("agent") or me.get("profile") or me
    quotas = me.get("quotas") or {}
    out_table("CTF2 Agent 状态", ["项目", "值"], [
        ["身份", profile.get("username") or profile.get("friendly_id") or "-"],
        ["Agent ID", profile.get("id") or "-"],
        ["总分 / 排名", f"{me.get('total_score', me.get('score', '-'))} / {me.get('rank', '-')}"],
        ["解题数", f"solved={me.get('solved_count', me.get('solved', '-'))}"],
        ["竞赛开关", str(me.get("competition_enabled", "-"))],
        ["环境配额", quotas.get("max_environments", "-")],
        ["读/写限速", f"{quotas.get('reads_per_minute', 120)}/min · {quotas.get('writes_per_minute', 30)}/min"],
    ])


async def cmd_list(
    ctf2: CTF2Client, client: httpx.AsyncClient, token: str,
    *, source: str, category: str, difficulty: str, limit: int,
) -> list[dict[str, Any]]:
    items = await ctf2.next_challenges(
        client, token, source=source, category=category,
        difficulty=difficulty, limit=limit)
    rows = []
    for item in items:
        source_type, competition_id, _stage = source_of(item)
        rows.append([
            str(item.get("id"))[:8],
            challenge_title(item)[:38],
            item.get("category") or "-",
            item.get("difficulty") or "-",
            item.get("score") if item.get("score") is not None else "-",
            "竞赛" if source_type == "competition" else "练习",
            "✔" if item.get("is_solved") else "可解",
            "🐳" if item.get("has_container") else "-",
        ])
    out_table(f"可解题目（{len(items)}，推荐序：易/高通过优先）",
              ["ID", "题名", "分类", "难度", "分值", "来源", "状态", "容器"], rows)
    if not items:
        out("[ctf2] 没有可解题目：放宽过滤或稍后再试（agent_next_challenges 为空）。")
    return items


_PRACTICE_ID_CACHE: dict[str, str] = {}   # challenge_id → practice_id（进程内）
_PRACTICE_INDEX_BUILT = False


async def build_practice_index(
    ctf2: CTF2Client, client: httpx.AsyncClient, token: str,
) -> None:
    """全量索引公开练习场：challenge_id → practice_id（按 total_page 翻页）。"""
    global _PRACTICE_INDEX_BUILT
    for ground in await ctf2.practice_grounds(client, token):
        practice_id = str(ground.get("id") or "")
        if not practice_id:
            continue
        for page in range(1, 61):        # 安全上限：60 页 × 100/页
            challenges = await ctf2.practice_challenges(
                client, token, practice_id, page=page)
            if not challenges:
                break
            for challenge in challenges:
                cid = str(challenge.get("id") or "")
                if cid:
                    _PRACTICE_ID_CACHE[cid] = practice_id
            if len(challenges) < 100:
                break
    _PRACTICE_INDEX_BUILT = True
    out(f"[ctf2] 练习场索引已建立：{len(_PRACTICE_ID_CACHE)} 题已映射")


async def locate_practice_id(
    ctf2: CTF2Client, client: httpx.AsyncClient, token: str, challenge_id: str,
) -> str | None:
    """定位题目所属 practice_id；索引未建时全量构建一次。"""
    if challenge_id in _PRACTICE_ID_CACHE:
        return _PRACTICE_ID_CACHE[challenge_id]
    if not _PRACTICE_INDEX_BUILT:
        await build_practice_index(ctf2, client, token)
        if challenge_id in _PRACTICE_ID_CACHE:
            return _PRACTICE_ID_CACHE[challenge_id]
    return None


async def resolve_item(
    ctf2: CTF2Client, client: httpx.AsyncClient, token: str,
    args: argparse.Namespace, challenge_id: str,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """把题目 ID 解析为 (item, challenge detail)。优先 next-challenges，再扫练习场。"""
    items = await ctf2.next_challenges(client, token, source=args.source or "all", limit=100)
    for item in items:
        if str(item.get("id")) == challenge_id:
            source_type, competition_id, stage_id = source_of(item)
            if source_type == "competition" and competition_id and stage_id:
                challenge = await ctf2.competition_challenge(
                    client, token, competition_id, stage_id, challenge_id)
            else:
                # 推荐条目自带 practice_ground_id（权威归属），索引仅兜底
                practice_id = (str(item.get("practice_ground_id") or "")
                               or str((item.get("source") or {}).get("practice_ground_id") or "")
                               or str(item.get("practice_id") or "")
                               or args.practice_id
                               or await locate_practice_id(ctf2, client, token, challenge_id)
                               or "")
                if not practice_id:
                    return None
                item = {**item, "practice_id": practice_id}
                challenge = await ctf2.practice_challenge(
                    client, token, practice_id, challenge_id)
            return item, challenge
    # 回退：全量索引定位练习场（带分页），再取题目详情
    practice_id = await locate_practice_id(ctf2, client, token, challenge_id)
    if practice_id:
        detail = await ctf2.practice_challenge(client, token, practice_id, challenge_id)
        item = {**detail, "id": challenge_id, "practice_id": practice_id,
                "source": {"type": "practice"}}
        return item, detail
    return None


async def cmd_solve(
    ctf2: CTF2Client, client: httpx.AsyncClient, token: str,
    lingshu: LingshuClient, args: argparse.Namespace,
) -> dict[str, Any] | None:
    resolved = await resolve_item(ctf2, client, token, args, args.challenge_id)
    if resolved is None:
        out(f"[ctf2] 未找到题目 {args.challenge_id}；先 list 查看可解题目。")
        return None
    item, challenge = resolved
    out(f"[ctf2] 选题: {challenge_title(item, args.challenge_id)} "
        f"（mode={args.mode}, {'自动提交' if not args.no_submit else '仅解题不提交'}）")
    result = await solve_challenge(
        ctf2, client, token, lingshu, args, item, challenge, args.mode)
    out_table("单题结果", ["字段", "值"], [
        ["题目", result["title"]], ["模式", result["mode"]],
        ["Flag", result["flag"] or "-"],
        ["提交", "是" if result["submitted"] else "否"],
        ["判定", "✅ 正确" if result["accepted"] else ("❌ 未通过" if result["submitted"] else "-")],
        ["会话", result["session_id"] or "-"],
        ["错误", result["error"] or "-"],
    ])
    return result


async def cmd_auto(
    ctf2: CTF2Client, client: httpx.AsyncClient, token: str,
    lingshu: LingshuClient, args: argparse.Namespace,
) -> None:
    """全自动循环：选题 → 解题 → 提交 → 成功选下一题。"""
    solved: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    exclude: set[str] = set(args.exclude or [])
    started = time.monotonic()
    cooldown: dict[str, float] = {}
    while len(solved) + len(failed) < args.limit:
        items = await ctf2.next_challenges(
            client, token, source=args.source or "practice",
            category=args.category, difficulty=args.difficulty, limit=100)
        item = pick_next(items, exclude, cooldown)
        if item is None:
            out("[auto] 推荐列表已无可解题目（全部已解/被排除），循环结束。")
            break
        challenge_id = str(item.get("id") or "")
        out(f"\n[auto] ▶ 第 {len(solved) + len(failed) + 1} 题："
            f"{challenge_title(item, challenge_id)}（已排除 {len(exclude)}）")
        resolved = await resolve_item(ctf2, client, token, args, challenge_id)
        if resolved is None:
            exclude.add(challenge_id)
            continue
        item, challenge = resolved
        result = await solve_challenge(
            ctf2, client, token, lingshu, args, item, challenge, args.mode, auto=True)
        if result["accepted"]:
            solved.append(result)
        elif "agent_environment_limit" in str(result.get("error") or ""):
            cooldown[challenge_id] = time.monotonic() + 90   # 环境配额：90s 后重试
            out(f"[auto] 环境配额占用，{challenge_id[:8]} 90s 后重试")
        else:
            failed.append(result)
            exclude.add(challenge_id)   # 未通过的题本轮不再自动重试
        out(f"[auto] 进度: ✅{len(solved)}  ❌{len(failed)}  （剩余配额 {args.limit - len(solved) - len(failed)}）")
    out_table("全自动战报", ["结果", "题名", "Flag", "会话"], [
        ["✅" if r in solved else "❌", r["title"][:36], r["flag"] or "-", r["session_id"] or "-"]
        for r in [*solved, *failed]
    ] or [["-", "无", "-", "-"]])
    out(f"[auto] 结束：✅{len(solved)} ❌{len(failed)} 用时 {time.monotonic() - started:.0f}s")


async def cmd_watch(lingshu: LingshuClient, args: argparse.Namespace) -> None:
    out(f"[lingshu] 实时观察会话 {args.watch}（Ctrl+C 退出，不影响任务）")
    try:
        async for event_type, event in lingshu.stream(args.watch, args.timeout):
            agent = str(event.get("agent") or "system")
            if event_type in {"text_delta", "thinking_delta"}:
                print(event.get("delta") or event.get("content") or "", end="", flush=True)
            elif event_type in {"text_end", "thinking_end"}:
                print()
            elif event_type == "tool_call_start":
                out(f"\n[lingshu] 🔧 {agent}: {event.get('tool_name')}")
            elif event_type == "phase_change":
                out(f"\n[lingshu] 阶段 → {event.get('phase')}")
            elif event_type == "approval_required":
                out("\n[lingshu] ⏸ 等待人工审批（在 Web 界面或命令条回复）")
            elif event_type == "flag_found":
                out(f"\n[lingshu] 🚩 Flag: {extract_flag(event.get('flag') or event.get('content'))}")
            elif event_type == "mission_end":
                out(f"\n[lingshu] 任务结束: {event.get('status')}")
                break
    except asyncio.CancelledError:
        raise


INTERACTIVE_HELP = """工作台命令：
  status                          Agent 身份/积分/配额
  list [--source p|c|all] [--category web] [--difficulty easy]
                                  列出可解题目（推荐序）
  solve <challenge-id> [--mode fast|standard] [--no-submit]
                                  选题让灵枢解（实时观察，默认自动提交）
  auto [--mode fast] [--limit N] [--source practice] [--category X] [--difficulty Y]
                                  全自动：选题→环境→解题→提交→成功选下一题
  watch <session-id>              实时观察运行中的灵枢会话
  note <challenge-id> <plan|finding|result> <text>
                                  记录 Agent 解题笔记
  submit <challenge-id> <flag>    手动确认提交精确 Flag
  help / quit"""


async def interactive_shell(
    ctf2: CTF2Client, client: httpx.AsyncClient, token: str,
    lingshu: LingshuClient, args: argparse.Namespace,
) -> None:
    out("=" * 62)
    out("灵枢 × CTF2 Agent 竞技场工作台")
    out("=" * 62)
    out(INTERACTIVE_HELP)
    while True:
        try:
            raw = input("\nctf2> ").strip()
        except (EOFError, KeyboardInterrupt):
            out()
            break
        if not raw:
            continue
        parts = shlex.split(raw)
        command, rest = parts[0].lower(), parts[1:]
        try:
            if command in {"quit", "exit", "q"}:
                break
            if command == "help":
                out(INTERACTIVE_HELP)
            elif command == "status":
                await cmd_status(ctf2, client, token)
            elif command == "list":
                ns = parse_list_args(rest)
                await cmd_list(ctf2, client, token, source=ns.source,
                               category=ns.category, difficulty=ns.difficulty,
                               limit=ns.limit)
            elif command == "solve":
                if not rest:
                    out("用法: solve <challenge-id> [--mode fast|standard] [--no-submit]")
                    continue
                cid = rest[0]
                ns = solve_ns(args, cid, rest[1:])
                await cmd_solve(ctf2, client, token, lingshu, ns)
            elif command == "auto":
                ns = auto_ns(args, rest)
                await cmd_auto(ctf2, client, token, lingshu, ns)
            elif command == "watch":
                if not rest:
                    out("用法: watch <session-id>")
                    continue
                args.watch = rest[0]
                await cmd_watch(lingshu, args)
            elif command == "note":
                if len(rest) < 3:
                    out("用法: note <challenge-id> <plan|finding|result> <text>")
                    continue
                await ctf2.log_note(client, token, rest[0], rest[1], " ".join(rest[2:]))
                out("[ctf2] 笔记已记录")
            elif command == "submit":
                if len(rest) < 2:
                    out("用法: submit <challenge-id> <flag>")
                    continue
                item = await resolve_item(ctf2, client, token, args, rest[0])
                if item is None:
                    out("[ctf2] 未找到题目")
                    continue
                it, _ = item
                stype, comp_id, stage_id = source_of(it)
                if stype == "competition":
                    data = await ctf2.submit_competition_flag(
                        client, token, comp_id, stage_id, rest[0], rest[1])
                else:
                    data = await ctf2.submit_flag(
                        client, token, str(it.get("practice_id") or args.practice_id or ""),
                        rest[0], rest[1])
                out(f"[ctf2] 提交结果: {'✅ 正确' if data.get('accepted') else '❌ 未通过'}")
            else:
                out(f"未知命令 {command}；help 查看命令列表。")
        except KeyboardInterrupt:
            out("\n[workbench] 已打断当前操作（不影响运行中的灵枢会话）")
        except (CTF2Error, httpx.HTTPError, RuntimeError) as exc:
            out(f"[workbench] 错误: {exc}")


# ────────────────────────────────────────────────────────────────
# 参数解析
# ────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="灵枢 × CTF2 Agent 竞技场工作台（交互式 / 脚本化 / 全自动）")
    parser.add_argument("--token", help="CTF2 Agent PAT（或环境变量 CTF2_API_TOKEN；不落盘）")
    parser.add_argument("--api-url", default=DEFAULT_API_URL, help="灵枢 Web 地址")
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--provider", "-p", default=DEFAULT_PROVIDER)
    parser.add_argument("--model", "-m", default=DEFAULT_MODEL, choices=["Low", "Min", "Max"])
    parser.add_argument("--mode", default=DEFAULT_MODE, choices=["fast", "standard"],
                        help="解题模式：fast=快速模式（默认）/ standard=标准模式")
    parser.add_argument("--timeout", type=int, default=1800, help="单会话观察秒数")
    parser.add_argument("--environment-polls", type=int, default=24)
    parser.add_argument("--environment-poll-interval", type=int, default=5)
    parser.add_argument("--practice-id", help="显式指定练习场 ID（默认自动解析）")
    parser.add_argument("--source", default="practice",
                        choices=["practice", "competition", "all"], help="选题来源")
    parser.add_argument("--category", default="", help="题型过滤（web/pwn/reverse/...）")
    parser.add_argument("--difficulty", default="", help="难度过滤")
    parser.add_argument("--limit", type=int, default=5, help="auto 循环题数上限")
    parser.add_argument("--exclude", default="", help="auto 跳过的题目 ID（逗号分隔）")
    parser.add_argument("--no-submit", action="store_true", help="只解题不提交")
    parser.add_argument("--keep-env", action="store_true", help="结束后保留远程环境")
    parser.add_argument("--watch", help="实时观察指定灵枢会话")
    parser.add_argument("--list", action="store_true", help="列出可解题目后退出")
    parser.add_argument("--status", action="store_true", help="打印 Agent 状态后退出")
    parser.add_argument("--solve", help="解题指定题目后退出")
    parser.add_argument("--auto-run", action="store_true", help="启动全自动循环后退出")
    return parser


def parse_list_args(rest: list[str]) -> argparse.Namespace:
    ns = argparse.Namespace(source="all", category="", difficulty="", limit=50)
    i = 0
    while i < len(rest):
        if rest[i] == "--source" and i + 1 < len(rest):
            ns.source = {"p": "practice", "c": "competition", "a": "all"}.get(
                rest[i + 1], rest[i + 1]); i += 2
        elif rest[i] == "--category" and i + 1 < len(rest):
            ns.category = rest[i + 1]; i += 2
        elif rest[i] == "--difficulty" and i + 1 < len(rest):
            ns.difficulty = rest[i + 1]; i += 2
        elif rest[i] == "--limit" and i + 1 < len(rest):
            ns.limit = int(rest[i + 1]); i += 2
        else:
            i += 1
    return ns


def solve_ns(base: argparse.Namespace, challenge_id: str, rest: list[str]) -> argparse.Namespace:
    ns = argparse.Namespace(**vars(base))
    ns.challenge_id = challenge_id
    ns.no_submit = base.no_submit
    for i, part in enumerate(rest):
        if part == "--mode" and i + 1 < len(rest):
            ns.mode = rest[i + 1]
        elif part == "--no-submit":
            ns.no_submit = True
    return ns


def auto_ns(base: argparse.Namespace, rest: list[str]) -> argparse.Namespace:
    ns = argparse.Namespace(**vars(base))
    i = 0
    while i < len(rest):
        if rest[i] == "--mode" and i + 1 < len(rest):
            ns.mode = rest[i + 1]; i += 2
        elif rest[i] == "--limit" and i + 1 < len(rest):
            ns.limit = int(rest[i + 1]); i += 2
        elif rest[i] == "--source" and i + 1 < len(rest):
            ns.source = rest[i + 1]; i += 2
        elif rest[i] == "--category" and i + 1 < len(rest):
            ns.category = rest[i + 1]; i += 2
        elif rest[i] == "--difficulty" and i + 1 < len(rest):
            ns.difficulty = rest[i + 1]; i += 2
        else:
            i += 1
    return ns


async def async_main() -> None:
    args = build_parser().parse_args()
    token = args.token or os.environ.get("CTF2_API_TOKEN") or os.environ.get("CTF2_TOKEN") or ""
    if not token:
        raise SystemExit("缺少 CTF2 Agent 凭据：--token 或环境变量 CTF2_API_TOKEN（不落盘）。")
    args.mode = str(args.mode).lower()
    lingshu = LingshuClient(args.api_url, args.username, args.password)
    await lingshu.login()

    timeout = httpx.Timeout(60, connect=30)
    async with httpx.AsyncClient(timeout=timeout) as client:
        ctf2 = CTF2Client(token)
        if args.status:
            await cmd_status(ctf2, client, token)
            return
        if args.list:
            await cmd_list(ctf2, client, token, source=args.source,
                           category=args.category, difficulty=args.difficulty, limit=100)
            return
        if args.watch:
            await cmd_watch(lingshu, args)
            return
        if args.solve:
            await cmd_solve(ctf2, client, token, lingshu, args)
            return
        if args.auto_run:
            await cmd_auto(ctf2, client, token, lingshu, args)
            return
        await interactive_shell(ctf2, client, token, lingshu, args)


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        out("\n[workbench] 已退出（运行中的灵枢会话不受影响）。")


if __name__ == "__main__":
    main()
