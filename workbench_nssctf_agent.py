"""NSSCTF Agent Arena 工作台客户端与解题流程。

协议参考：.agents/skills/nssctf-agent-arena/references/api.md
- Bearer Token 认证（nss_agent_xxx），响应统一 {code, data}，code != 200 即错误
- 单题模式：next 复用未结束的 attempt；同一 Agent 同时只有一道题
- 提交错误消耗 wrong_count（max_wrong_count 默认 20）；abandon 主动放弃结算
- 单题默认 1 小时超时（ttl_seconds=3600）

解题链路复用灵枢工作台基础设施（run_lingshu / build_goal / 自动审批 / 流看门狗）。
"""
from __future__ import annotations

import argparse
import asyncio
import re
from pathlib import Path
from typing import Any

import httpx

from workbench_ctf2_agent import (
    WORKDIR,
    LingshuClient,
    build_goal,          # noqa: F401 （复用；题目目标/约束文案与 CTF2 一致）
    extract_flag,        # noqa: F401
    out,
    run_lingshu,
)

NSSCTF_API = "https://www.nssctf.cn/api"
NSS_WORKDIR = WORKDIR / "nssctf"

# attempt.state_label 终态集合：进入后不能再提交/放弃
NSS_TERMINAL_STATES = {"solved", "failed", "abandoned", "expired", "invalid"}


class NSSCTFError(RuntimeError):
    """NSSCTF 平台错误（code 非 200 或 HTTP >= 400）。"""

    def __init__(self, code: int | str, message: str = ""):
        self.code = code
        self.message = message
        super().__init__(f"[NSSCTF {code}] {message}")


def attempt_brief(attempt: dict[str, Any] | None) -> dict[str, Any] | None:
    """attempt → 前端摘要（题面截断，容器/附件就绪状态扁平化）。"""
    if not attempt:
        return None
    problem = attempt.get("problem") or {}
    annex = problem.get("annex") or {}
    container = problem.get("container") or {}
    return {
        "attempt_id": attempt.get("id"),
        "state": attempt.get("state_label"),
        "wrong_count": attempt.get("wrong_count"),
        "max_wrong_count": attempt.get("max_wrong_count"),
        "remaining_seconds": attempt.get("remaining_seconds"),
        "rating_delta": attempt.get("rating_delta"),
        "reused": bool(attempt.get("reused")),
        "problem": {
            "id": problem.get("id"),
            "title": problem.get("title"),
            "type_label": problem.get("type_label"),
            "tags": problem.get("tag") or [],
            "rating": problem.get("rating"),
            "content": str(problem.get("content") or "")[:4000],
            "has_annex": bool(annex.get("url")),
            "annex_name": annex.get("name"),
            "annex_size": annex.get("size"),
            "container_enabled": bool(problem.get("container_enabled")),
            "container_urls": [str(u) for u in (container.get("url") or []) if u],
        },
    }


class NSSCTFClient:
    """NSSCTF Agent Arena Open API 客户端。"""

    def __init__(self, token: str, base: str = NSSCTF_API, timeout: float = 60.0):
        self.token = token
        self.base = base.rstrip("/")
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"}

    async def request(
        self, client: httpx.AsyncClient, method: str, path: str,
        payload: dict[str, Any] | None = None, *, retries: int = 3,
    ) -> dict[str, Any]:
        response = await client.request(
            method, f"{self.base}{path}", headers=self._headers(), json=payload)
        if response.status_code == 429 and retries > 0:
            wait = max(1, min(60, int(response.headers.get("Retry-After", "2") or "2")))
            out(f"[nss] 限流，等待 {wait}s 重试")
            await asyncio.sleep(wait)
            return await self.request(client, method, path, payload, retries - 1)
        if response.status_code in {401, 403}:
            raise PermissionError(
                f"NSSCTF 认证失败 HTTP {response.status_code}：检查 NSSCTF Agent Token")
        try:
            body = response.json()
        except ValueError:
            response.raise_for_status()
            raise RuntimeError(f"NSSCTF 非 JSON 响应 HTTP {response.status_code}")
        if response.status_code >= 400:
            raise NSSCTFError(
                response.status_code,
                str(body.get("message") or body)[:200])
        code = body.get("code")
        if code is not None and str(code) != "200":
            raise NSSCTFError(code, str(body.get("message") or body)[:200])
        return body.get("data") or {}

    # ── 端点 ──
    async def current(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """{agent, attempt|null}：当前进行中的题。"""
        return await self.request(client, "GET", "/skill/agent/arena/current/")

    async def next_challenge(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """随机领题；已有未结束题时复用（reused=true）。"""
        return await self.request(client, "POST", "/skill/agent/arena/next/")

    async def detail(
        self, client: httpx.AsyncClient, attempt_id: int | str,
    ) -> dict[str, Any]:
        return await self.request(
            client, "GET", f"/skill/agent/arena/attempt/{attempt_id}/")

    async def submit_flag(
        self, client: httpx.AsyncClient, attempt_id: int | str, flag: str,
    ) -> dict[str, Any]:
        """提交 flag。错误不重试：错误提交消耗 wrong_count 次数。"""
        return await self.request(
            client, "POST", f"/skill/agent/arena/attempt/{attempt_id}/submit/",
            {"flag": flag})

    async def abandon(
        self, client: httpx.AsyncClient, attempt_id: int | str,
    ) -> dict[str, Any]:
        return await self.request(
            client, "POST", f"/skill/agent/arena/attempt/{attempt_id}/abandon/")


# ────────────────────────────────────────────────────────────────
# 解题流程
# ────────────────────────────────────────────────────────────────

def _safe_filename(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name)[:120] or "annex.bin"


async def download_annex(
    client: httpx.AsyncClient, problem: dict[str, Any], attempt_id: int | str,
) -> list[Path]:
    """下载附件到 NSS_WORKDIR/<attempt_id>/；无附件返回空。"""
    annex = problem.get("annex") or {}
    url = str(annex.get("url") or "")
    if not url:
        return []
    name = _safe_filename(str(annex.get("name")
                             or url.rstrip("/").split("/")[-1] or "annex.bin"))
    dest_dir = NSS_WORKDIR / str(attempt_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / name
    async with client.stream("GET", url) as response:
        response.raise_for_status()
        with target.open("wb") as fh:
            async for chunk in response.aiter_bytes():
                fh.write(chunk)
    out(f"[nss] 附件已下载: {name}")
    return [target]


async def wait_container_ready(
    nss: NSSCTFClient, client: httpx.AsyncClient, attempt: dict[str, Any],
    *, polls: int = 20, interval: float = 5.0,
) -> list[str]:
    """等待靶机 URL 就绪（领取后容器可能还在启动）。无容器题返回空。"""
    problem = attempt.get("problem") or {}
    if not problem.get("container_enabled"):
        return []
    attempt_id = attempt.get("id")
    for _ in range(polls):
        container = problem.get("container") or {}
        urls = [str(u) for u in (container.get("url") or []) if u]
        if urls:
            return urls
        fresh = await nss.detail(client, attempt_id)
        problem = (fresh or {}).get("problem") or problem
        await asyncio.sleep(interval)
    container = problem.get("container") or {}
    return [str(u) for u in (container.get("url") or []) if u]


async def solve_attempt(
    lingshu: LingshuClient, args: argparse.Namespace,
    nss: NSSCTFClient, client: httpx.AsyncClient,
    attempt: dict[str, Any], *, mode: str, on_event=None,
) -> dict[str, Any]:
    """解一道 NSSCTF attempt：附件 → 靶机 → 灵枢 → 提交。返回结果摘要。"""
    say = ((lambda message, **extra: on_event({"type": "log", "message": message, **extra}))
           if on_event else (lambda message, **extra: out(message)))
    problem = attempt.get("problem") or {}
    attempt_id = attempt.get("id")
    title = str(problem.get("title") or f"attempt-{attempt_id}")
    result: dict[str, Any] = {
        "attempt_id": attempt_id, "title": title, "mode": mode,
        "flag": None, "submitted": False, "correct": None,
        "remaining_wrong_attempts": None, "session_id": None, "error": None,
    }
    try:
        attachments = await download_annex(client, problem, attempt_id)
        access_urls = await wait_container_ready(nss, client, attempt)
        access_url = access_urls[0] if access_urls else ""
        target = access_url or str(NSS_WORKDIR / str(attempt_id))
        if access_url:
            say(f"靶机就绪: {access_url}", type="env_ready", url=access_url)
        else:
            say("本题无靶机，仅分析本地附件", type="env_ready", url="")
        flag, session_id = await run_lingshu(
            lingshu, args, title=title,
            description=str(problem.get("content") or ""),
            access_url=access_url, target=target, attachments=attachments,
            mode=mode, on_event=on_event, auto_approve=True)
        result["session_id"] = session_id
        result["flag"] = flag
        if not flag:
            result["error"] = "未提取到 Flag"
            return result
        data = await nss.submit_flag(client, attempt_id, flag)
        result["submitted"] = True
        result["correct"] = bool(data.get("correct"))
        result["remaining_wrong_attempts"] = data.get("remaining_wrong_attempts")
        verdict = "✅ 正确" if result["correct"] else "❌ 错误"
        extra = (f"（剩余错误次数 {data.get('remaining_wrong_attempts')}）"
                 if not result["correct"] else "")
        say(f"提交结果: {verdict}{extra}", type="submit", accepted=result["correct"])
    except NSSCTFError as exc:
        result["error"] = str(exc)
        say(f"NSSCTF 平台错误: {exc}")
    except PermissionError as exc:
        result["error"] = str(exc)
        say(str(exc))
    except (httpx.HTTPError, RuntimeError) as exc:
        result["error"] = str(exc)
        say(f"执行失败: {exc}")
    return result


async def abandon_if_active(
    nss: NSSCTFClient, client: httpx.AsyncClient, attempt_id: int | str,
) -> bool:
    """仍处于 active 才放弃（已结算的题 abandon 会报错）。"""
    detail = await nss.detail(client, attempt_id)
    if str(detail.get("state_label") or "") == "active":
        await nss.abandon(client, attempt_id)
        return True
    return False


async def auto_arena(
    lingshu: LingshuClient, args: argparse.Namespace,
    nss: NSSCTFClient, *, mode: str, limit: int,
    on_result=None, on_progress=None, on_event=None,
    stop_event: asyncio.Event | None = None,
) -> dict[str, Any]:
    """全自动循环：领题 → 解题 → 提交 → 正确计数 / 否则放弃 → 下一题。"""
    solved, failed, results = 0, 0, []
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
        while solved + failed < limit and not (stop_event and stop_event.is_set()):
            data = await nss.next_challenge(client)
            attempt = data.get("attempt")
            if not attempt:
                out("[nss-auto] 平台未返回题目（无可用题），循环结束")
                break
            if str(attempt.get("state_label") or "") in NSS_TERMINAL_STATES:
                out(f"[nss-auto] attempt {attempt.get('id')} 已结算"
                    f"（{attempt.get('state_label')}），跳过")
                break
            title = str((attempt.get("problem") or {}).get("title")
                        or f"attempt-{attempt.get('id')}")
            if on_progress:
                on_progress({"current": title, "solved": solved, "failed": failed})
            result = await solve_attempt(
                lingshu, args, nss, client, attempt, mode=mode, on_event=on_event)
            if result["correct"]:
                solved += 1
            else:
                failed += 1
                try:
                    await abandon_if_active(nss, client, attempt["id"])
                except (NSSCTFError, httpx.HTTPError) as exc:
                    out(f"[nss-auto] 放弃失败（忽略）: {exc}")
            results.append(result)
            if on_result:
                on_result(result)
    return {"solved": solved, "failed": failed, "results": results}
