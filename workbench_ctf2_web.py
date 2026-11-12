#!/usr/bin/env python3
"""灵枢 × CTF2 Agent 竞技场 —— 独立 WebUI 工作台控制台。

独立于灵枢主服务运行（默认 127.0.0.1:8081），提供浏览器工作台：
  - Agent 状态总览（身份/积分/环境配额/竞赛开关）
  - 可解题目列表（来源/题型/难度过滤，实时刷新）
  - 选题解题：标准/快速模式选择，实时事件流（SSE），Flag 与提交判定
  - 全自动挂机：自动选题 → 环境 → 解题 → 提交 → 成功选下一题（可启停/限额）
  - 任务记录与手动提交/笔记

凭据仅存内存（进程生命周期），支持环境变量预置：
  CTF2_API_TOKEN / LINGSHU_API_URL / LINGSHU_USER / LINGSHU_PASS /
  CTF2_LLM_PROVIDER / CTF2_MODEL_LEVEL

运行：
    python workbench_ctf2_web.py [--host 127.0.0.1] [--port 8081]
"""
from __future__ import annotations

import argparse
import asyncio
import secrets
import json
import os
import time
from pathlib import Path
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from workbench_ctf2_agent import (
    CTF2Client,
    CTF2Error,
    LingshuClient,
    WORKDIR,
    challenge_text,
    challenge_title,
    extract_flag,
    pick_next,
    resolve_item as agent_resolve_item,
    solve_challenge,
    source_of,
)
import workbench_nssctf_agent as nss_mod
from workbench_nssctf_agent import (
    NSSCTFClient,
    NSSCTFError,
    attempt_brief as nss_attempt_brief,
    auto_arena as nss_auto_arena,
    solve_attempt as nss_solve_attempt,
)
import workbench_agwars_agent as ag
from workbench_agwars_agent import (
    AgWarsClient,
    AgWarsError,
    credentials_brief as ag_credentials_brief,
    solve_hill as ag_solve_hill,
    auto_arena as ag_auto_arena,
)


# ────────────────────────────────────────────────────────────────
# 运行时状态
# ────────────────────────────────────────────────────────────────

CONFIG_FILE = Path(__file__).resolve().parent / "data" / "ctf2_workbench_config.json"
ENVS_FILE = Path(__file__).resolve().parent / "data" / "ctf2_workbench_envs.json"


def out(message: str) -> None:
    """工作台进程日志。run_auto/run_queue 等执行器无 emit 上下文时使用；
    与 agent 模块的 out 同名，避免执行器半路 NameError 崩溃。"""
    print(f"{time.strftime('%H:%M:%S')} {message}", flush=True)


def envs_load() -> dict[str, dict[str, Any]]:
    """环境注册表：challenge_id → {practice_id, title, started_at}。"""
    try:
        if ENVS_FILE.is_file():
            return json.loads(ENVS_FILE.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        pass
    return {}


def envs_save(reg: dict[str, dict[str, Any]]) -> None:
    ENVS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = ENVS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(reg, ensure_ascii=False, indent=1), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, ENVS_FILE)


ACTIVE_FILE = Path(__file__).resolve().parent / "data" / "ctf2_workbench_active.json"
# 同一题目的会话保护窗口：会话创建后在该窗口内不允许再次拉起新会话。
# 覆盖本地模型单题动辄十几分钟的解题时长；进程重启后依然生效（落盘）。
_ACTIVE_TTL_SECONDS = int(os.environ.get("CTF2_ACTIVE_TTL_SECONDS", "3600"))


def active_load() -> dict[str, dict[str, Any]]:
    """题目 → {session_id, started_at} 活跃会话登记（跨进程重启生效）。"""
    try:
        if ACTIVE_FILE.is_file():
            data = json.loads(ACTIVE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:  # noqa: BLE001 — 登记损坏按空处理
        pass
    return {}


def active_save(reg: dict[str, dict[str, Any]]) -> None:
    ACTIVE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = ACTIVE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(reg, ensure_ascii=False, indent=1), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, ACTIVE_FILE)


def active_claim(challenge_id: str) -> str | None:
    """抢占题目解题权；已被占用时返回现有 session_id（None=抢占成功）。"""
    reg = active_load()
    now = time.time()
    for cid, info in list(reg.items()):
        if now - float(info.get("started_at") or 0) > _ACTIVE_TTL_SECONDS:
            reg.pop(cid, None)
    existing = reg.get(challenge_id)
    if existing and existing.get("session_id"):
        return str(existing["session_id"])
    reg[challenge_id] = {"session_id": "", "started_at": now}
    active_save(reg)
    return None


def active_bind(challenge_id: str, session_id: str) -> None:
    reg = active_load()
    entry = reg.get(challenge_id) or {"started_at": time.time()}
    entry["session_id"] = str(session_id)
    reg[challenge_id] = entry
    active_save(reg)


def active_release(challenge_id: str) -> None:
    reg = active_load()
    if reg.pop(challenge_id, None) is not None:
        active_save(reg)


@dataclass
class Config:
    ctf2_token: str = os.environ.get("CTF2_API_TOKEN", "")
    lingshu_url: str = os.environ.get("LINGSHU_API_URL", "http://localhost:8080")
    lingshu_user: str = os.environ.get("LINGSHU_USER", "admin")
    lingshu_pass: str = os.environ.get("LINGSHU_PASS", "gdcp@2026")
    provider: str = os.environ.get("CTF2_LLM_PROVIDER", "deepseek")
    model: str = os.environ.get("CTF2_MODEL_LEVEL", "Min")
    mode: str = os.environ.get("CTF2_MODE", "fast")
    fast_summary: str = os.environ.get("CTF2_FAST_SUMMARY", "0")
    nssctf_token: str = os.environ.get("NSSCTF_AGENT_TOKEN", "")
    # AgWars 注册元信息（凭据本身存 data/agwars/credentials.json）
    agwars_model_group: str = os.environ.get("AGWARS_MODEL_GROUP", "other")
    agwars_model_url: str = os.environ.get("AGWARS_MODEL_URL", "")
    agwars_model_name: str = os.environ.get("AGWARS_MODEL_NAME", "")

    @classmethod
    def load(cls) -> "Config":
        """从 data/ctf2_workbench_config.json 恢复（0600，仅操作者本机使用）。"""
        cfg = cls()
        try:
            if CONFIG_FILE.is_file():
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                for key in ("ctf2_token", "lingshu_url", "lingshu_user",
                            "lingshu_pass", "provider", "model", "mode",
                            "fast_summary", "nssctf_token",
                            "agwars_model_group", "agwars_model_url",
                            "agwars_model_name"):
                    value = str(data.get(key) or "").strip()
                    if value:
                        setattr(cfg, key, value)
        except Exception:  # noqa: BLE001 — 配置损坏时回退默认
            pass
        return cfg

    def save(self) -> None:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {k: getattr(self, k) for k in (
            "ctf2_token", "lingshu_url", "lingshu_user", "lingshu_pass",
            "provider", "model", "mode", "fast_summary", "nssctf_token",
            "agwars_model_group", "agwars_model_url", "agwars_model_name")}
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONFIG_FILE)


@dataclass
class Job:
    id: str
    challenge_id: str
    title: str
    mode: str
    status: str = "queued"          # queued|running|done|error
    flag: str | None = None
    submitted: bool = False
    accepted: bool | None = None
    error: str | None = None
    session_id: str | None = None
    source: str = "practice"
    started_at: float = field(default_factory=time.time)
    events: deque = field(default_factory=lambda: deque(maxlen=800))
    task: asyncio.Task | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id, "challenge_id": self.challenge_id, "title": self.title,
            "mode": self.mode, "status": self.status, "flag": self.flag,
            "submitted": self.submitted, "accepted": self.accepted,
            "error": self.error, "session_id": self.session_id,
            "source": self.source, "started_at": self.started_at,
        }


class AutoState:
    def __init__(self) -> None:
        self.running = False
        self.mode = "fast"
        self.limit = 5
        self.source = "practice"
        self.category = ""
        self.difficulty = ""
        self.solved = 0
        self.failed = 0
        self.current = ""
        self.exclude: set[str] = set()
        self.cooldown: dict[str, float] = {}
        self.results: list[dict[str, Any]] = []
        self.stop_event = asyncio.Event()
        self.task: asyncio.Task | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "running": self.running, "mode": self.mode, "limit": self.limit,
            "source": self.source, "category": self.category,
            "difficulty": self.difficulty, "solved": self.solved,
            "failed": self.failed, "current": self.current,
            "results": self.results[-20:],
        }


STATE = {
    "config": Config.load(),
    "jobs": {},                      # job_id → Job
    "job_order": deque(maxlen=100),
    "auto": AutoState(),
    "queue": {
        "items": [],                 # [{challenge_id, title, item, challenge}]
        "running": False,
        "current": "",
        "results": [],
        "stop_event": asyncio.Event(),
        "task": None,
    },
    "nss": {                         # NSSCTF Agent Arena 分区
        "auto": {
            "running": False, "mode": "fast", "limit": 5,
            "solved": 0, "failed": 0, "current": "", "results": [],
        },
        "jobs": {},                  # job_id → Job（NSS 解题任务）
        "job_order": deque(maxlen=50),
        "stop_event": asyncio.Event(),
        "task": None,
    },
    "agwars": {                      # AgWars 攻防 Benchmark 分区
        "auto": {
            "running": False, "mode": "fast", "limit": 5,
            "solved": 0, "failed": 0, "current": "", "results": [],
        },
        "jobs": {},
        "job_order": deque(maxlen=50),
        "stop_event": asyncio.Event(),
        "task": None,
        "proxies": {},               # proxy_id → {slot_url, hill, created_at}
    },
    "subscribers": set(),            # asyncio.Queue
    "agent_cache": {"data": None, "at": 0.0},
}
LOCK = asyncio.Lock()


def broadcast(event: dict[str, Any]) -> None:
    for queue in list(STATE["subscribers"]):
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass


def args_like(cfg: Config, challenge_id: str, *, no_submit: bool = False):
    """构造 solve_challenge 所需的 args 命名空间。"""
    from types import SimpleNamespace

    return SimpleNamespace(
        provider=cfg.provider, model=cfg.model, timeout=1800,
        environment_polls=24, environment_poll_interval=5,
        practice_id="", source="all", no_submit=no_submit,
        keep_env=False, challenge_id=challenge_id,
        fast_summary=str(getattr(cfg, "fast_summary", "0")) == "1",
    )


def make_lingshu(cfg: Config) -> LingshuClient:
    return LingshuClient(cfg.lingshu_url, cfg.lingshu_user, cfg.lingshu_pass)


def make_ctf2(cfg: Config) -> CTF2Client:
    return CTF2Client(cfg.ctf2_token)


async def ensure_lingshu(cfg: Config, lingshu: LingshuClient) -> None:
    if not lingshu.token:
        await lingshu.login()


# ────────────────────────────────────────────────────────────────
# 解题任务（Web 版：事件入环 + 广播）
# ────────────────────────────────────────────────────────────────

async def run_job(job: Job) -> None:
    cfg: Config = STATE["config"]
    job.status = "running"
    broadcast({"type": "job", "job": job.snapshot()})
    no_submit = bool(getattr(job, "no_submit", False))

    def emit(event: dict[str, Any]) -> None:
        event = {"job_id": job.id, "ts": time.time(), **event}
        job.events.append(event)
        if event.get("type") == "session_started" and event.get("session_id"):
            job.session_id = event["session_id"]   # 会话创建即回报（诊断用）
            active_bind(job.challenge_id, job.session_id)   # 题目级活跃会话登记
        if event.get("type") == "env_ready":
            reg = envs_load()
            reg[job.challenge_id] = {
                "practice_id": str(getattr(job.item, "practice_id", "")
                                   or (job.item or {}).get("practice_id", "")),
                "title": job.title, "url": event.get("url", ""),
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S")}
            envs_save(reg)
        broadcast({"type": "job_event", "job_id": job.id, "event": event})

    ctf2 = make_ctf2(cfg)
    lingshu = make_lingshu(cfg)
    try:
        await ensure_lingshu(cfg, lingshu)
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
            result = await solve_challenge(
                ctf2, client, cfg.ctf2_token, lingshu,
                args_like(cfg, job.challenge_id, no_submit=no_submit),
                item=job.item, challenge=job.challenge, mode=job.mode,
                on_event=emit, auto_approve=True,
            )
        job.flag = result.get("flag")
        job.submitted = result.get("submitted", False)
        job.accepted = result.get("accepted")
        job.error = result.get("error")
        job.status = "done" if not job.error or job.accepted else "error"
        if job.accepted is False and not job.error:
            job.status = "done"
    except CTF2Error as exc:
        job.error = f"{exc.code}: {exc}"
        job.status = "error"
    except asyncio.CancelledError:
        job.status = "cancelled"
        job.error = "已取消"
        raise
    except Exception as exc:  # noqa: BLE001
        job.error = str(exc)
        job.status = "error"
    finally:
        # 任务终结即释放题目占位：允许下一次解题（失败重试/换模式重跑）
        active_release(job.challenge_id)
        broadcast({"type": "job", "job": job.snapshot()})
        emit({"type": "log", "message": f"任务结束：{job.status}"})


# ────────────────────────────────────────────────────────────────
# 全自动循环
# ────────────────────────────────────────────────────────────────

async def run_auto() -> None:
    auto: AutoState = STATE["auto"]
    cfg: Config = STATE["config"]
    auto.stop_event.clear()
    ctf2 = make_ctf2(cfg)
    lingshu = make_lingshu(cfg)
    try:
        await ensure_lingshu(cfg, lingshu)
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
            while not auto.stop_event.is_set() and auto.solved + auto.failed < auto.limit:
                try:
                    items = await ctf2.next_challenges(
                        client, cfg.ctf2_token, source=auto.source or "practice",
                        category=auto.category, difficulty=auto.difficulty, limit=100)
                except (CTF2Error, httpx.HTTPError) as exc:
                    broadcast({"type": "auto", "auto": auto.snapshot(),
                               "event": {"type": "log", "message": f"拉取题目失败: {exc}"}})
                    await asyncio.sleep(5)
                    continue
                item = pick_next(items, auto.exclude, auto.cooldown)
                if item is None:
                    broadcast({"type": "auto", "auto": auto.snapshot(),
                               "event": {"type": "log",
                                         "message": "没有可解题目（全部已解/排除），挂机结束"}})
                    break
                auto.current = challenge_title(item, str(item.get("id")))
                challenge_id = str(item.get("id"))
                broadcast({"type": "auto", "auto": auto.snapshot(),
                           "event": {"type": "log",
                                     "message": f"▶ {auto.current}"}})
                resolved = None
                try:
                    resolved = await agent_resolve_item(
                        ctf2, client, cfg.ctf2_token,
                        args_like(cfg, challenge_id), challenge_id)
                except (CTF2Error, httpx.HTTPError) as exc:
                    broadcast({"type": "auto", "auto": auto.snapshot(),
                               "event": {"type": "log",
                                         "message": f"题目解析失败: {exc}"}})
                if resolved is None:
                    auto.exclude.add(challenge_id)
                    continue
                claimed = active_claim(challenge_id)
                if claimed:
                    # 该题已有存活会话（例如上一轮遗留仍在跑）：跳过，避免一题多会话
                    auto.exclude.add(challenge_id)
                    broadcast({"type": "auto", "auto": auto.snapshot(),
                               "event": {"type": "log",
                                         "message": f"跳过 {challenge_id[:8]}：已有会话 {claimed[:8]} 在运行"}})
                    continue
                item, challenge = resolved
                job = Job(
                    id=f"a{int(time.time() * 1000) % 10**10}",
                    challenge_id=challenge_id, title=auto.current,
                    mode=auto.mode, source=source_of(item)[0],
                )
                job.item = item            # type: ignore[attr-defined]
                job.challenge = challenge  # type: ignore[attr-defined]
                STATE["jobs"][job.id] = job
                STATE["job_order"].append(job.id)
                await run_job(job)
                out(f"[auto] job 完成: {job.title[:24]} status={job.status} "
                    f"accepted={job.accepted} error={str(job.error or '')[:60]}")
                if job.accepted:
                    auto.solved += 1
                    auto.results.append({"title": job.title, "accepted": True,
                                         "flag": job.flag, "mode": job.mode})
                elif "agent_environment_limit" in str(job.error or ""):
                    auto.cooldown[challenge_id] = time.monotonic() + 90
                    auto.results.append({"title": job.title, "accepted": False,
                                         "error": "环境配额占用，90s 后重试",
                                         "mode": job.mode})
                else:
                    auto.failed += 1
                    auto.exclude.add(challenge_id)
                    auto.results.append({"title": job.title, "accepted": False,
                                         "flag": job.flag, "error": job.error,
                                         "mode": job.mode})
                broadcast({"type": "auto", "auto": auto.snapshot()})
    finally:
        auto.running = False
        auto.current = ""
        broadcast({"type": "auto", "auto": auto.snapshot(),
                   "event": {"type": "log", "message": "全自动挂机已停止"}})


# ────────────────────────────────────────────────────────────────
# FastAPI 应用
# ────────────────────────────────────────────────────────────────

app = FastAPI(title="Lingshu CTF2 Agent Workbench", docs_url=None, redoc_url=None)


class ConfigIn(BaseModel):
    ctf2_token: str | None = None
    lingshu_url: str | None = None
    lingshu_user: str | None = None
    lingshu_pass: str | None = None
    provider: str | None = None
    model: str | None = None
    mode: str | None = None
    fast_summary: str | None = None
    nssctf_token: str | None = None


class SolveIn(BaseModel):
    challenge_id: str
    mode: str | None = None
    practice_id: str | None = None
    no_submit: bool = False


class AutoIn(BaseModel):
    mode: str | None = None
    limit: int | None = None
    source: str | None = None
    category: str | None = None
    difficulty: str | None = None


class SubmitIn(BaseModel):
    challenge_id: str
    flag: str
    practice_id: str | None = None
    competition_id: str | None = None
    stage_id: str | None = None


class NoteIn(BaseModel):
    challenge_id: str
    kind: str = "finding"
    content: str


def ctf2_http_error(exc: Exception) -> HTTPException:
    """把 CTF2/网络/权限异常转成带明确信息的 JSON 错误（记日志便于诊断）。"""
    import logging

    logging.getLogger("ctf2_workbench").warning("CTF2 调用失败: %r", exc)
    if isinstance(exc, CTF2Error):
        detail = f"[{exc.code}] {exc.message or exc.hint}" + (
            f"（{exc.retry_after_ms}ms 后可重试）" if exc.retryable else "")
    else:
        detail = str(exc) or exc.__class__.__name__
    return HTTPException(status_code=502, detail=f"CTF2 平台错误：{detail}")


def require_config() -> Config:
    cfg: Config = STATE["config"]
    if not cfg.ctf2_token:
        raise HTTPException(status_code=400, detail="未配置 CTF2 Agent Token：请先在「连接设置」填写")
    return cfg


async def agent_snapshot(cfg: Config) -> dict[str, Any]:
    cache = STATE["agent_cache"]
    if cache["data"] and time.time() - cache["at"] < 30:
        return cache["data"]
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=15)) as client:
            me = await make_ctf2(cfg).whoami(client, cfg.ctf2_token)
        cache["data"] = me
        cache["at"] = time.time()
    except Exception as exc:  # noqa: BLE001
        cache["data"] = {"error": str(exc)}
        cache["at"] = time.time()
    return cache["data"]


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(CONSOLE_HTML, headers={"Cache-Control": "no-store"})


async def providers_snapshot(cfg: Config) -> list[dict[str, Any]]:
    """灵枢账户可用模型池（30s 缓存）；登录失败返回空列表。"""
    cache = STATE.setdefault("providers_cache", {"data": [], "at": 0.0})
    if cache["data"] and time.time() - cache["at"] < 30:
        return cache["data"]
    try:
        lingshu = make_lingshu(cfg)
        await ensure_lingshu(cfg, lingshu)
        cache["data"] = await lingshu.providers_detail()
        cache["at"] = time.time()
    except Exception:  # noqa: BLE001 — 凭据未配/密码错误时下拉留空
        cache["data"] = []
        cache["at"] = time.time()
    return cache["data"]


@app.get("/api/state")
async def api_state():
    cfg: Config = STATE["config"]
    jobs = [STATE["jobs"][jid].snapshot()
            for jid in reversed(STATE["job_order"]) if jid in STATE["jobs"]]
    agent = await agent_snapshot(cfg) if cfg.ctf2_token else None
    providers = await providers_snapshot(cfg)
    return {
        "configured": bool(cfg.ctf2_token),
        "agent": agent,
        "config": {"lingshu_url": cfg.lingshu_url, "provider": cfg.provider,
                   "model": cfg.model, "mode": cfg.mode,
                   "fast_summary": getattr(cfg, "fast_summary", "0") == "1"},
        "providers": providers,
        "jobs": jobs[:50],
        "auto": STATE["auto"].snapshot(),
        "queue": {
            "items": [{"challenge_id": q["challenge_id"], "title": q["title"]}
                      for q in STATE["queue"]["items"]],
            "running": STATE["queue"]["running"],
            "current": STATE["queue"]["current"],
            "results": STATE["queue"]["results"][-20:],
        },
        "envs_count": len(envs_load()),
        "workdir": str(WORKDIR),
    }


@app.get("/api/challenges")
async def api_challenges(source: str = "all", category: str = "",
                         difficulty: str = "", limit: int = 100):
    cfg = require_config()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
            items = await make_ctf2(cfg).next_challenges(
                client, cfg.ctf2_token, source=source, category=category,
                difficulty=difficulty, limit=limit)
    except (CTF2Error, PermissionError, httpx.HTTPError) as exc:
        raise ctf2_http_error(exc) from exc
    return {"items": [{
        "id": str(i.get("id")), "title": challenge_title(i),
        "category": i.get("category"), "difficulty": i.get("difficulty"),
        "score": i.get("score"), "solved": bool(i.get("is_solved")),
        "has_container": bool(i.get("has_container")),
        "submission_type": str(i.get("submission_type") or "flag"),
        "source": source_of(i)[0],
        "practice_ground_id": str(
            i.get("practice_ground_id")
            or (i.get("source") or {}).get("practice_ground_id") or ""),
        "competition_id": source_of(i)[1], "stage_id": source_of(i)[2],
    } for i in items]}


@app.post("/api/config")
async def api_config(data: ConfigIn):
    cfg: Config = STATE["config"]
    if data.ctf2_token is not None and data.ctf2_token.strip():
        cfg.ctf2_token = data.ctf2_token.strip()
        STATE["agent_cache"] = {"data": None, "at": 0.0}
    if data.nssctf_token is not None and data.nssctf_token.strip():
        cfg.nssctf_token = data.nssctf_token.strip()
    if data.fast_summary is not None:
        cfg.fast_summary = "1" if data.fast_summary.strip().lower() in ("1", "true", "yes", "on") else "0"
    for field_name in ("lingshu_url", "lingshu_user", "lingshu_pass",
                       "provider", "model", "mode"):
        value = getattr(data, field_name)
        if value:
            setattr(cfg, field_name, value.strip() if isinstance(value, str) else value)
    cfg.save()   # 持久化（0600），重启不再重填
    return {"ok": True, "configured": bool(cfg.ctf2_token)}


@app.post("/api/solve")
async def api_solve(data: SolveIn):
    cfg = require_config()
    running = [j for j in STATE["jobs"].values() if j.status in {"queued", "running"}]
    if running or STATE["queue"]["running"] or STATE["auto"].running:
        raise HTTPException(status_code=409,
                            detail="已有解题任务/队列/挂机在运行（环境配额默认 1）；请等待完成或先停止")
    # 题目级防重：该题已有存活会话（含 workbench 重启前的会话）时拒绝再次拉起
    claimed = active_claim(data.challenge_id)
    if claimed:
        raise HTTPException(
            status_code=409,
            detail=f"该题目已有进行中的灵枢会话（{claimed[:8]}）；"
                   "请等待其完成，或在灵枢会话列表停止该会话后重试")
    resolved = None
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
            resolved = await agent_resolve_item(
                make_ctf2(cfg), client, cfg.ctf2_token,
                args_like(cfg, data.challenge_id), data.challenge_id)
    except (CTF2Error, PermissionError, httpx.HTTPError) as exc:
        raise ctf2_http_error(exc) from exc
    if resolved is None:
        active_release(data.challenge_id)   # 未建会话，归还题目占位
        raise HTTPException(status_code=404, detail=f"未找到题目 {data.challenge_id}")
    item, challenge = resolved
    job = Job(
        id=f"j{int(time.time() * 1000) % 10**10}",
        challenge_id=data.challenge_id,
        title=challenge_title(item, data.challenge_id),
        mode=(data.mode or cfg.mode or "fast"),
        source=source_of(item)[0],
    )
    job.item = item            # type: ignore[attr-defined]
    job.challenge = challenge  # type: ignore[attr-defined]
    if data.practice_id:
        job.item["practice_id"] = data.practice_id  # type: ignore[index]
    job.no_submit = data.no_submit
    STATE["jobs"][job.id] = job
    STATE["job_order"].append(job.id)
    job.task = asyncio.create_task(run_job(job))
    broadcast({"type": "job", "job": job.snapshot()})
    return {"job_id": job.id}


@app.post("/api/auto")
async def api_auto(data: AutoIn):
    cfg = require_config()
    auto: AutoState = STATE["auto"]
    if auto.running:
        raise HTTPException(status_code=409, detail="全自动挂机已在运行")
    if STATE["queue"]["running"]:
        raise HTTPException(status_code=409, detail="队列正在执行；请先停止队列再启动挂机")
    auto.mode = (data.mode or cfg.mode or "fast")
    auto.limit = max(1, min(50, data.limit or 5))
    auto.source = data.source or "practice"
    auto.category = data.category or ""
    auto.difficulty = data.difficulty or ""
    auto.solved = auto.failed = 0
    auto.exclude = set()
    auto.cooldown = {}
    auto.results = []
    auto.running = True
    auto.stop_event.clear()
    auto.task = asyncio.create_task(run_auto())
    broadcast({"type": "auto", "auto": auto.snapshot()})
    return {"ok": True}


@app.post("/api/auto/stop")
async def api_auto_stop():
    auto: AutoState = STATE["auto"]
    if auto.running:
        auto.stop_event.set()
        task = auto.task
        if task is not None and not task.done():
            task.cancel()          # 硬停止：立即中断当前解题
        return {"ok": True, "message": "已停止（当前解题已中断）"}
    return {"ok": True, "message": "挂机未在运行"}


@app.post("/api/submit")
async def api_submit(data: SubmitIn):
    cfg = require_config()
    ctf2 = make_ctf2(cfg)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
            if data.competition_id and data.stage_id:
                result = await ctf2.submit_competition_flag(
                    client, cfg.ctf2_token, data.competition_id,
                    data.stage_id, data.challenge_id, data.flag)
            else:
                result = await ctf2.submit_flag(
                    client, cfg.ctf2_token, data.practice_id or "",
                    data.challenge_id, data.flag)
    except (CTF2Error, PermissionError, httpx.HTTPError) as exc:
        raise ctf2_http_error(exc) from exc
    return {"accepted": bool(result.get("accepted")), "attempt": result.get("attempt"),
            "raw": result}


@app.post("/api/note")
async def api_note(data: NoteIn):
    cfg = require_config()
    ctf2 = make_ctf2(cfg)
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
        ok = await ctf2.log_note(client, cfg.ctf2_token, data.challenge_id,
                                 data.kind, data.content)
    return {"ok": ok}


async def run_queue() -> None:
    """自定义队列执行器：按用户排列的顺序逐题解题提交。"""
    queue: dict[str, Any] = STATE["queue"]
    cfg: Config = STATE["config"]
    queue["stop_event"].clear()
    ctf2 = make_ctf2(cfg)
    lingshu = make_lingshu(cfg)
    env_retries: dict[str, int] = {}
    try:
        await ensure_lingshu(cfg, lingshu)
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
            while queue["items"] and not queue["stop_event"].is_set():
                entry = queue["items"][0]
                queue["current"] = entry["title"]
                broadcast({"type": "queue", "queue": queue_snapshot(),
                           "event": {"type": "log", "message": f"▶ {entry['title']}"}})
                job = Job(
                    id=f"q{int(time.time() * 1000) % 10**10}",
                    challenge_id=entry["challenge_id"], title=entry["title"],
                    mode=queue.get("mode") or cfg.mode or "fast",
                    source=source_of(entry["item"])[0],
                )
                job.item = entry["item"]            # type: ignore[attr-defined]
                job.challenge = entry["challenge"]  # type: ignore[attr-defined]
                job.no_submit = bool(queue.get("no_submit"))
                claimed = active_claim(entry["challenge_id"])
                if claimed:
                    msg = (f"[queue] {entry['title'][:22]} 已有会话 {claimed[:8]} 在运行，"
                           "60s 后再试")
                    out(msg)
                    broadcast({"type": "queue", "queue": queue_snapshot(),
                               "event": {"type": "log", "message": msg}})
                    await asyncio.sleep(60)
                    continue
                STATE["jobs"][job.id] = job
                STATE["job_order"].append(job.id)
                # 入队时只存了条目摘要：执行前按权威场地拉取完整题面与附件清单
                try:
                    _pid = str(entry["item"].get("practice_id") or "")
                    if _pid:
                        _fresh = await ctf2.practice_challenge(
                            client, cfg.ctf2_token, _pid, entry["challenge_id"])
                    else:
                        _fresh = None
                    if isinstance(_fresh, dict) and _fresh:
                        # 权威题面详情：题干/附件清单 + 容器标记（附件题据此
                        # 跳过环境启动，缺失会误报 NOT_FOUND）。
                        # 必须原地 update：job.challenge 已绑定同一对象，
                        # 重绑新字典会让 job 拿不到附件清单
                        entry["challenge"].update({
                            k: v for k, v in _fresh.items()
                            if k in ("content", "description", "files",
                                     "attachments", "body",
                                     "has_container", "has_attachments")})
                        if "has_container" in _fresh:
                            entry["item"]["has_container"] = bool(_fresh["has_container"])
                except Exception as exc:  # noqa: BLE001 — 详情拉取失败不阻断
                    out(f"[queue] 题面详情拉取失败（用摘要继续）: {exc}")
                await run_job(job)
                accepted = bool(job.accepted)
                env_limited = (not accepted) and (
                    "agent_environment_limit" in str(job.error or ""))
                if env_limited and env_retries.get(entry["challenge_id"], 0) < 6:
                    # 环境配额占用：90s 冷却后重试同一题（最多 6 次 ≈ 9 分钟窗口）
                    env_retries[entry["challenge_id"]] = (
                        env_retries.get(entry["challenge_id"], 0) + 1)
                    msg = (f"[queue] 环境配额占用，{entry['title'][:22]} 90s 后重试"
                           f"（第 {env_retries[entry['challenge_id']]} 次）")
                    out(msg)
                    broadcast({"type": "queue", "queue": queue_snapshot(),
                               "event": {"type": "log", "message": msg}})
                    await asyncio.sleep(90)
                else:
                    queue["results"].append({
                        "title": entry["title"], "accepted": accepted,
                        "flag": job.flag, "error": job.error, "mode": job.mode,
                    })
                    queue["items"].pop(0)   # 成败已入 results
                    if not accepted:
                        await asyncio.sleep(3)
                broadcast({"type": "queue", "queue": queue_snapshot()})
    finally:
        queue["running"] = False
        queue["current"] = ""
        broadcast({"type": "queue", "queue": queue_snapshot(),
                   "event": {"type": "log", "message": "队列执行结束"}})


def queue_snapshot() -> dict[str, Any]:
    queue: dict[str, Any] = STATE["queue"]
    return {
        "items": [{"challenge_id": q["challenge_id"], "title": q["title"]}
                  for q in queue["items"]],
        "running": queue["running"], "current": queue["current"],
        "results": queue["results"][-20:],
        "mode": queue.get("mode"), "no_submit": bool(queue.get("no_submit")),
    }


class QueueRunIn(BaseModel):
    mode: str | None = None
    no_submit: bool = False


class QueueMoveIn(BaseModel):
    challenge_id: str
    delta: int = 1            # +1 上移 / -1 下移


class QueueAddIn(SolveIn):
    item: dict | None = None


@app.post("/api/queue/add")
async def queue_add(data: QueueAddIn):
    cfg = require_config()
    queue: dict[str, Any] = STATE["queue"]
    if queue["running"]:
        raise HTTPException(status_code=409, detail="队列执行中，不能编辑")
    if any(q["challenge_id"] == data.challenge_id for q in queue["items"]):
        raise HTTPException(status_code=409, detail="该题目已在队列中")
    if len(queue["items"]) >= 50:
        raise HTTPException(status_code=409, detail="队列最多 50 题")
    challenge_id = data.challenge_id
    if data.item:
        # 前端随请求携带条目（含 practice_ground_id）→ 入队即锁定，
        # 免受平台推荐列表轮换影响；详情在执行时按权威场地拉取。
        raw = dict(data.item)
        raw.setdefault("id", challenge_id)
        raw["id"] = challenge_id
        source_type = str(raw.get("source") or "practice")
        item = {**raw, "id": challenge_id,
                "practice_id": str(raw.get("practice_ground_id") or "")}
        challenge = {"title": raw.get("title") or raw.get("name") or challenge_id,
                     "name": raw.get("title") or raw.get("name") or challenge_id,
                     "content": raw.get("content") or raw.get("description") or "",
                     "files": raw.get("files") or []}
        if "has_container" in raw:
            # 附件题（无容器）标记必须随队列条目存活到执行时，
            # 否则执行器会误调环境启动接口 → 平台 NOT_FOUND
            challenge["has_container"] = bool(raw["has_container"])
        title = challenge_title(item, challenge_id)
    else:
        resolved = None
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(90, connect=30)) as client:
                resolved = await agent_resolve_item(
                    make_ctf2(cfg), client, cfg.ctf2_token,
                    args_like(cfg, challenge_id), challenge_id)
        except (CTF2Error, PermissionError, httpx.HTTPError) as exc:
            raise ctf2_http_error(exc) from exc
        if resolved is None:
            raise HTTPException(status_code=404, detail=f"未找到题目 {challenge_id}")
        item, challenge = resolved
        title = challenge_title(item, challenge_id)
    queue["items"].append({
        "challenge_id": challenge_id, "title": title,
        "item": item, "challenge": challenge,
    })
    broadcast({"type": "queue", "queue": queue_snapshot()})
    return {"ok": True, "size": len(queue["items"])}




@app.post("/api/queue/remove")
async def queue_remove(data: QueueMoveIn):
    queue: dict[str, Any] = STATE["queue"]
    if queue["running"]:
        raise HTTPException(status_code=409, detail="队列执行中，不能编辑")
    queue["items"] = [q for q in queue["items"] if q["challenge_id"] != data.challenge_id]
    broadcast({"type": "queue", "queue": queue_snapshot()})
    return {"ok": True}


@app.post("/api/queue/move")
async def queue_move(data: QueueMoveIn):
    queue: dict[str, Any] = STATE["queue"]
    if queue["running"]:
        raise HTTPException(status_code=409, detail="队列执行中，不能编辑")
    items = queue["items"]
    idx = next((i for i, q in enumerate(items) if q["challenge_id"] == data.challenge_id), -1)
    target = idx - (1 if data.delta > 0 else -1)   # delta=+1 上移（先执行）
    if idx == -1:
        raise HTTPException(status_code=404, detail="题目不在队列中")
    if 0 <= target < len(items):
        items[idx], items[target] = items[target], items[idx]
    broadcast({"type": "queue", "queue": queue_snapshot()})
    return {"ok": True}


@app.post("/api/queue/clear")
async def queue_clear():
    queue: dict[str, Any] = STATE["queue"]
    if queue["running"]:
        raise HTTPException(status_code=409, detail="队列执行中，不能编辑")
    queue["items"] = []
    broadcast({"type": "queue", "queue": queue_snapshot()})
    return {"ok": True}


@app.post("/api/queue/run")
async def queue_run(data: QueueRunIn):
    cfg = require_config()
    queue: dict[str, Any] = STATE["queue"]
    if queue["running"] or STATE["auto"].running:
        raise HTTPException(status_code=409, detail="队列/挂机已在运行")
    running = [j for j in STATE["jobs"].values() if j.status in {"queued", "running"}]
    if running:
        raise HTTPException(status_code=409, detail="已有单题任务在运行")
    if not queue["items"]:
        raise HTTPException(status_code=400, detail="队列为空：先从题目列表加入")
    queue["mode"] = (data.mode or cfg.mode or "fast")
    queue["no_submit"] = bool(data.no_submit)
    queue["running"] = True
    queue["stop_event"] = asyncio.Event()
    queue["task"] = asyncio.create_task(run_queue())
    broadcast({"type": "queue", "queue": queue_snapshot()})
    return {"ok": True, "size": len(queue["items"])}


@app.post("/api/queue/stop")
async def queue_stop():
    queue: dict[str, Any] = STATE["queue"]
    if queue["running"]:
        queue["stop_event"].set()
        task = queue.get("task")
        if task is not None and not task.done():
            task.cancel()          # 硬停止：立即中断当前解题
        return {"ok": True, "message": "已停止（当前解题已中断）"}
    return {"ok": True, "message": "队列未在运行"}


@app.get("/api/envs")
async def api_envs():
    """环境注册表（含状态探测）。"""
    cfg = require_config()
    reg = envs_load()
    out_list = []
    if reg and cfg.ctf2_token:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=15)) as client:
            for cid, info in list(reg.items()):
                status = "未知"
                remaining = None
                try:
                    data = (await make_ctf2(cfg).get_environment(
                        client, cfg.ctf2_token,
                        info.get("practice_id") or "", cid)).get("data") or {}
                    status = str(data.get("status") or "未知")
                    remaining = data.get("remaining_seconds")
                except Exception:  # noqa: BLE001
                    status = "不可达"
                out_list.append({"challenge_id": cid, **info,
                                 "status": status, "remaining": remaining})
    return {"envs": out_list}


@app.post("/api/envs/destroy")
async def api_envs_destroy(data: dict):
    """销毁指定题目环境并移出注册表。"""
    cfg = require_config()
    cid = str(data.get("challenge_id") or "")
    reg = envs_load()
    info = reg.get(cid)
    if not info:
        raise HTTPException(status_code=404, detail="该题目不在环境注册表中")
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
        await make_ctf2(cfg).destroy_environment(
            client, cfg.ctf2_token, info.get("practice_id") or "", cid)
    reg.pop(cid, None)
    envs_save(reg)
    broadcast({"type": "envs", "envs": reg})
    return {"ok": True, "message": "环境已销毁"}


@app.post("/api/envs/destroy_all")
async def api_envs_destroy_all():
    """销毁注册表中全部环境（异常中断遗留的也一并清理）。"""
    cfg = require_config()
    reg = envs_load()
    destroyed, failed = [], []
    async with httpx.AsyncClient(timeout=httpx.Timeout(90, connect=30)) as client:
        for cid, info in list(reg.items()):
            try:
                await make_ctf2(cfg).destroy_environment(
                    client, cfg.ctf2_token, info.get("practice_id") or "", cid)
                destroyed.append(cid)
            except Exception as exc:  # noqa: BLE001
                failed.append({"challenge_id": cid, "error": str(exc)[:80]})
            reg.pop(cid, None)
    envs_save(reg)
    broadcast({"type": "envs", "envs": reg})
    return {"ok": True, "destroyed": destroyed, "failed": failed}


# ════════════════════════════════════════════════════════════════
# NSSCTF Agent Arena（独立子页面）
# ════════════════════════════════════════════════════════════════

def require_nss_config() -> Config:
    cfg: Config = STATE["config"]
    if not cfg.nssctf_token:
        raise HTTPException(status_code=400, detail="未配置 NSSCTF Agent Token（连接设置中填写）")
    return cfg


def nss_http_error(exc: Exception) -> HTTPException:
    """把 NSSCTF/网络/权限异常转成带明确信息的 JSON 错误。"""
    import logging

    logging.getLogger("ctf2_workbench").warning("NSSCTF 调用失败: %r", exc)
    if isinstance(exc, NSSCTFError):
        detail = f"[{exc.code}] {exc.message}"
    else:
        detail = str(exc) or exc.__class__.__name__
    return HTTPException(status_code=502, detail=f"NSSCTF 平台错误：{detail}")


def make_nss(cfg: Config) -> NSSCTFClient:
    return NSSCTFClient(cfg.nssctf_token)


def nss_jobs_snapshot() -> list[dict[str, Any]]:
    nss: dict[str, Any] = STATE["nss"]
    return [nss["jobs"][jid].snapshot() for jid in list(nss["job_order"])[-20:]]


async def nss_state_payload(client: httpx.AsyncClient, cfg: Config) -> dict[str, Any]:
    """NSS 页面数据：Agent 概况 + 当前题 + 挂机进度 + 任务记录。"""
    data = await make_nss(cfg).current(client)
    nss: dict[str, Any] = STATE["nss"]
    return {
        "configured": True,
        "agent": data.get("agent") or {},
        "attempt": nss_attempt_brief(data.get("attempt")),
        "auto": nss["auto"],
        "jobs": nss_jobs_snapshot(),
    }


@app.get("/api/nss/state")
async def api_nss_state():
    cfg = require_nss_config()
    async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=15)) as client:
        try:
            payload = await nss_state_payload(client, cfg)
        except NSSCTFError as exc:
            raise nss_http_error(exc) from exc
    return payload


@app.post("/api/nss/next")
async def api_nss_next():
    """随机领题（已有未结束题时复用同一道）。"""
    cfg = require_nss_config()
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
        try:
            data = await make_nss(cfg).next_challenge(client)
        except (NSSCTFError, PermissionError) as exc:
            raise nss_http_error(exc) from exc
    return {"agent": data.get("agent") or {},
            "attempt": nss_attempt_brief(data.get("attempt")),
            "reused": bool(data.get("reused"))}


class NssSolveIn(BaseModel):
    mode: str | None = None


async def nss_run_job(job: Job, attempt: dict[str, Any]) -> None:
    """NSS 解题任务：附件/靶机 → 灵枢 → 自动提交。"""
    cfg: Config = STATE["config"]
    nss: dict[str, Any] = STATE["nss"]
    job.status = "running"
    broadcast({"type": "job_event", "job_id": job.id,
               "event": {"job_id": job.id, "ts": time.time(), "type": "log",
                         "message": f"▶ {job.title}"}})

    def emit(event: dict[str, Any]) -> None:
        event = {"job_id": job.id, "ts": time.time(), **event}
        job.events.append(event)
        if event.get("type") == "session_started" and event.get("session_id"):
            job.session_id = event["session_id"]
        broadcast({"type": "job_event", "job_id": job.id, "event": event})

    ctf2 = None
    lingshu = make_lingshu(cfg)
    try:
        await ensure_lingshu(cfg, lingshu)
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
            result = await nss_solve_attempt(
                lingshu, args_like(cfg, str(attempt.get("id"))),
                make_nss(cfg), client, attempt, mode=job.mode, on_event=emit)
        job.flag = result.get("flag")
        job.submitted = bool(result.get("submitted"))
        job.accepted = result.get("correct")
        job.error = result.get("error")
        job.status = "done" if (job.accepted or not job.error) else "error"
        if job.accepted is False:
            job.status = "done"
    except asyncio.CancelledError:
        job.status = "cancelled"
        job.error = "已取消"
        raise
    except Exception as exc:  # noqa: BLE001
        job.error = str(exc)
        job.status = "error"
    finally:
        broadcast({"type": "nss", "nss": nss_state_lite()})
        broadcast({"type": "job_event", "job_id": job.id,
                   "event": {"job_id": job.id, "ts": time.time(), "type": "log",
                             "message": f"任务结束：{job.status}"}})


def nss_state_lite() -> dict[str, Any]:
    nss: dict[str, Any] = STATE["nss"]
    return {"auto": dict(nss["auto"]), "jobs": nss_jobs_snapshot()}


@app.post("/api/nss/solve")
async def api_nss_solve(data: NssSolveIn):
    """解当前进行中的题（无则自动领一道）。"""
    cfg = require_nss_config()
    nss: dict[str, Any] = STATE["nss"]
    if nss["auto"]["running"]:
        raise HTTPException(status_code=409, detail="NSS 挂机运行中，请先停止")
    if any(j.status in {"queued", "running"} for j in nss["jobs"].values()):
        raise HTTPException(status_code=409, detail="已有 NSS 解题任务在运行")
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
        try:
            cur = await make_nss(cfg).current(client)
        except (NSSCTFError, PermissionError) as exc:
            raise nss_http_error(exc) from exc
        attempt = cur.get("attempt")
        if not attempt:
            attempt = (await make_nss(cfg).next_challenge(client)).get("attempt")
        if not attempt:
            raise HTTPException(status_code=409, detail="平台未返回题目")
    problem = attempt.get("problem") or {}
    job = Job(
        id=f"n{int(time.time() * 1000) % 10**10}",
        challenge_id=str(attempt.get("id")),
        title=str(problem.get("title") or f"attempt-{attempt.get('id')}"),
        mode=data.mode or cfg.mode or "fast", source="nss",
    )
    nss["jobs"][job.id] = job
    nss["job_order"].append(job.id)
    job.task = asyncio.create_task(nss_run_job(job, attempt))
    broadcast({"type": "nss", "nss": nss_state_lite()})
    return {"job_id": job.id}


class NssSubmitIn(BaseModel):
    flag: str


@app.post("/api/nss/submit")
async def api_nss_submit(data: NssSubmitIn):
    """手动提交 flag 到当前 active attempt。"""
    cfg = require_nss_config()
    flag = extract_flag(data.flag) or data.flag.strip()
    if not flag:
        raise HTTPException(status_code=400, detail="flag 为空")
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
        nss_client = make_nss(cfg)
        try:
            cur = await nss_client.current(client)
            attempt = cur.get("attempt")
            if not attempt:
                raise HTTPException(status_code=409, detail="当前没有进行中的题目")
            result = await nss_client.submit_flag(client, attempt.get("id"), flag)
        except (NSSCTFError, PermissionError) as exc:
            raise nss_http_error(exc) from exc
    return {"correct": bool(result.get("correct")),
            "remaining_wrong_attempts": result.get("remaining_wrong_attempts")}


@app.post("/api/nss/abandon")
async def api_nss_abandon():
    cfg = require_nss_config()
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=30)) as client:
        nss_client = make_nss(cfg)
        try:
            cur = await nss_client.current(client)
            attempt = cur.get("attempt")
            if not attempt:
                return {"ok": True, "message": "当前没有进行中的题目"}
            if str(attempt.get("state_label") or "") != "active":
                return {"ok": True,
                        "message": f"题目已结算（{attempt.get('state_label')}）"}
            await nss_client.abandon(client, attempt.get("id"))
        except (NSSCTFError, PermissionError) as exc:
            raise nss_http_error(exc) from exc
    return {"ok": True, "message": "已放弃，可领取下一题"}


class NssAutoIn(BaseModel):
    mode: str | None = None
    limit: int | None = None


async def nss_run_auto(mode: str, limit: int) -> None:
    """NSS 全自动：领题 → 解题 → 提交 → 错/未解出放弃 → 下一题。"""
    nss: dict[str, Any] = STATE["nss"]
    cfg: Config = STATE["config"]
    lingshu = make_lingshu(cfg)
    stop_event: asyncio.Event = nss["stop_event"]
    stop_event.clear()
    auto = nss["auto"]
    auto.update({"running": True, "solved": 0, "failed": 0, "current": "",
                 "results": []})
    broadcast({"type": "nss", "nss": nss_state_lite()})

    def on_progress(info: dict[str, Any]) -> None:
        auto["current"] = info.get("current", "")
        auto["solved"] = info.get("solved", auto["solved"])
        auto["failed"] = info.get("failed", auto["failed"])
        broadcast({"type": "nss", "nss": nss_state_lite()})

    def on_result(result: dict[str, Any]) -> None:
        auto["results"].append({
            "title": result.get("title"), "flag": result.get("flag"),
            "correct": result.get("correct"), "error": result.get("error"),
            "mode": result.get("mode")})
        broadcast({"type": "nss", "nss": nss_state_lite()})

    # 事件流：当前题建临时 Job 承载（与手动解题共用前端渲染）
    holder: dict[str, Any] = {"job": None}

    def on_event(event: dict[str, Any]) -> None:
        job = holder.get("job")
        if job is None:
            return
        emit_event = {"job_id": job.id, "ts": time.time(), **event}
        job.events.append(emit_event)
        if event.get("type") == "session_started" and event.get("session_id"):
            job.session_id = event["session_id"]
        broadcast({"type": "job_event", "job_id": job.id, "event": emit_event})

    def wrap_progress(info: dict[str, Any]) -> None:
        # 每道新题换一个 Job 承载事件流
        job = Job(id=f"n{int(time.time() * 1000) % 10**10}",
                  challenge_id="auto", title=info.get("current", ""),
                  mode=mode, source="nss")
        nss["jobs"][job.id] = job
        nss["job_order"].append(job.id)
        job.status = "running"
        holder["job"] = job
        on_progress(info)

    try:
        await ensure_lingshu(cfg, lingshu)
        await nss_auto_arena(
            lingshu, args_like(cfg, "auto"), make_nss(cfg),
            mode=mode, limit=limit,
            on_result=on_result, on_progress=wrap_progress, on_event=on_event,
            stop_event=stop_event)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        out(f"[nss-auto] 挂机异常终止: {exc}")
        auto["results"].append({"title": auto.get("current") or "-",
                                "correct": False, "error": str(exc)[:120],
                                "mode": mode})
    finally:
        for job in nss["jobs"].values():
            if job.status == "running":
                job.status = "cancelled"
        auto["running"] = False
        auto["current"] = ""
        broadcast({"type": "nss", "nss": nss_state_lite()})


@app.post("/api/nss/auto")
async def api_nss_auto(data: NssAutoIn):
    cfg = require_nss_config()
    nss: dict[str, Any] = STATE["nss"]
    if nss["auto"]["running"]:
        raise HTTPException(status_code=409, detail="NSS 挂机已在运行")
    if any(j.status in {"queued", "running"} for j in nss["jobs"].values()):
        raise HTTPException(status_code=409, detail="已有 NSS 解题任务在运行")
    mode = data.mode or cfg.mode or "fast"
    limit = max(1, min(50, data.limit or 5))
    nss["task"] = asyncio.create_task(nss_run_auto(mode, limit))
    return {"ok": True}


@app.post("/api/nss/auto/stop")
async def api_nss_auto_stop():
    nss: dict[str, Any] = STATE["nss"]
    if nss["auto"]["running"]:
        nss["stop_event"].set()
        task = nss.get("task")
        if task is not None and not task.done():
            task.cancel()          # 硬停止：立即中断当前解题
        nss["auto"]["running"] = False
        return {"ok": True, "message": "已停止（当前解题已中断）"}
    return {"ok": True, "message": "挂机未在运行"}


# ════════════════════════════════════════════════════════════════
# AgWars 智能渗透 Agent 攻防 Benchmark（独立子页面）
# ════════════════════════════════════════════════════════════════

def require_agwars() -> AgWarsClient:
    aw = AgWarsClient()
    if not (aw.token and aw.secret and aw.trace):
        raise HTTPException(
            status_code=400,
            detail="尚未注册 AgWars Agent：请在本页填写模型信息后点「注册 Agent」"
                   "（每设备最多 2 个，api_secret 仅本机 0600 保存）")
    return aw


def agwars_http_error(exc: Exception) -> HTTPException:
    import logging

    logging.getLogger("ctf2_workbench").warning("AgWars 调用失败: %r", exc)
    detail = str(exc) or exc.__class__.__name__
    if isinstance(exc, AgWarsError) and exc.status == 403 and "verification" in detail.lower():
        detail += "（请先完成模型验证）"
    return HTTPException(status_code=502, detail=f"AgWars 平台错误：{detail}")


def agwars_snapshot() -> dict[str, Any]:
    state: dict[str, Any] = STATE["agwars"]
    return {
        "auto": dict(state["auto"]),
        "jobs": [state["jobs"][jid].snapshot() for jid in list(state["job_order"])[-20:]],
        "credentials": ag_credentials_brief(),
    }


async def agwars_public_config(client: httpx.AsyncClient) -> dict[str, Any]:
    try:
        return await AgWarsClient().public_config(client)
    except Exception:  # noqa: BLE001 — 公开配置失败不影响页面
        return {}


@app.get("/api/agwars/state")
async def api_agwars_state():
    async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=15)) as client:
        config = await agwars_public_config(client)
    payload = agwars_snapshot()
    active = config.get("active_hills") or {}
    creds = payload["credentials"]
    shard = str(creds.get("shard") or "")
    # 未注册时不知道分片，绝不能猜测——跨分片访问会被平台判定违规
    hills = active.get(shard) if (shard and isinstance(active, dict)) else None
    payload["platform"] = {
        "active_hills": list(hills or []),
        "shards": sorted(active.keys()) if isinstance(active, dict) else [],
        "hills_by_shard": active if isinstance(active, dict) else {},
        "rounds": config.get("rounds"),
        "capacity": (config.get("capacity") or {}).get("slots"),
        "formal_end": config.get("formal_end"),
        "slot_required": config.get("slot_required"),
        "shard": shard,
    }
    return payload


class AgWarsRegisterIn(BaseModel):
    model_group: str
    model_url: str = ""
    model_name: str = ""


@app.post("/api/agwars/register")
async def api_agwars_register(data: AgWarsRegisterIn):
    """注册 Agent（无签名，带设备标识）。每设备最多 2 个，失败会明确报错。"""
    cfg: Config = STATE["config"]
    group = (data.model_group or "").strip().lower()
    if group not in ag.MODEL_GROUPS:
        raise HTTPException(status_code=400,
                            detail=f"model_group 不在支持列表：{', '.join(ag.MODEL_GROUPS)}")
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=20)) as client:
        try:
            body = await AgWarsClient().register(
                client, model_group=group,
                model_url=(data.model_url or cfg.agwars_model_url).strip(),
                model_name=(data.model_name or cfg.agwars_model_name).strip())
        except AgWarsError as exc:
            raise agwars_http_error(exc) from exc
    cfg.agwars_model_group = group
    cfg.agwars_model_url = (data.model_url or cfg.agwars_model_url).strip()
    cfg.agwars_model_name = (data.model_name or cfg.agwars_model_name).strip()
    cfg.save()
    return {"ok": True, "credentials": ag_credentials_brief(),
            "shard": body.get("shard"), "score_total": body.get("score_total"),
            "identity_path": str(ag.IDENTITY_FILE)}


async def _attest_model_answer(cfg: Config, prompt: str) -> str:
    """用灵枢同款模型回答平台的模型验证题（关闭思考，避免只出 reasoning）。"""
    from agentscope.message import UserMsg

    from core.auth import get_user_by_username
    from core.config import RuntimeConfig
    from LLM.model import create_model

    user = get_user_by_username(cfg.lingshu_user) or {}
    runtime = RuntimeConfig.from_env(user_id=user.get("id"))
    model = create_model(
        provider=cfg.provider, model=cfg.model or None,
        thinking_intensity="off", temperature=0.0,
        web_search=False, config=runtime)

    async def _collect() -> str:
        result = await model([UserMsg(name="user", content=prompt)])
        if hasattr(result, "get_text_content"):
            return str(result.get_text_content() or "")
        parts: list[str] = []
        async for chunk in result:
            content = getattr(chunk, "content", None)
            if not content:
                continue
            for item in (content if isinstance(content, list) else [content]):
                kind = str(getattr(item, "type", ""))
                if "thinking" in kind:
                    continue
                parts.append(str(getattr(item, "text", "") or ""))
        return "".join(parts)

    return (await asyncio.wait_for(_collect(), timeout=120)).strip()


@app.post("/api/agwars/verify-model")
async def api_agwars_verify_model():
    """模型验证：challenge → 本方模型作答 → verify（平台据此放行 slot/flag_submit）。"""
    cfg: Config = STATE["config"]
    aw = require_agwars()
    async with httpx.AsyncClient(timeout=httpx.Timeout(180, connect=20)) as client:
        try:
            challenge = await aw.model_challenge(client)
            nonce = str(challenge.get("nonce") or "")
            prompt = str(challenge.get("prompt") or "")
            if not nonce or not prompt:
                raise HTTPException(status_code=502, detail="平台未返回模型验证题")
            answer = await _attest_model_answer(cfg, prompt)
            if not answer:
                raise HTTPException(
                    status_code=502,
                    detail="本地模型未返回答案（检查 provider/model 配置与思考开关）")
            verified = await aw.model_verify(client, nonce=nonce, answer=answer)
        except AgWarsError as exc:
            raise agwars_http_error(exc) from exc
        except asyncio.TimeoutError as exc:
            raise HTTPException(status_code=504, detail="模型作答超时（120s）") from exc
    return {"ok": True, "verified": bool(verified.get("verified")),
            "vendor": verified.get("vendor"), "answer_preview": answer[:80]}


class AgWarsHillIn(BaseModel):
    hill: str


@app.post("/api/agwars/slot/acquire")
async def api_agwars_slot_acquire(data: AgWarsHillIn):
    aw = require_agwars()
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=20)) as client:
        try:
            return await aw.slot_acquire(client, data.hill.strip())
        except AgWarsError as exc:
            raise agwars_http_error(exc) from exc


@app.post("/api/agwars/slot/poll")
async def api_agwars_slot_poll():
    aw = require_agwars()
    async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=15)) as client:
        try:
            return await aw.slot_poll(client)
        except AgWarsError as exc:
            raise agwars_http_error(exc) from exc


@app.post("/api/agwars/slot/keepalive")
async def api_agwars_slot_keepalive():
    aw = require_agwars()
    async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=15)) as client:
        try:
            return await aw.slot_keepalive(client)
        except AgWarsError as exc:
            raise agwars_http_error(exc) from exc


@app.post("/api/agwars/slot/release")
async def api_agwars_slot_release():
    aw = require_agwars()
    async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=15)) as client:
        try:
            return await aw.slot_release(client)
        except AgWarsError as exc:
            raise agwars_http_error(exc) from exc


class AgWarsSolveIn(BaseModel):
    hill: str
    mode: str | None = None


def agwars_self_base() -> str:
    """灵枢访问本工作台的地址（代理入口）。"""
    port = STATE.get("self_port") or int(os.environ.get("WORKBENCH_PORT", "8081"))
    return f"http://127.0.0.1:{port}"


async def agwars_run_job(job: Job, hill: str, mode: str) -> None:
    cfg: Config = STATE["config"]
    state: dict[str, Any] = STATE["agwars"]
    job.status = "running"

    def emit(event: dict[str, Any]) -> None:
        event = {"job_id": job.id, "ts": time.time(), **event}
        job.events.append(event)
        if event.get("type") == "session_started" and event.get("session_id"):
            job.session_id = event["session_id"]
        broadcast({"type": "job_event", "job_id": job.id, "event": event})

    lingshu = make_lingshu(cfg)
    aw = require_agwars()
    proxy_holder: dict[str, str] = {}   # finally 需要，必须在 try 之前绑定
    try:
        await ensure_lingshu(cfg, lingshu)

        def _expose(slot_url: str) -> str:
            proxy_id = agwars_proxy_register(hill, slot_url)
            proxy_holder["id"] = proxy_id
            return f"{agwars_self_base()}/agwars/proxy/{proxy_id}"

        async with httpx.AsyncClient(timeout=httpx.Timeout(90, connect=30)) as client:
            result = await ag_solve_hill(
                lingshu, args_like(cfg, hill), aw, client, hill,
                mode=mode, on_event=emit, expose_url_factory=_expose)
        job.flag = result.get("flag")
        job.submitted = bool(result.get("submitted"))
        job.accepted = result.get("accepted")
        job.error = result.get("error")
        job.status = "done" if (job.accepted or not job.error) else "error"
        if job.accepted is False:
            job.status = "done"
    except asyncio.CancelledError:
        job.status = "cancelled"
        job.error = "已取消"
        raise
    except Exception as exc:  # noqa: BLE001
        job.error = str(exc)
        job.status = "error"
    finally:
        active_release(hill)
        if proxy_holder.get("id"):
            agwars_proxy_release(proxy_holder["id"])
        broadcast({"type": "agwars", "agwars": agwars_snapshot()})
        broadcast({"type": "job_event", "job_id": job.id,
                   "event": {"job_id": job.id, "ts": time.time(), "type": "log",
                             "message": f"任务结束：{job.status}"}})


@app.post("/api/agwars/solve")
async def api_agwars_solve(data: AgWarsSolveIn):
    cfg = require_agwars()
    state: dict[str, Any] = STATE["agwars"]
    if state["auto"]["running"]:
        raise HTTPException(status_code=409, detail="AgWars 挂机运行中，请先停止")
    if any(j.status in {"queued", "running"} for j in state["jobs"].values()):
        raise HTTPException(status_code=409, detail="已有 AgWars 解题任务在运行")
    hill = data.hill.strip()
    if not hill:
        raise HTTPException(status_code=400, detail="hill 不能为空")
    claimed = active_claim(f"agwars:{hill}")
    if claimed:
        raise HTTPException(status_code=409,
                            detail=f"该题号已有进行中的会话（{claimed[:8]}）")
    mode = data.mode or cfg.mode or "fast"
    job = Job(id=f"g{int(time.time() * 1000) % 10**10}", challenge_id=hill,
              title=f"AgWars {hill}", mode=mode, source="agwars")
    state["jobs"][job.id] = job
    state["job_order"].append(job.id)
    job.task = asyncio.create_task(agwars_run_job(job, hill, mode))
    broadcast({"type": "agwars", "agwars": agwars_snapshot()})
    return {"job_id": job.id}


class AgWarsFlagIn(BaseModel):
    flag: str


@app.post("/api/agwars/submit")
async def api_agwars_submit(data: AgWarsFlagIn):
    aw = require_agwars()
    flag = extract_flag(data.flag) or data.flag.strip()
    if not flag:
        raise HTTPException(status_code=400, detail="flag 为空")
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=20)) as client:
        try:
            result = await aw.submit_flag(client, flag)
        except AgWarsError as exc:
            raise agwars_http_error(exc) from exc
    return {"ok": True, "raw": result}


class AgWarsAutoIn(BaseModel):
    mode: str | None = None
    limit: int | None = None
    hills: list[str] | None = None


async def agwars_run_auto(mode: str, limit: int, hills: list[str] | None) -> None:
    state: dict[str, Any] = STATE["agwars"]
    cfg: Config = STATE["config"]
    auto = state["auto"]
    stop_event: asyncio.Event = state["stop_event"]
    stop_event.clear()
    auto.update({"running": True, "solved": 0, "failed": 0,
                 "current": "", "results": []})
    broadcast({"type": "agwars", "agwars": agwars_snapshot()})
    lingshu = make_lingshu(cfg)
    holder: dict[str, Any] = {"job": None}

    def on_event(event: dict[str, Any]) -> None:
        job = holder.get("job")
        if job is None:
            return
        item = {"job_id": job.id, "ts": time.time(), **event}
        job.events.append(item)
        if event.get("type") == "session_started" and event.get("session_id"):
            job.session_id = event["session_id"]
        broadcast({"type": "job_event", "job_id": job.id, "event": item})

    def on_progress(info: dict[str, Any]) -> None:
        job = Job(id=f"g{int(time.time() * 1000) % 10**10}",
                  challenge_id=str(info.get("current") or "auto"),
                  title=f"AgWars {info.get('current') or ''}",
                  mode=mode, source="agwars")
        job.status = "running"
        state["jobs"][job.id] = job
        state["job_order"].append(job.id)
        holder["job"] = job
        auto["current"] = str(info.get("current") or "")
        auto["solved"] = info.get("solved", auto["solved"])
        auto["failed"] = info.get("failed", auto["failed"])
        broadcast({"type": "agwars", "agwars": agwars_snapshot()})

    def on_result(result: dict[str, Any]) -> None:
        auto["results"].append({
            "hill": result.get("hill"), "flag": result.get("flag"),
            "accepted": result.get("accepted"), "error": result.get("error"),
            "slot_url": result.get("slot_url"),
        })
        job = holder.get("job")
        if job is not None:
            job.status = "done" if result.get("accepted") else "error"
            job.flag = result.get("flag")
            job.accepted = result.get("accepted")
            job.error = result.get("error")
        broadcast({"type": "agwars", "agwars": agwars_snapshot()})

    created_proxies: list[str] = []

    def _expose_auto(slot_url: str) -> str:
        proxy_id = agwars_proxy_register("auto", slot_url)
        created_proxies.append(proxy_id)
        return f"{agwars_self_base()}/agwars/proxy/{proxy_id}"

    try:
        await ensure_lingshu(cfg, lingshu)
        await ag_auto_arena(
            lingshu, args_like(cfg, "agwars-auto"), require_agwars(),
            mode=mode, limit=limit, hills=hills,
            on_result=on_result, on_progress=on_progress, on_event=on_event,
            stop_event=stop_event, expose_url_factory=_expose_auto)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        out(f"[agwars-auto] 挂机异常终止: {exc}")
        auto["results"].append({"hill": auto.get("current") or "-",
                                "accepted": False, "error": str(exc)[:160]})
    finally:
        for proxy_id in created_proxies:
            agwars_proxy_release(proxy_id)
        for job in state["jobs"].values():
            if job.status == "running":
                job.status = "cancelled"
        auto["running"] = False
        auto["current"] = ""
        broadcast({"type": "agwars", "agwars": agwars_snapshot()})


@app.post("/api/agwars/auto")
async def api_agwars_auto(data: AgWarsAutoIn):
    cfg: Config = STATE["config"]
    state: dict[str, Any] = STATE["agwars"]
    require_agwars()
    if state["auto"]["running"]:
        raise HTTPException(status_code=409, detail="AgWars 挂机已在运行")
    if any(j.status in {"queued", "running"} for j in state["jobs"].values()):
        raise HTTPException(status_code=409, detail="已有 AgWars 解题任务在运行")
    mode = data.mode or cfg.mode or "fast"
    limit = max(1, min(50, data.limit or 5))
    state["task"] = asyncio.create_task(
        agwars_run_auto(mode, limit, data.hills or None))
    return {"ok": True}


@app.post("/api/agwars/auto/stop")
async def api_agwars_auto_stop():
    state: dict[str, Any] = STATE["agwars"]
    if state["auto"]["running"]:
        state["stop_event"].set()
        task = state.get("task")
        if task is not None and not task.done():
            task.cancel()
        state["auto"]["running"] = False
        return {"ok": True, "message": "已停止（当前解题已中断）"}
    return {"ok": True, "message": "挂机未在运行"}


class AgWarsControlIn(BaseModel):
    action: str
    hours: int = 6


@app.post("/api/agwars/control")
async def api_agwars_control(data: AgWarsControlIn):
    """参赛状态控制：暂停 / 恢复 / 弃赛 / 申诉。"""
    aw = require_agwars()
    action = (data.action or "").strip().lower()
    async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=20)) as client:
        try:
            if action == "pause":
                return await aw.pause(client, hours=max(1, min(72, data.hours)))
            if action == "resume":
                return await aw.resume(client)
            if action == "forfeit":
                return await aw.forfeit(client)
            if action == "appeal":
                return await aw.appeal(client)
        except AgWarsError as exc:
            raise agwars_http_error(exc) from exc
    raise HTTPException(status_code=400,
                        detail="action 仅支持 pause / resume / forfeit / appeal")


AGWARS_PROXY_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


def agwars_proxy_register(hill: str, slot_url: str) -> str:
    """为本次解题登记一个本地注入代理：token 不进入模型上下文。"""
    state: dict[str, Any] = STATE["agwars"]
    proxies: dict[str, Any] = state.setdefault("proxies", {})
    # 清理陈旧代理（超过 2 小时）
    now = time.time()
    for pid, info in list(proxies.items()):
        if now - float(info.get("created_at") or 0) > 7200:
            proxies.pop(pid, None)
    proxy_id = secrets.token_hex(8)
    proxies[proxy_id] = {"slot_url": slot_url.rstrip("/"), "hill": hill,
                         "created_at": now}
    return proxy_id


def agwars_proxy_release(proxy_id: str) -> None:
    STATE["agwars"].get("proxies", {}).pop(proxy_id, None)


@app.api_route("/agwars/proxy/{proxy_id}/{rest:path}", methods=AGWARS_PROXY_METHODS)
async def agwars_proxy(proxy_id: str, rest: str, request: Request):
    """把灵枢的请求转发到本题实例，并注入平台要求的认证头。

    平台规定实例请求需 ``X-Agent-Token`` + ``X-Trace-Id``（不需 HMAC）。
    由工作台代注入可以让 api_token 完全不进入模型上下文与命令历史；
    响应中的绝对 Location 会被改写回代理路径，避免模型直连实例域名。
    """
    info = STATE["agwars"].get("proxies", {}).get(proxy_id)
    if not info:
        raise HTTPException(status_code=404, detail="代理不存在或已过期")
    slot_url = str(info["slot_url"]).rstrip("/")
    target = f"{slot_url}/{rest}" if rest else f"{slot_url}/"
    query = request.url.query
    if query:
        target = f"{target}?{query}"
    aw = AgWarsClient()
    headers = {
        key: value for key, value in request.headers.items()
        if key.lower() not in {"host", "content-length", "connection",
                               "accept-encoding"}
    }
    headers["X-Agent-Token"] = aw.token
    headers["X-Trace-Id"] = aw.trace
    body = await request.body()
    async with httpx.AsyncClient(timeout=httpx.Timeout(120, connect=20),
                                 follow_redirects=False) as client:
        response = await client.request(
            request.method, target, headers=headers, content=body or None)
    out_headers = {
        key: value for key, value in response.headers.items()
        if key.lower() not in {"content-encoding", "content-length",
                               "transfer-encoding", "connection"}
    }
    location = out_headers.get("location") or out_headers.get("Location")
    if location:
        prefix = f"/agwars/proxy/{proxy_id}"
        if location.startswith(slot_url):
            out_headers["location"] = prefix + location[len(slot_url):]
        elif location.startswith("/"):
            out_headers["location"] = prefix + location
    return StreamingResponse(
        iter([response.content]), status_code=response.status_code,
        headers=out_headers, media_type=response.headers.get("content-type"))


@app.get("/api/stream")
async def api_stream():
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    STATE["subscribers"].add(queue)

    async def generator():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            STATE["subscribers"].discard(queue)

    return StreamingResponse(generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


# ────────────────────────────────────────────────────────────────
# 前端控制台（自包含单页）
# ────────────────────────────────────────────────────────────────

CONSOLE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>灵枢 × CTF2 Agent 工作台</title>
<style>
:root{--bg:#0a0a0a;--panel:#141414;--panel2:#101010;--line:#2c2c2c;--dim:#8a8a8a;
--text:#e8e8e8;--accent:#ff302f;--ok:#3fb950}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font-family:Inter,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;font-size:13px}
.top{display:flex;align-items:center;gap:12px;padding:12px 18px;border-bottom:1px solid var(--line);
background:var(--panel);position:sticky;top:0;z-index:5}
.top b{font-size:15px;letter-spacing:.5px}
.top .chip{border:1px solid var(--line);border-radius:99px;padding:3px 10px;font-size:11px;color:var(--dim)}
.top .chip b{color:var(--text);font-size:11px}
.top .chip.ok{border-color:var(--ok);color:var(--ok)}
.top .spacer{flex:1}
.top button{border:1px solid var(--line);background:var(--panel2);color:var(--text);
border-radius:7px;padding:7px 12px;font-size:12px;cursor:pointer}
.top button:hover{border-color:var(--accent);color:var(--accent)}
.wrap{display:grid;grid-template-columns:minmax(400px,540px) minmax(0,1fr);gap:14px;padding:14px 18px;max-width:1560px;margin:0 auto}
.tabs{display:flex;align-items:center;gap:6px;padding:10px 18px 0;max-width:1560px;margin:0 auto}
.tab{border:1px solid var(--line);border-radius:8px 8px 0 0;background:transparent;color:var(--fg);padding:8px 18px;cursor:pointer;font-weight:600}
.tab.active{background:var(--panel);border-bottom-color:var(--panel)}
.card>.body{overflow-x:auto}
.card{border:1px solid var(--line);border-radius:10px;background:var(--panel);overflow:hidden}
.card>header{display:flex;align-items:center;gap:9px;padding:10px 14px;border-bottom:1px solid var(--line);
background:var(--panel2);font-weight:700;font-size:12.5px}
.card>header .right{margin-left:auto;display:flex;gap:8px;align-items:center}
.card>.body{padding:12px 14px}
.filters{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:10px}
select,input[type=text],input[type=number],input[type=password]{background:var(--panel2);border:1px solid var(--line);
color:var(--text);border-radius:6px;padding:6px 9px;font-size:12px;outline:none}
select:focus,input:focus{border-color:var(--accent)}
.btn{border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:7px;
padding:7px 13px;font-size:12px;cursor:pointer}
.btn.primary{border-color:var(--accent);background:linear-gradient(135deg,var(--accent),#a70e0d);color:#fff;font-weight:700}
.btn.danger{border-color:#e5484d;color:#ff777b;background:#2a1011}
.btn:disabled{opacity:.45;cursor:not-allowed}
table{width:100%;border-collapse:collapse;font-size:11.5px}
th{background:var(--panel2);color:var(--dim);font-size:10px;letter-spacing:.6px;text-transform:uppercase;
padding:8px 10px;text-align:left;white-space:nowrap}
td{padding:9px 10px;border-top:1px solid #232323;color:#c9c9c9;vertical-align:middle}
tr:hover td{background:#ffffff06}
.tag{border:1px solid var(--line);border-radius:99px;padding:1px 8px;font-size:10px;color:var(--dim)}
.tag.ok{color:var(--ok);border-color:var(--ok)}
.tag.fast{color:var(--accent);border-color:var(--accent)}
.tag.err{color:#e5484d;border-color:#e5484d}
.solved{color:var(--ok)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.stream{height:300px;overflow:auto;background:#0d0d0d;border:1px solid var(--line);border-radius:8px;
padding:10px;font:11px/1.65 ui-monospace,SFMono-Regular,monospace;white-space:pre-wrap;word-break:break-word;color:#c8c8c8}
.flagline{margin-top:9px;font:700 13px ui-monospace,monospace}
.flagline .v{color:var(--accent);word-break:break-all}
.muted{color:var(--dim)}
.stat{display:inline-flex;align-items:center;gap:6px;margin-right:14px;font-size:12px}
.stat b{font-size:16px}
.overlay{position:fixed;inset:0;background:#000c;display:grid;place-items:center;z-index:20}
.modal{width:min(460px,92vw);background:var(--panel);border:1px solid var(--line);border-top:2px solid var(--accent);
border-radius:10px;padding:20px}
.modal h3{margin:0 0 14px}
.modal label{display:grid;gap:5px;font-size:11px;color:var(--dim);margin:10px 0}
.modal input{width:100%}
.modal .row{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}
.errtext{color:#ff8585;font-size:12px;margin:8px 0}
.mini{font-size:11px;color:var(--dim)}
.big{font-size:20px;font-weight:800}
.ok{color:var(--ok)} .bad{color:#e5484d} .acc{color:var(--accent)}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:#1a1a1a;border:1px solid var(--accent);color:var(--text);border-radius:8px;padding:10px 18px;font-size:12.5px;z-index:60;box-shadow:0 10px 30px #000a}
</style>
</head>
<body>
<div class="top">
  <b>灵枢 × CTF 竞技场工作台</b>
  <span class="chip" id="chip-ver">v2.7</span>
  <span class="chip" id="chip-conn">● 未连接</span>
  <span class="chip" id="chip-agent">AGENT —</span>
  <span class="chip" id="chip-score">SCORE —</span>
  <span class="chip" id="chip-env">ENV —</span>
  <span class="spacer"></span>
  <span class="chip" id="chip-mode">MODE fast</span>
  <button onclick="openConfig()">连接设置</button>
</div>
<div class="tabs">
  <button class="tab active" id="tab-ctf2" onclick="switchTab('ctf2')">CTF2 竞技场</button>
  <button class="tab" id="tab-nss" onclick="switchTab('nss')">NSSCTF 竞技场</button>
  <button class="tab" id="tab-agwars" onclick="switchTab('agwars')">AgWars 攻防场</button>
  <span class="mini" id="nss-chip" style="margin-left:10px"></span>
</div>
<div id="page-ctf2">
<div class="wrap">
  <div class="card">
    <header>可解题目
      <div class="right">
        <select id="f-source"><option value="all">全部来源</option>
          <option value="practice">练习</option><option value="competition">竞赛</option></select>
        <input type="text" id="f-category" placeholder="题型 web/pwn…" style="width:110px">
        <button class="btn" onclick="loadChallenges()">刷新</button>
      </div>
    </header>
    <div class="body">
      <div class="filters">
        <span class="mini">解题模式：</span>
        <label class="mini"><input type="radio" name="mode" value="fast" checked> 快速 ⚡</label>
        <label class="mini"><input type="radio" name="mode" value="standard"> 标准</label>
        <label class="mini"><input type="checkbox" id="f-nosubmit"> 仅解题不提交</label>
      </div>
      <table><thead><tr><th>题目</th><th>分类 / 难度 / 分</th><th>操作</th></tr></thead>
      <tbody id="ch-body"><tr><td colspan="3" class="muted">点击「刷新」拉取 Agent 推荐题目</td></tr></tbody></table>
      <div style="display:flex;align-items:center;gap:10px;margin-top:10px">
        <span class="mini" id="ch-info"></span>
        <span style="margin-left:auto;display:flex;gap:6px;align-items:center">
          <select id="ch-size" onchange="chalPage=1;renderChallenges()">
            <option value="10" selected>10/页</option><option value="20">20/页</option><option value="50">50/页</option></select>
          <button class="btn" id="ch-prev" onclick="chalPage=Math.max(1,chalPage-1);renderChallenges()">◀</button>
          <span class="mini" id="ch-page">1/1</span>
          <button class="btn" id="ch-next" onclick="chalPage=Math.min(chalPages,chalPage+1);renderChallenges()">▶</button>
        </span>
      </div>
    </div>
  </div>
  <div style="display:grid;gap:14px;min-width:0">
    <div class="card">
      <header>实时解题 <span class="right mini" id="job-title"></span></header>
      <div class="body">
        <div class="stream" id="stream">等待任务事件…</div>
        <div class="flagline">FLAG: <span class="v" id="job-flag">—</span>
          <span id="job-result"></span></div>
      </div>
    </div>
    <div class="card">
      <header>我的解题队列（按此顺序执行）
        <div class="right">
          <select id="q-mode"><option value="fast">快速 ⚡</option><option value="standard">标准</option></select>
          <label class="mini"><input type="checkbox" id="q-nosubmit"> 仅解题</label>
          <button class="btn primary" id="q-run" onclick="queueRun()">执行队列</button>
          <button class="btn danger" id="q-stop" onclick="queueStop()" disabled>停止</button>
          <button class="btn" onclick="queueClear()">清空</button>
        </div>
      </header>
      <div class="body">
        <span class="mini" id="q-current">空闲</span>
        <table><tbody id="q-body"><tr><td class="muted">队列为空：在左侧题目列表点「＋队」加入</td></tr></tbody></table>
      </div>
    </div>
    <div class="grid2">
      <div class="card">
        <header>全自动挂机
          <div class="right">
            <button class="btn primary" id="auto-start" onclick="autoStart()">启动</button>
            <button class="btn danger" id="auto-stop" onclick="autoStop()" disabled>停止</button>
          </div>
        </header>
        <div class="body">
          <div class="filters">
            <select id="a-mode"><option value="fast">快速 ⚡</option><option value="standard">标准</option></select>
            <input type="number" id="a-limit" value="5" min="1" max="50" style="width:70px" title="题数上限">
            <select id="a-source"><option value="practice">练习</option><option value="all">全部</option></select>
            <input type="text" id="a-category" placeholder="题型" style="width:90px">
            <input type="text" id="a-difficulty" placeholder="难度" style="width:80px">
          </div>
          <div>
            <span class="stat">✅ <b id="a-solved" class="ok">0</b></span>
            <span class="stat">❌ <b id="a-failed" class="bad">0</b></span>
            <span class="stat mini" id="a-current">空闲</span>
          </div>
          <table><tbody id="a-results"></tbody></table>
        </div>
      </div>
      <div class="card">
        <header>任务记录</header>
        <div class="body">
          <table><thead><tr><th>题名</th><th>模式</th><th>Flag</th><th>判定</th></tr></thead>
          <tbody id="j-history"><tr><td colspan="4" class="muted">暂无</td></tr></tbody></table>
        </div>
      </div>
    </div>
  </div>
</div>
</div>

<div id="page-nss" style="display:none">
<div class="wrap">
  <div class="card">
    <header>当前题目
      <div class="right">
        <button class="btn" onclick="nssRefresh()">刷新</button>
        <button class="btn primary" onclick="nssNext()">随机领题</button>
        <button class="btn danger" onclick="nssAbandon()">放弃本题</button>
      </div>
    </header>
    <div class="body" id="nss-attempt">
      <span class="muted">点击「随机领题」或等待自动挂机；当前无进行中的题目</span>
    </div>
  </div>
  <div style="display:grid;gap:14px;min-width:0">
    <div class="card">
      <header>实时解题 <span class="right mini" id="nss-job-title"></span></header>
      <div class="body">
        <div class="stream" id="nss-stream">等待任务事件…</div>
        <div class="flagline">FLAG: <span class="v" id="nss-job-flag">—</span>
          <span id="nss-job-result"></span></div>
        <div class="filters" style="margin-top:10px">
          <select id="n-mode"><option value="fast">快速 ⚡</option><option value="standard">标准</option></select>
          <button class="btn primary" onclick="nssSolve()">解当前题</button>
          <input type="text" id="n-flag" placeholder="手动提交 flag（可选）" style="flex:1">
          <button class="btn" onclick="nssSubmit()">提交 Flag</button>
        </div>
      </div>
    </div>
    <div class="grid2">
      <div class="card">
        <header>NSSCTF 全自动挂机
          <div class="right">
            <button class="btn primary" id="na-start" onclick="nssAutoStart()">启动</button>
            <button class="btn danger" id="na-stop" onclick="nssAutoStop()" disabled>停止</button>
          </div>
        </header>
        <div class="body">
          <div class="filters">
            <input type="number" id="na-limit" value="5" min="1" max="50" style="width:70px" title="题数上限">
            <span class="mini">题数上限（解错即放弃计 ❌，rating 结算）</span>
          </div>
          <div>
            <span class="stat">✅ <b id="na-solved" class="ok">0</b></span>
            <span class="stat">❌ <b id="na-failed" class="bad">0</b></span>
            <span class="stat mini" id="na-current">空闲</span>
          </div>
          <table><tbody id="na-results"></tbody></table>
        </div>
      </div>
      <div class="card">
        <header>Agent 战绩（rating）</header>
        <div class="body" id="nss-agent">
          <span class="muted">配置 NSSCTF Agent Token 后显示</span>
        </div>
      </div>
    </div>
    <div class="card">
      <header>任务记录</header>
      <div class="body">
        <table><thead><tr><th>题名</th><th>模式</th><th>Flag</th><th>判定</th></tr></thead>
        <tbody id="n-history"><tr><td colspan="4" class="muted">暂无</td></tr></tbody></table>
      </div>
    </div>
  </div>
</div>
</div>
<div id="page-agwars" style="display:none">
<div class="wrap">
  <div style="display:grid;gap:14px;min-width:0">
    <div class="card">
      <header>Agent 身份 <span class="right mini" id="ag-id-hint"></span></header>
      <div class="body" id="ag-identity">
        <span class="muted">尚未注册 AgWars Agent</span>
      </div>
    </div>
    <div class="card">
      <header>注册 / 模型验证</header>
      <div class="body">
        <div class="filters" style="flex-wrap:wrap">
          <select id="ag-group" title="model_group">
            <option value="other">other</option>
            <option value="deepseek">deepseek</option>
            <option value="qwen">qwen</option>
            <option value="glm">glm</option>
            <option value="claude">claude</option>
            <option value="gpt">gpt</option>
            <option value="gemini">gemini</option>
            <option value="kimi">kimi</option>
            <option value="doubao">doubao</option>
            <option value="siliconflow">siliconflow</option>
            <option value="hunyuan">hunyuan</option>
            <option value="minimax">minimax</option>
          </select>
          <input type="text" id="ag-url" placeholder="model_url（如 http://10.8.20.116:8201/v1）" style="flex:1;min-width:220px">
          <input type="text" id="ag-model" placeholder="model_name" style="width:170px">
        </div>
        <div class="filters" style="margin-top:8px">
          <button class="btn primary" onclick="agwarsRegister()">注册 Agent</button>
          <button class="btn" onclick="agwarsVerifyModel()">模型验证</button>
          <span class="mini" id="ag-verify-hint"></span>
        </div>
        <p class="mini muted" style="margin:6px 0 0">
          每设备最多注册 2 个 Agent；api_secret 仅本机 0600 保存，不会显示在页面。
          注册后请把 API Token 交给主人，用于 agwars.hxorz.com 的「我的排队」。
        </p>
      </div>
    </div>
    <div class="card">
      <header>激活题号 <span class="right mini" id="ag-round"></span></header>
      <div class="body">
        <div class="filters" style="flex-wrap:wrap">
          <select id="ag-hill" style="min-width:110px"></select>
          <select id="ag-mode"><option value="fast">快速 ⚡</option><option value="standard">标准</option></select>
          <button class="btn primary" onclick="agwarsSolve()">排队并解题</button>
          <button class="btn" onclick="agwarsRefresh()">刷新</button>
        </div>
        <div class="filters" style="margin-top:8px">
          <button class="btn" onclick="agwarsSlot('poll')">查询槽位</button>
          <button class="btn" onclick="agwarsSlot('keepalive')">保活</button>
          <button class="btn danger" onclick="agwarsSlot('release')">释放槽位</button>
          <span class="mini" id="ag-slot-hint"></span>
        </div>
      </div>
    </div>
  </div>
  <div style="display:grid;gap:14px;min-width:0">
    <div class="card">
      <header>实时解题 <span class="right mini" id="ag-job-title"></span></header>
      <div class="body">
        <div class="stream" id="ag-stream">等待任务事件…</div>
        <div class="flagline">FLAG: <span class="v" id="ag-job-flag">—</span>
          <span id="ag-job-result"></span></div>
        <div class="filters" style="margin-top:10px">
          <input type="text" id="ag-flag" placeholder="手动提交 flag（可选）" style="flex:1">
          <button class="btn" onclick="agwarsSubmit()">提交 Flag</button>
        </div>
      </div>
    </div>
    <div class="grid2">
      <div class="card">
        <header>AgWars 全自动
          <div class="right">
            <button class="btn primary" id="ag-auto-start" onclick="agwarsAutoStart()">启动</button>
            <button class="btn danger" id="ag-auto-stop" onclick="agwarsAutoStop()" disabled>停止</button>
          </div>
        </header>
        <div class="body">
          <div class="filters">
            <input type="number" id="ag-limit" value="3" min="1" max="50" style="width:70px" title="题数上限">
            <span class="mini">按激活题号顺序排队解题（错题扣分，勿刷错误 Flag）</span>
          </div>
          <div>
            <span class="stat">✅ <b id="ag-solved" class="ok">0</b></span>
            <span class="stat">❌ <b id="ag-failed" class="bad">0</b></span>
            <span class="stat mini" id="ag-current">空闲</span>
          </div>
          <table><tbody id="ag-results"></tbody></table>
        </div>
      </div>
      <div class="card">
        <header>参赛控制</header>
        <div class="body">
          <div class="filters" style="flex-wrap:wrap">
            <button class="btn" onclick="agwarsControl('pause')">暂停 6h</button>
            <button class="btn" onclick="agwarsControl('resume')">恢复</button>
            <button class="btn" onclick="agwarsControl('appeal')">申诉</button>
            <button class="btn danger" onclick="agwarsControl('forfeit')">弃赛</button>
          </div>
          <p class="mini muted" style="margin:8px 0 0">
            罚则：蜜罐 -3%、反扫描/模板 -5%、错误 Flag -5%（同一 Flag 10 分钟不重复扣）；
            每 30 分钟无有效活动计躺平窗口。弃赛会释放山头并永久免罚，不可逆。
          </p>
        </div>
      </div>
    </div>
    <div class="card">
      <header>任务记录</header>
      <div class="body">
        <table><thead><tr><th>题号</th><th>模式</th><th>Flag</th><th>判定</th></tr></thead>
        <tbody id="ag-history"><tr><td colspan="4" class="muted">暂无</td></tr></tbody></table>
      </div>
    </div>
  </div>
</div>
</div>

<div class="overlay" id="cfg-modal" style="display:none">
  <div class="modal">
    <h3>连接设置</h3>
    <p class="mini">凭据仅保存在本进程内存（不落盘）；也可通过环境变量 CTF2_API_TOKEN 等预置。</p>
    <label>CTF2 Agent Token（PAT）
      <input type="password" id="c-token" placeholder="ctf2 agent 竞技场签发的 Agent Token"></label>
    <label>NSSCTF Agent Token（nss_agent_…，NSSCTF 竞技场页使用）
      <input type="password" id="c-nsstoken" placeholder="NSSCTF Agent Arena 签发的 Token"></label>
    <label>灵枢 Web 地址
      <input type="text" id="c-url" placeholder="http://localhost:8080"></label>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <label>灵枢用户<input type="text" id="c-user"></label>
      <label>灵枢密码<input type="password" id="c-pass"></label>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
      <label>默认供应商（来自你的模型池）
        <select id="c-provider"><option value="">（刷新后自动填充）</option></select></label>
      <label>默认级别<select id="c-model"><option>Min</option><option>Max</option><option>Low</option></select></label>
      <label>默认模式<select id="c-mode2"><option value="fast">fast</option><option value="standard">standard</option></select></label>
    </div>
    <label class="mini" style="display:flex;align-items:center;gap:6px">
      <input type="checkbox" id="c-fastsummary"> FAST 模式收尾生成总结报告（默认关闭省 token；需验证报告链路时勾选）
    </label>
    <div class="errtext" id="cfg-err"></div>
    <div class="row">
      <button class="btn" onclick="closeConfig()">取消</button>
      <button class="btn primary" onclick="saveConfig()">保存并连接</button>
    </div>
  </div>
</div>

<script>
const $ = (id) => document.getElementById(id);
function toast(msg, kind){
  const el = document.createElement("div");
  el.className = "toast" + (kind ? " " + kind : "");
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}
toast.info = (m) => toast(m);
let currentJobId = null;
const jobStreams = {};

function esc(s){return String(s ?? "").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}

async function refreshState(){
  try{
    const st = await (await fetch("/api/state")).json();
    $("chip-conn").textContent = st.configured ? "● 已连接" : "● 未配置";
    $("chip-conn").className = "chip " + (st.configured ? "ok" : "err");
    const a = st.agent || {};
    const agent = a.agent || a.profile || a;
    $("chip-agent").innerHTML = "AGENT <b>" + esc(agent.username || agent.friendly_id || "—") + "</b>";
    $("chip-score").innerHTML = "SCORE <b>" + esc(String(a.total_score ?? a.score ?? "—")) + "</b>";
    const q = a.quotas || {};
    $("chip-env").innerHTML = "ENV 配额 <b>" + esc(String(q.max_environments ?? "—")) + "</b>";
    $("c-url").value = st.config.lingshu_url || "";
    $("c-model").value = st.config.model || "Min";
    $("c-mode2").value = st.config.mode || "fast";
    const sel = $("c-provider");
    const current = st.config.provider || "";
    const provs = st.providers || [];
    sel.innerHTML = (provs.length ? provs.map(p =>
      '<option value="' + esc(p.id) + '">' + esc(p.label) +
      "（" + (p.models || []).length + " 模型）</option>").join("")
      : '<option value="">（无可用供应商：请先在灵枢设置中心添加）</option>');
    if (current && !provs.some(p => p.id === current))
      sel.innerHTML += '<option value="' + esc(current) + '">' + esc(current) + "（当前值）</option>";
    sel.value = current || (provs[0] ? provs[0].id : "");
    renderJobs(st.jobs || []);
    renderAuto(st.auto || {});
    renderQueue(st.queue || {items: []});
  }catch(e){ $("chip-conn").textContent = "● 服务不可达"; $("chip-conn").className = "chip err"; }
}
function renderJobs(jobs){
  const done = jobs.filter(j => j.status !== "running" && j.status !== "queued");
  $("j-history").innerHTML = done.length ? done.map(j =>
    "<tr><td>" + esc(j.title.slice(0,26)) + "</td><td>" +
    (j.mode === "fast" ? '<span class="tag fast">FAST</span>' : '<span class="tag">STD</span>') +
    "</td><td><code>" + esc(j.flag || "—") + "</code></td><td>" +
    (j.accepted === true ? '<span class="tag ok">正确</span>'
      : j.accepted === false ? '<span class="tag err">未通过</span>' : '<span class="tag">' + esc(j.status) + "</span>")
    + "</td></tr>").join("")
    : '<tr><td colspan="4" class="muted">暂无</td></tr>';
  const running = jobs.find(j => j.status === "running" || j.status === "queued");
  if (running){
    $("job-title").textContent = running.title + " · " + running.mode.toUpperCase();
    if (currentJobId !== running.id){
      currentJobId = running.id;
      $("stream").textContent = (jobStreams[running.id] || "").slice(-6000);
    }
    if (running.flag) $("job-flag").textContent = running.flag;
    $("job-result").innerHTML = running.accepted === true ? '<span class="ok">✅ 已提交判定正确</span>'
      : running.accepted === false ? '<span class="bad">❌ 提交未通过</span>'
      : (running.error ? '<span class="bad">' + esc(running.error) + "</span>" : "");
  }
}
function renderAuto(auto){
  $("a-solved").textContent = auto.solved;
  $("a-failed").textContent = auto.failed;
  $("a-current").textContent = auto.running ? ("运行中：" + (auto.current || "…")) : "空闲";
  $("auto-start").disabled = auto.running;
  $("auto-stop").disabled = !auto.running;
  $("a-results").innerHTML = (auto.results || []).map(r =>
    "<tr><td>" + (r.accepted ? '<span class="ok">✅</span>' : '<span class="bad">❌</span>')
    + "</td><td>" + esc((r.title || "").slice(0, 22)) + "</td><td><code>" + esc(r.flag || "—") + "</code></td></tr>").join("");
}
let chalAll = [], chalPage = 1, chalPages = 1;
let queueState = {items: [], running: false, current: ""};
function renderChallenges(){
  const size = Number($("ch-size").value);
  chalPages = Math.max(1, Math.ceil(chalAll.length / size));
  chalPage = Math.min(chalPage, chalPages);
  const slice = chalAll.slice((chalPage - 1) * size, chalPage * size);
  const noSubmit = $("f-nosubmit").checked;
  const queueIds = new Set((queueState.items || []).map(q => q.challenge_id));
  const body = $("ch-body");
  if (!slice.length){
    body.innerHTML = '<tr><td colspan="3" class="muted">没有可解题目</td></tr>';
  } else {
    body.innerHTML = slice.map(it => {
      const btn = it.solved ? "" :
        '<button class="btn primary" data-act="solve" data-id="' + it.id + '" data-nosubmit="' + (noSubmit ? 1 : 0) + '">解题</button>' +
        (queueIds.has(it.id) ? '<button class="btn" disabled>已入队</button>' :
        '<button class="btn" data-act="queueadd" data-id="' + it.id + '">＋队</button>');
      return "<tr>" +
        '<td><b>' + esc(it.title.slice(0, 28)) + '</b>' +
        (it.has_container ? ' <span class="tag">🐳</span>' : '') +
        (it.source === "competition" ? ' <span class="tag">竞赛</span>' : '') +
        (it.solved ? ' <span class="solved">✔已解</span>' : '') + '</td>' +
        '<td class="mini">' + esc(it.category || "—") + '<br>' +
        esc(it.difficulty || "—") + ' · ' + esc(String(it.score ?? "—")) + '分</td>' +
        '<td style="white-space:nowrap">' + btn + '</td></tr>';
    }).join("");
  }
  $("ch-info").textContent = "共 " + chalAll.length + " 题";
  $("ch-page").textContent = chalPage + "/" + chalPages;
  $("ch-prev").disabled = chalPage <= 1;
  $("ch-next").disabled = chalPage >= chalPages;
}
let queueState2 = null;
function renderQueue(q){
  queueState = q;
  $("q-current").textContent = q.running ? ("执行中：" + (q.current || "…")) : "空闲";
  $("q-run").disabled = q.running || !(q.items || []).length;
  $("q-stop").disabled = !q.running;
  $("q-body").innerHTML = (q.items || []).length ? q.items.map((it, i) =>
    "<tr><td>" + (i + 1) + "</td><td>" + esc((it.title || "").slice(0, 34)) + "</td><td style=\\"white-space:nowrap\\">" +
    (q.running ? "" :
      '<button class="btn" data-act="qup" data-id="' + it.challenge_id + '">↑</button>' +
      '<button class="btn" data-act="qdown" data-id="' + it.challenge_id + '">↓</button>' +
      '<button class="btn danger" data-act="qrm" data-id="' + it.challenge_id + '">✕</button>') +
    "</td></tr>").join("")
    : '<tr><td class="muted">队列为空：在左侧题目列表点「＋队」加入</td></tr>';
}
async function queueAdd(id){
  const it = chalAll.find(x => x.id === id) || {};
  const r = await fetch("/api/queue/add", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({challenge_id: id, item: {
      id, title: it.title || id, name: it.title || id,
      category: it.category || "", difficulty: it.difficulty || "",
      source: it.source || "practice",
      practice_ground_id: it.practice_ground_id || "",
      has_container: !!it.has_container, has_attachments: !!it.has_attachments,
    }})});
  if (!r.ok){ alert(await readError(r)); return; }
  renderChallenges();
}
async function queueRemove(id){
  await fetch("/api/queue/remove", {method: "POST",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify({challenge_id: id})});
  renderChallenges();
}
async function queueMove(id, delta){
  await fetch("/api/queue/move", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({challenge_id: id, delta})});
}
async function queueClear(){
  if (!confirm("清空整个队列？")) return;
  await fetch("/api/queue/clear", {method: "POST"});
}
async function queueRun(){
  const r = await fetch("/api/queue/run", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({mode: $("q-mode").value, no_submit: $("q-nosubmit").checked})});
  if (!r.ok) alert(await readError(r));
}
async function queueStop(){
  const r = await fetch("/api/queue/stop", {method: "POST"});
  const d = await r.json().catch(() => ({}));
  if (d.message) toast.info(d.message);
  refreshState();
}

async function loadChallenges(){
  const source = $("f-source").value, category = $("f-category").value.trim();
  const body = $("ch-body");
  body.innerHTML = '<tr><td colspan="3" class="muted">拉取中…</td></tr>';
  try{
    const q = new URLSearchParams({source, category, limit: "100"});
    const data = await (await fetch("/api/challenges?" + q)).json();
    if (data.detail){ body.innerHTML = '<tr><td colspan="3" class="errtext">' + esc(data.detail) + "</td></tr>"; return; }
    chalAll = data.items || [];
    chalPage = 1;
    renderChallenges();
  }catch(e){ body.innerHTML = '<tr><td colspan="3" class="errtext">' + esc(String(e)) + "</td></tr>"; }
}
async function readError(r){
  const text = await r.text();
  try { const d = JSON.parse(text); return d.detail || text; } catch(e){ return text || r.statusText; }
}
async function solve(id, noSubmit){
  const mode = document.querySelector("input[name=mode]:checked").value;
  const r = await fetch("/api/solve", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({challenge_id: id, mode, no_submit: !!noSubmit})});
  if (!r.ok){ alert(await readError(r)); return; }
  const data = await r.json();
  currentJobId = data.job_id; $("stream").textContent = ""; $("job-flag").textContent = "—";
}
async function autoStart(){
  const r = await fetch("/api/auto", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({mode: $("a-mode").value, limit: Number($("a-limit").value),
      source: $("a-source").value, category: $("a-category").value.trim(),
      difficulty: $("a-difficulty").value.trim()})});
  if (!r.ok) alert(await readError(r));
}
async function autoStop(){
  const r = await fetch("/api/auto/stop", {method: "POST"});
  const d = await r.json().catch(() => ({}));
  if (d.message) toast.info(d.message);
  refreshState();
}
function openConfig(){
  $("cfg-err").textContent = ""; $("cfg-modal").style.display = "grid";
  fetch("/api/state").then(r => r.json()).then(st => {
    $("c-url").value = st.config.lingshu_url || "http://localhost:8080";
    $("c-user").value = st.config.provider ? $("c-user").value : "";
    $("c-fastsummary").checked = !!st.config.fast_summary;
  });
}
function closeConfig(){ $("cfg-modal").style.display = "none"; }
async function saveConfig(){
  const payload = {
    ctf2_token: $("c-token").value || null,
    nssctf_token: $("c-nsstoken").value || null,
    lingshu_url: $("c-url").value || null,
    lingshu_user: $("c-user").value || null,
    lingshu_pass: $("c-pass").value || null,
    provider: $("c-provider").value || null,
    model: $("c-model").value || null,
    mode: $("c-mode2").value || null,
    fast_summary: $("c-fastsummary").checked ? "1" : "0",
  };
  const r = await fetch("/api/config", {method: "POST",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)});
  const data = await r.json();
  if (!r.ok){ $("cfg-err").textContent = data.detail || "保存失败"; return; }
  closeConfig(); $("c-token").value = ""; refreshState(); loadChallenges();
}
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-act]");
  if (!el) return;
  const id = el.dataset.id;
  if (el.dataset.act === "solve") solve(id, el.dataset.nosubmit === "1");
  else if (el.dataset.act === "queueadd") queueAdd(id);
  else if (el.dataset.act === "qup") queueMove(id, 1);
  else if (el.dataset.act === "qdown") queueMove(id, -1);
  else if (el.dataset.act === "qrm") queueRemove(id);
});

// ── NSSCTF 竞技场子页面 ──
let activeTab = "ctf2";
let nssJobId = null;
const nssStreams = {};
function switchTab(t){
  activeTab = t;
  $("page-ctf2").style.display = t === "ctf2" ? "" : "none";
  $("page-nss").style.display = t === "nss" ? "" : "none";
  $("page-agwars").style.display = t === "agwars" ? "" : "none";
  $("tab-ctf2").classList.toggle("active", t === "ctf2");
  $("tab-nss").classList.toggle("active", t === "nss");
  $("tab-agwars").classList.toggle("active", t === "agwars");
  if (t === "nss") nssRefresh();
  if (t === "agwars") agwarsRefresh();
}
function nssEsc(s){ return esc(String(s ?? "")); }
function renderNss(st){
  const ag = st.agent || {};
  $("nss-chip").textContent = ag.name ? ("NSS: " + ag.name + " · rating " + (ag.rating ?? "—")) : "";
  const rows = [
    ["Agent", nssEsc(ag.name || "—")],
    ["Rating", String(ag.rating ?? "—")],
    ["已结算题数", String(ag.attempt_count ?? "—")],
    ["解出 / 失败", (ag.solved_count ?? "—") + " / " + (ag.failed_count ?? "—")],
    ["错误提交", String(ag.wrong_count ?? "—")],
    ["成功率", ag.success_rate != null ? (ag.success_rate + "%") : "—"],
    ["状态", nssEsc(ag.status_label || "—")],
  ];
  $("nss-agent").innerHTML = "<table>" + rows.map(r =>
    "<tr><td class='mini' style='width:110px'>" + r[0] + "</td><td><b>" + r[1] + "</b></td></tr>").join("") + "</table>";
  const at = st.attempt;
  if (at && at.state === "active"){
    const p = at.problem || {};
    const remain = at.remaining_seconds != null ? Math.floor(at.remaining_seconds / 60) + " 分钟" : "—";
    const annex = p.has_annex ? ("📎 " + nssEsc(p.annex_name || "附件")) : "—";
    const box = p.container_urls && p.container_urls.length
      ? p.container_urls.map(u => "<code>" + nssEsc(u) + "</code>").join(" ") : "—";
    $("nss-attempt").innerHTML =
      "<div style='display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px'>" +
      "<b style='font-size:1.05em'>" + nssEsc(p.title || ("attempt-" + at.attempt_id)) + "</b>" +
      (p.type_label ? "<span class='tag'>" + nssEsc(p.type_label) + "</span>" : "") +
      (p.rating ? "<span class='tag'>R" + p.rating + "</span>" : "") +
      (at.reused ? "<span class='tag'>复用</span>" : "") +
      "<span class='mini'>剩余 " + remain + " · 错误 " + (at.wrong_count ?? 0) + "/" + (at.max_wrong_count ?? "—") + "</span></div>" +
      "<div class='mini' style='margin-bottom:6px'>附件：" + annex + " · 靶机：" + box + "</div>" +
      "<div style='white-space:pre-wrap;max-height:220px;overflow:auto;background:var(--bg);border:1px solid var(--line);" +
      "border-radius:8px;padding:10px;font-size:12px'>" + nssEsc(p.content || "（无题面）") + "</div>";
  } else {
    $("nss-attempt").innerHTML = "<span class='muted'>" +
      (at ? ("题目已结算：" + nssEsc(at.state) + "（rating 变动 " + (at.rating_delta ?? 0) + "），可领下一题")
          : "当前无进行中的题目：点「随机领题」或启动全自动挂机") + "</span>";
  }
  const au = st.auto || {};
  $("na-start").disabled = !!au.running; $("na-stop").disabled = !au.running;
  $("na-solved").textContent = au.solved ?? 0; $("na-failed").textContent = au.failed ?? 0;
  $("na-current").textContent = au.current || "空闲";
  $("na-results").innerHTML = (au.results || []).slice(-10).reverse().map(r =>
    "<tr><td>" + nssEsc((r.title || "?").slice(0, 26)) + "</td><td><code>" + nssEsc(r.flag || "—") + "</code></td><td>" +
    (r.correct ? '<span class="tag ok">✓</span>' : '<span class="tag err">✗</span>') +
    "<span class='mini'> " + nssEsc((r.error || "").slice(0, 40)) + "</span></td></tr>").join("");
}
async function nssRefresh(){
  const r = await fetch("/api/nss/state");
  if (!r.ok){ const t = await readError(r);
    $("nss-agent").innerHTML = "<span class='muted'>" + nssEsc(t) + "</span>"; return; }
  renderNss(await r.json());
}
async function nssNext(){
  const r = await fetch("/api/nss/next", {method: "POST"});
  if (!r.ok){ alert(await readError(r)); return; }
  nssRefresh();
}
async function nssSolve(){
  const r = await fetch("/api/nss/solve", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({mode: $("n-mode").value})});
  if (!r.ok){ alert(await readError(r)); return; }
  const d = await r.json();
  nssJobId = d.job_id; nssStreams[nssJobId] = "";
  $("nss-stream").textContent = ""; $("nss-job-flag").textContent = "—"; $("nss-job-title").textContent = "";
}
async function nssSubmit(){
  const flag = $("n-flag").value.trim();
  if (!flag){ alert("请输入 flag"); return; }
  const r = await fetch("/api/nss/submit", {method: "POST",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify({flag})});
  if (!r.ok){ alert(await readError(r)); return; }
  const d = await r.json();
  toast.info(d.correct ? "✅ 正确！" : "❌ 错误（剩余次数 " + (d.remaining_wrong_attempts ?? "?") + "）");
  nssRefresh();
}
async function nssAbandon(){
  if (!confirm("确定放弃当前题？将按未解出结算。")) return;
  const r = await fetch("/api/nss/abandon", {method: "POST"});
  const d = await r.json().catch(() => ({}));
  if (!r.ok){ alert(await readError(r)); return; }
  if (d.message) toast.info(d.message);
  nssRefresh();
}
async function nssAutoStart(){
  const r = await fetch("/api/nss/auto", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({mode: $("n-mode").value, limit: Number($("na-limit").value)})});
  if (!r.ok){ alert(await readError(r)); return; }
  nssRefresh();
}
async function nssAutoStop(){
  const r = await fetch("/api/nss/auto/stop", {method: "POST"});
  const d = await r.json().catch(() => ({}));
  if (d.message) toast.info(d.message);
  nssRefresh();
}

// ── AgWars 攻防场 ──
let agJobId = null;
const agStreams = {};
function renderAgwars(st){
  const c = st.credentials || {};
  const p = st.platform || {};
  $("ag-id-hint").textContent = c.registered
    ? (c.player_name + " · " + (c.shard || "")) : "未注册";
  $("ag-identity").innerHTML = c.registered ? (
    "<table>" +
    "<tr><td class='mini' style='width:96px'>用户名</td><td><b>" + nssEsc(c.player_name) + "</b></td></tr>" +
    "<tr><td class='mini'>Agent ID</td><td><b>" + nssEsc(c.agent_id) + "</b></td></tr>" +
    "<tr><td class='mini'>分片</td><td>" + nssEsc(c.shard) + "</td></tr>" +
    "<tr><td class='mini'>得分</td><td>" + nssEsc(String(c.score_total ?? "—")) + "</td></tr>" +
    "<tr><td class='mini'>Token</td><td><code>" + nssEsc(c.token_hint) + "</code>（完整值见身份文件）</td></tr>" +
    "<tr><td class='mini'>Secret</td><td><code>" + nssEsc(c.secret_hint) + "</code> 仅本机 0600</td></tr>" +
    "<tr><td class='mini'>身份文件</td><td class='mini'>" + nssEsc(c.identity_path) + "</td></tr>" +
    "</table>"
  ) : "<span class='muted'>尚未注册：填写下方模型信息后点「注册 Agent」</span>";

  // 激活题号下拉
  const hills = p.active_hills || [];
  const sel = $("ag-hill"); const prev = sel.value;
  sel.innerHTML = hills.length
    ? hills.map(h => "<option value='" + nssEsc(h) + "'>" + nssEsc(h) + "</option>").join("")
    : "<option value=''>（无激活题号）</option>";
  if (prev && hills.includes(prev)) sel.value = prev;
  $("ag-round").textContent = p.formal_end
    ? ("关服 " + nssEsc(p.formal_end) + (p.capacity ? " · 容量 " + p.capacity : ""))
    : (hills.length ? "" : "读取中…");

  const au = st.auto || {};
  $("ag-auto-start").disabled = !!au.running;
  $("ag-auto-stop").disabled = !au.running;
  $("ag-solved").textContent = au.solved ?? 0;
  $("ag-failed").textContent = au.failed ?? 0;
  $("ag-current").textContent = au.current || "空闲";
  $("ag-results").innerHTML = (au.results || []).slice(-10).reverse().map(r =>
    "<tr><td>" + nssEsc(r.hill || "?") + "</td><td><code>" + nssEsc(r.flag || "—") +
    "</code></td><td>" + (r.accepted ? '<span class="tag ok">✓</span>'
      : '<span class="tag err">✗</span>') +
    "<span class='mini'> " + nssEsc((r.error || "").slice(0, 40)) + "</span></td></tr>").join("");
  $("ag-history").innerHTML = (st.jobs || []).slice().reverse().map(j =>
    "<tr><td>" + nssEsc(j.challenge_id || "?") + "</td><td>" +
    (j.mode === "fast" ? '<span class="tag fast">FAST</span>' : '<span class="tag">STD</span>') +
    "</td><td><code>" + nssEsc(j.flag || "—") + "</code></td><td>" +
    (j.accepted === true ? '<span class="tag ok">正确</span>'
      : j.accepted === false ? '<span class="tag err">未通过</span>'
      : '<span class="tag err">' + nssEsc(j.error || j.status) + "</span>") + "</td></tr>").join("")
    || '<tr><td colspan="4" class="muted">暂无</td></tr>';
}
async function agwarsRefresh(){
  const r = await fetch("/api/agwars/state");
  if (!r.ok){ const t = await readError(r);
    $("ag-identity").innerHTML = "<span class='muted'>" + nssEsc(t) + "</span>"; return; }
  renderAgwars(await r.json());
}
async function agwarsRegister(){
  if (!confirm("确认注册新 Agent？每设备最多 2 个，注册后不可撤销。")) return;
  const r = await fetch("/api/agwars/register", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({model_group: $("ag-group").value,
      model_url: $("ag-url").value.trim(), model_name: $("ag-model").value.trim()})});
  if (!r.ok){ alert(await readError(r)); return; }
  toast.info("注册成功，身份文件已生成");
  agwarsRefresh();
}
async function agwarsVerifyModel(){
  $("ag-verify-hint").textContent = "验证中…";
  const r = await fetch("/api/agwars/verify-model", {method: "POST"});
  if (!r.ok){ $("ag-verify-hint").textContent = ""; alert(await readError(r)); return; }
  const d = await r.json();
  $("ag-verify-hint").textContent = d.verified
    ? ("✅ 已验证（" + (d.vendor || "?") + "）") : "❌ 未通过（可重试）";
  toast.info(d.verified ? "模型验证通过" : "模型验证未通过");
}
async function agwarsSolve(){
  const hill = $("ag-hill").value;
  if (!hill){ alert("请先选择激活题号"); return; }
  const r = await fetch("/api/agwars/solve", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({hill, mode: $("ag-mode").value})});
  if (!r.ok){ alert(await readError(r)); return; }
  const d = await r.json();
  agJobId = d.job_id; agStreams[agJobId] = "";
  $("ag-stream").textContent = ""; $("ag-job-flag").textContent = "—";
  $("ag-job-title").textContent = "AgWars " + hill;
}
async function agwarsSlot(action){
  const r = await fetch("/api/agwars/slot/" + action, {method: "POST"});
  if (!r.ok){ $("ag-slot-hint").textContent = ""; alert(await readError(r)); return; }
  const d = await r.json();
  $("ag-slot-hint").textContent = d.state
    ? ("槽位 " + d.state + (d.position ? " / 第 " + d.position + " 位" : "") + (d.url ? " · " + d.url : ""))
    : ("ok" + (d.slot ? " · " + d.slot : ""));
}
async function agwarsSubmit(){
  const flag = $("ag-flag").value.trim();
  if (!flag){ alert("请输入 flag"); return; }
  const r = await fetch("/api/agwars/submit", {method: "POST",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify({flag})});
  if (!r.ok){ alert(await readError(r)); return; }
  toast.info("已提交，平台判定见「我的排队」");
}
async function agwarsAutoStart(){
  const r = await fetch("/api/agwars/auto", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({mode: $("ag-mode").value, limit: Number($("ag-limit").value)})});
  if (!r.ok){ alert(await readError(r)); return; }
  agwarsRefresh();
}
async function agwarsAutoStop(){
  const r = await fetch("/api/agwars/auto/stop", {method: "POST"});
  const d = await r.json().catch(() => ({}));
  if (d.message) toast.info(d.message);
  agwarsRefresh();
}
async function agwarsControl(action){
  if (action === "forfeit" && !confirm("弃赛会释放山头并永久免罚，且不可撤销。确认？")) return;
  const r = await fetch("/api/agwars/control", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({action, hours: 6})});
  if (!r.ok){ alert(await readError(r)); return; }
  toast.info("已提交：" + action);
}
const es = new EventSource("/api/stream");
es.onmessage = (ev) => {
  let msg; try{ msg = JSON.parse(ev.data); }catch(e){ return; }
  if (msg.type === "job_event"){
    const e = msg.event || {};
    const line = e.type === "delta" ? (e.message || "")
      : "[" + (e.agent || "workbench") + "] " + (e.message || e.flag || "");
    if (msg.job_id.startsWith("g")){
      // AgWars 事件流
      if (line){ agStreams[msg.job_id] = (agStreams[msg.job_id] || "") + line;
        const gb = $("ag-stream");
        gb.textContent = agStreams[msg.job_id].slice(-8000);
        gb.scrollTop = gb.scrollHeight; }
      if (e.type === "flag" && e.flag) $("ag-job-flag").textContent = e.flag;
      if (e.type === "submit") $("ag-job-result").textContent =
        e.accepted ? "✅ 正确" : "❌ 未通过";
    } else if (msg.job_id.startsWith("n")){
      // NSSCTF 竞技场事件流（独立面板）
      if (line){ nssStreams[msg.job_id] = (nssStreams[msg.job_id] || "") + line;
        const nb = $("nss-stream");
        nb.textContent = nssStreams[msg.job_id].slice(-8000);
        nb.scrollTop = nb.scrollHeight; }
      if (e.type === "flag" && e.flag) $("nss-job-flag").textContent = e.flag;
      if (e.type === "submit") $("nss-job-result").textContent =
        e.accepted ? "✅ 正确" : "❌ 错误";
      if (e.type === "log" && e.message && e.message.startsWith("▶"))
        $("nss-job-title").textContent = e.message.slice(1).trim().slice(0, 40);
    } else if (msg.job_id === currentJobId){
      const box = $("stream");
      if (line){ jobStreams[msg.job_id] = (jobStreams[msg.job_id] || "") + line;
        box.textContent = jobStreams[msg.job_id].slice(-8000);
        box.scrollTop = box.scrollHeight; }
      if (e.type === "flag" && e.flag) $("job-flag").textContent = e.flag;
    }
  } else if (msg.type === "job"){
    renderJobsStateless(msg.job);
  } else if (msg.type === "auto"){
    renderAuto(msg.auto);
  } else if (msg.type === "queue"){
    renderQueue(msg.queue);
  } else if (msg.type === "agwars"){
    const st = msg.agwars || {};
    const au = st.auto || {};
    $("ag-auto-start").disabled = !!au.running;
    $("ag-auto-stop").disabled = !au.running;
    $("ag-solved").textContent = au.solved ?? 0;
    $("ag-failed").textContent = au.failed ?? 0;
    $("ag-current").textContent = au.current || "空闲";
    $("ag-results").innerHTML = (au.results || []).slice(-10).reverse().map(r =>
      "<tr><td>" + nssEsc(r.hill || "?") + "</td><td><code>" + nssEsc(r.flag || "—") +
      "</code></td><td>" + (r.accepted ? '<span class="tag ok">✓</span>'
        : '<span class="tag err">✗</span>') +
      "<span class='mini'> " + nssEsc((r.error || "").slice(0, 40)) + "</span></td></tr>").join("");
    $("ag-history").innerHTML = (st.jobs || []).slice().reverse().map(j =>
      "<tr><td>" + nssEsc(j.challenge_id || "?") + "</td><td>" +
      (j.mode === "fast" ? '<span class="tag fast">FAST</span>' : '<span class="tag">STD</span>') +
      "</td><td><code>" + nssEsc(j.flag || "—") + "</code></td><td>" +
      (j.accepted === true ? '<span class="tag ok">正确</span>'
        : j.accepted === false ? '<span class="tag err">未通过</span>'
        : '<span class="tag err">' + nssEsc(j.error || j.status) + "</span>") + "</td></tr>").join("")
      || '<tr><td colspan="4" class="muted">暂无</td></tr>';
  } else if (msg.type === "nss"){
    const st = msg.nss || {};
    const au = st.auto || {};
    $("na-start").disabled = !!au.running; $("na-stop").disabled = !au.running;
    $("na-solved").textContent = au.solved ?? 0; $("na-failed").textContent = au.failed ?? 0;
    $("na-current").textContent = au.current || "空闲";
    $("na-results").innerHTML = (au.results || []).slice(-10).reverse().map(r =>
      "<tr><td>" + nssEsc((r.title || "?").slice(0, 26)) + "</td><td><code>" + nssEsc(r.flag || "—") + "</code></td><td>" +
      (r.correct ? '<span class="tag ok">✓</span>' : '<span class="tag err">✗</span>') +
      "<span class='mini'> " + nssEsc((r.error || "").slice(0, 40)) + "</span></td></tr>").join("");
    const jobs = st.jobs || [];
    $("n-history").innerHTML = jobs.slice().reverse().map(j =>
      "<tr><td>" + nssEsc((j.title || "?").slice(0, 26)) + "</td><td>" +
      (j.mode === "fast" ? '<span class="tag fast">FAST</span>' : '<span class="tag">STD</span>') +
      "</td><td><code>" + nssEsc(j.flag || "—") + "</code></td><td>" +
      (j.accepted === true ? '<span class="tag ok">正确</span>'
        : j.accepted === false ? '<span class="tag err">未通过</span>'
        : '<span class="tag err">' + nssEsc(j.error || j.status) + "</span>") + "</td></tr>").join("")
      || '<tr><td colspan="4" class="muted">暂无</td></tr>';
  }
};
function renderJobsStateless(job){
  if (job.status === "done" || job.status === "error" || job.status === "cancelled"){
    const done = job;
    $("j-history").innerHTML =
      "<tr><td>" + esc(done.title.slice(0,26)) + "</td><td>" +
      (done.mode === "fast" ? '<span class="tag fast">FAST</span>' : '<span class="tag">STD</span>') +
      "</td><td><code>" + esc(done.flag || "—") + "</code></td><td>" +
      (done.accepted === true ? '<span class="tag ok">正确</span>'
        : done.accepted === false ? '<span class="tag err">未通过</span>'
        : '<span class="tag err">' + esc(done.error || done.status) + "</span>") + "</td></tr>"
      + $("j-history").innerHTML.replace('<tr><td colspan="4" class="muted">暂无</td></tr>', "");
    refreshState();
  }
}
refreshState();
setInterval(refreshState, 15000);
setInterval(() => { if (activeTab === "nss") nssRefresh(); }, 8000);
setInterval(() => { if (activeTab === "agwars") agwarsRefresh(); }, 10000);
</script>
</body>
</html>
"""


def main() -> None:
    import uvicorn

    print("workbench web v2.7 starting")

    parser = argparse.ArgumentParser(description="灵枢 × CTF2 Agent 竞技场 WebUI 工作台")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机）")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    STATE["self_port"] = args.port   # 代理入口需要灵枢回连本进程
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
