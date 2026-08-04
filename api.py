""" Web API FastAPI SSE — 多会话并行架构 """
from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from auth import (
    get_current_user,
    create_user,
    verify_password,
    create_access_token,
    decode_access_token,
    get_user_by_username,
    security,
    UserCreate,
    UserLogin,
    TokenResponse,
)

from main import run_mission
import session_store

# ── SessionContext 与会话注册表 ──

@dataclass
class SessionContext:
    session_id: str
    user_id: int
    event_queue: asyncio.Queue
    input_queue: asyncio.Queue
    task: asyncio.Task | None = None

# 活跃会话注册表：session_id → SessionContext
_active_sessions: dict[str, SessionContext] = {}
_sessions_dir = _PROJECT_ROOT / ".TaskMemory" / "sessions"
_sessions_dir.mkdir(parents=True, exist_ok=True)

# 用户并发上限
MAX_CONCURRENT_SESSIONS_PER_USER = 5
_session_creation_lock = asyncio.Lock()

# ── 旧端点兼容路径常量 ──
_mission_store_path = _PROJECT_ROOT / ".TaskMemory" / "current_mission.json"
_long_memory_path = _PROJECT_ROOT / ".LongMemory" / "agentic_memory.json"
_upload_dir = _PROJECT_ROOT / "WorkDir" / "uploads"
_upload_dir.mkdir(parents=True, exist_ok=True)


# ── 旧版全局 SSE（deprecated，保留兼容） ──
_event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=5000)
_mission_lock = asyncio.Lock()
_current_task: asyncio.Task[Any] | None = None


def _push_event(event_type: str, **payload: Any) -> None:
    """[deprecated] 旧版全局事件推送，仅供旧端点兼容。"""
    data = {"type": event_type, **payload}
    try:
        _event_queue.put_nowait(data)
    except asyncio.QueueFull:
        pass


async def _event_generator():
    """[deprecated] 旧版全局事件生成器，仅供旧端点兼容。"""
    while True:
        try:
            event = await asyncio.wait_for(_event_queue.get(), timeout=15.0)
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        except asyncio.TimeoutError:
            yield ": heartbeat\n\n"


# ── 需持久化到 session_messages 的事件类型 ──
_PERSIST_EVENT_TYPES = frozenset({
    "mission_start", "mission_end", "mission_cancelled",
    "phase_change", "message", "error",
    "approval_required", "approval_resolved",
    "plan_updated",
    # Agent 流式输出事件
    "text_start", "text_end",
    "thinking_start", "thinking_end",
    # 工具调用事件
    "tool_call_start", "tool_call_end",
    # 靶机信息事件
    "target_info", "flag_found",
})

# 系统级事件（role="system"），其余持久化事件 role="agent"
_SYSTEM_ROLE_EVENTS = frozenset({
    "mission_start", "mission_end", "mission_cancelled",
    "phase_change", "error",
    "approval_required", "approval_resolved",
})


def _persist_event(session_id: str, event_type: str, payload: dict) -> None:
    """将重要事件异步持久化到 session_messages 表，供历史消息加载。"""
    if event_type not in _PERSIST_EVENT_TYPES:
        return
    agent_name = payload.get("agent", "")
    # 根据事件类型提取内容和确定 role
    if event_type == "mission_start":
        content = f"目标: {payload.get('target', '')} | 目标: {payload.get('goal', '')}"
    elif event_type == "mission_end":
        content = f"状态: {payload.get('status', '未知')}"
    elif event_type == "mission_cancelled":
        content = payload.get("message", "任务已被取消")
    elif event_type == "phase_change":
        content = payload.get("phase", "")
        agent_name = "system"
    elif event_type == "error":
        content = payload.get("message", "")
    elif event_type in ("text_end", "thinking_end"):
        content = payload.get("full_text", payload.get("content", ""))
    elif event_type in ("text_start", "thinking_start"):
        content = ""
    elif event_type == "plan_updated":
        # 将计划条目和阶段序列化为 JSON 存入 content，供历史回放
        content = json.dumps({
            "items": payload.get("items", []),
            "phase": payload.get("phase", ""),
        }, ensure_ascii=False)
    elif event_type == "tool_call_start":
        content = payload.get("tool_name", "")
    elif event_type == "tool_call_end":
        content = payload.get("tool_name", "")
    else:
        content = payload.get("content", payload.get("message", ""))
    # 系统事件 role="system"，Agent 流式/消息事件 role="agent"
    role = "system" if event_type in _SYSTEM_ROLE_EVENTS else "agent"
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(
            asyncio.to_thread(session_store.add_message, session_id, role, content, event_type, agent_name)
        )
    except RuntimeError:
        # 无事件循环时同步写入
        session_store.add_message(session_id, role, content, event_type, agent_name)


# ── Session-aware 事件回调工厂 ──

def _make_session_callback(session_id: str, queue: asyncio.Queue):
    """为指定会话创建事件回调闭包，同时推送 SSE 和持久化到 DB。

    内置 Agent 流式全文缓冲：
    text_delta/thinking_delta 负责累积，text_end/thinking_end 自动将
    完整文本注入 payload["full_text"]，持久化时以一条 text_end 替代
    数百条 delta，大幅减少 DB 写次数，同时保证刷新后 Agent 日志面板
    可完整回放。

    text_start/thinking_start 也一并持久化（无 content），用于历史恢复
    时在 Agent 日志面板创建气泡入口。
    """
    _buf: dict[str, str] = {}  # agent_name → 累积全文

    def callback(event_type: str, **payload: Any) -> None:
        nonlocal _buf
        # 全文缓冲：text_delta / thinking_delta → 累积
        if event_type in ("text_delta", "thinking_delta"):
            agent = payload.get("agent", "")
            _buf[agent] = _buf.get(agent, "") + (
                payload.get("delta") or payload.get("content") or ""
            )
        # 全文终结：text_end → 注入 full_text 并清除缓冲区
        elif event_type in ("text_end", "thinking_end"):
            agent = payload.get("agent", "")
            full = _buf.pop(agent, "")
            if full:
                payload["full_text"] = full
            # 也推到 SSE（前端依靠 SSE 拿到含 full_text 的 text_end）
            # 注意：persist 由下面的 _persist_event 调用负责，不依赖 SSE
        # start 时清旧缓冲（防止上一条异常截断后残留）
        elif event_type in ("text_start", "thinking_start"):
            agent = payload.get("agent", "")
            if agent in _buf:
                _buf.pop(agent)  # 旧残留丢弃

        payload["session_id"] = session_id
        try:
            queue.put_nowait({"type": event_type, **payload})
        except asyncio.QueueFull:
            pass
        # 异步持久化到 session_messages 表（仅 _PERSIST_EVENT_TYPES 中的事件会实际落库）
        _persist_event(session_id, event_type, payload)

    return callback


async def _session_event_generator(session_id: str, queue: asyncio.Queue):
    """从指定会话的事件队列消费事件，带心跳。"""
    while True:
        try:
            event = await asyncio.wait_for(queue.get(), timeout=15.0)
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        except asyncio.TimeoutError:
            yield ": heartbeat\n\n"


# ── 会话归属验证辅助函数 ──

async def _verify_session_owner(session_id: str, user_id: int) -> dict:
    """验证会话归属权，返回会话信息或抛出 404。"""
    session_info = await asyncio.to_thread(session_store.get_session, session_id)
    if session_info is None or session_info["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="会话不存在")
    return session_info


# ── 长期记忆保存辅助函数 ──

def _save_long_term_memory(session_id, target, goal, phase, success, flag, summary):
    """保存任务到长期记忆。"""
    try:
        from AgenticMemory import save_mission
        save_mission(
            target=target,
            goal=goal,
            plan=summary,
            attack_chain=[],
            success=success or False,
            summary=summary,
            flag=flag or "",
        )
    except Exception:
        pass


# ── 运行并清理 ──

async def _run_and_cleanup(session_id: str, ctx: SessionContext, target: str, goal: str,
                           model_ver: str, provider: str, callback):
    """运行任务并处理清理逻辑。"""
    status_val = "completed"
    phase = "completed"
    summary = ""
    flag = None
    success = None
    try:
        mission_state = await run_mission(
            target=target, goal=goal, model_ver=model_ver,
            provider=provider, event_callback=callback,
            session_id=session_id, input_queue=ctx.input_queue,
        )
        phase = mission_state.phase.value if hasattr(mission_state.phase, 'value') else str(mission_state.phase)
        success = mission_state.success
        flag = mission_state.flag
        summary = mission_state.summary or ""
        if mission_state.success:
            status_val = "completed"
        else:
            status_val = "failed"
    except asyncio.CancelledError:
        status_val = "cancelled"
        phase = "cancelled"
        callback("mission_cancelled", message="任务已被用户取消", agent="system")
    except Exception as exc:
        status_val = "failed"
        phase = "failed"
        callback("error", message=f"任务异常：{exc}", agent="system")
    finally:
        callback("mission_end", message="任务已结束", status=status_val)
        await asyncio.to_thread(
            lambda: session_store.update_session(
                session_id, status=status_val, phase=phase,
                success=success, flag=flag, summary=summary,
            )
        )
        # 保存到长期记忆
        try:
            _save_long_term_memory(session_id, target, goal, phase, success, flag, summary)
        except Exception:
            pass
        # 延迟清理，给前端时间拉取最后的事件
        await asyncio.sleep(5)
        if session_id in _active_sessions:
            del _active_sessions[session_id]


app = FastAPI(
    title="灵枢 Lingshu — Web 控制台",
    description="多智能体授权安全测试系统前端 API",
    version="0.5.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── JWT 认证中间件 ──
_AUTH_SKIP_PATHS = (
    "/",
    "/index.html",
    "/session_state.js",
    "/uploads",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/favicon.ico",
    "/auth/login",
    "/auth/register",
)


class JWTAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/") or "/"
        if any(path == p or path.startswith(p + "/") for p in _AUTH_SKIP_PATHS):
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return Response(
                status_code=401,
                content=json.dumps({"detail": "需要 Bearer Token 认证"}),
                media_type="application/json",
            )
        token = auth[7:]
        try:
            payload = decode_access_token(token)
        except HTTPException:
            return Response(
                status_code=401,
                content=json.dumps({"detail": "无效的认证令牌"}),
                media_type="application/json",
            )

        # 预加载用户对象，避免路由层 get_current_user 重复查询 DB
        try:
            user = await asyncio.to_thread(get_user_by_username, payload["username"])
        except Exception:
            user = None

        if not user:
            return Response(
                status_code=401,
                content=json.dumps({"detail": "用户不存在"}),
                media_type="application/json",
            )

        # 存储完整的用户对象，供 get_current_user 直接使用
        request.state.current_user = {
            "id": user["id"],
            "username": user["username"],
            "email": user.get("email", ""),
            "role": user["role"],
        }
        return await call_next(request)


app.add_middleware(JWTAuthMiddleware)
app.mount("/uploads", StaticFiles(directory=str(_upload_dir)), name="uploads")

# ── 初始化会话数据库 ──
session_store.init_sessions_db()

# ── 请求模型 ──
class MissionStartRequest(BaseModel):
    target: str = Field(..., description="授权目标 IP / IP:端口 / 主机名 / 文件路径")
    goal: str = Field(default="获取 Flag", description="任务目标描述")
    provider: str = Field(default="deepseek", description="模型提供商: deepseek | qwen")
    model: str = Field(default="Min", description="思考级别: Low | Min | Max")


class ChatMessage(BaseModel):
    content: str


# ── 认证路由 ──
@app.post("/auth/register", response_model=TokenResponse)
async def register(data: UserCreate):
    try:
        user = create_user(data.username, data.password, data.email)
        token, expires_in = create_access_token(user["id"], user["username"], user["role"])
        return TokenResponse(access_token=token, username=user["username"], expires_in=expires_in)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auth/login", response_model=TokenResponse)
async def login(data: UserLogin):
    from auth import get_user_by_username as _get_user
    user = _get_user(data.username)
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    token, expires_in = create_access_token(user["id"], user["username"], user["role"])
    # 登录时更新 last_login
    from auth import get_db
    from datetime import datetime, timezone
    conn = get_db()
    try:
        conn.execute("UPDATE users SET last_login = ? WHERE username = ?",
                     (datetime.now(timezone.utc).isoformat(), data.username))
        conn.commit()
    finally:
        conn.close()
    return TokenResponse(access_token=token, username=user["username"], expires_in=expires_in)


@app.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user


@app.post("/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    return {"message": "登出成功"}


# ── 路由 ──
@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
async def index():
    html_path = _PROJECT_ROOT / "frontend" / "index.html"
    if html_path.is_file():
        return html_path.read_text(encoding="utf-8")
    return HTMLResponse("<h1>前端页面未找到</h1>", status_code=404)


@app.get("/session_state.js")
async def session_state_js():
    js_path = _PROJECT_ROOT / "frontend" / "session_state.js"
    if js_path.is_file():
        return FileResponse(js_path, media_type="application/javascript")
    return Response(status_code=404)


# ══════════════════════════════════════════════════
#  新版多会话 API
# ══════════════════════════════════════════════════

@app.post("/api/session/start")
async def session_start(req: MissionStartRequest, current_user: dict = Depends(get_current_user)):
    """创建并启动新会话。"""
    async with _session_creation_lock:
        # 检查用户并发上限
        user_session_count = sum(
            1 for ctx in _active_sessions.values() if ctx.user_id == current_user["id"]
        )
        if user_session_count >= MAX_CONCURRENT_SESSIONS_PER_USER:
            raise HTTPException(
                status_code=429,
                detail=f"并发会话数已达上限 ({MAX_CONCURRENT_SESSIONS_PER_USER})，请关闭部分会话后重试",
            )

        # 生成 session_id 并创建 SessionContext
        session_id = uuid.uuid4().hex[:16]
        ctx = SessionContext(
            session_id=session_id,
            user_id=current_user["id"],
            event_queue=asyncio.Queue(maxsize=5000),
            input_queue=asyncio.Queue(),
        )

        # 注册到活跃会话
        _active_sessions[session_id] = ctx

    # 持久化到 DB（传入 API 层生成的 session_id）
    await asyncio.to_thread(
        session_store.create_session,
        user_id=current_user["id"],
        target=req.target,
        goal=req.goal,
        provider=req.provider,
        model=req.model,
        title=req.target,
        session_id=session_id,
    )

    # 构建 session-aware callback
    callback = _make_session_callback(session_id, ctx.event_queue)

    # 推送启动事件
    callback("mission_start", target=req.target, goal=req.goal,
             provider=req.provider, model=req.model)

    # 创建后台任务
    task = asyncio.create_task(
        _run_and_cleanup(session_id, ctx, req.target, req.goal, req.model, req.provider, callback)
    )
    ctx.task = task

    return {"session_id": session_id, "status": "started"}


@app.get("/api/session/{session_id}/stream")
async def session_stream(session_id: str, current_user: dict = Depends(get_current_user)):
    """会话 SSE 事件流。"""
    await _verify_session_owner(session_id, current_user["id"])
    ctx = _active_sessions.get(session_id)
    if ctx is None:
        raise HTTPException(status_code=404, detail="会话不存在或已结束")
    return StreamingResponse(
        _session_event_generator(session_id, ctx.event_queue),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.post("/api/session/{session_id}/message")
async def send_message(session_id: str, msg: ChatMessage, current_user: dict = Depends(get_current_user)):
    """向指定会话发送用户消息。"""
    await _verify_session_owner(session_id, current_user["id"])
    ctx = _active_sessions.get(session_id)
    if ctx is None:
        raise HTTPException(status_code=404, detail="会话不存在或已结束")
    await ctx.input_queue.put(msg.content)
    await asyncio.to_thread(session_store.add_message, session_id, "user", msg.content)
    return {"status": "sent"}


@app.get("/api/sessions")
async def list_sessions(
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(get_current_user),
):
    """列出用户所有会话。"""
    sessions = await asyncio.to_thread(
        lambda: session_store.list_sessions(
            current_user["id"], status=status_filter, limit=limit, offset=offset,
        )
    )
    # 为活跃会话添加实时状态标记
    for s in sessions:
        s["is_live"] = s["id"] in _active_sessions
    return {"sessions": sessions}


@app.get("/api/session/{session_id}")
async def get_session_detail(session_id: str, current_user: dict = Depends(get_current_user)):
    """获取会话详情。"""
    session = await _verify_session_owner(session_id, current_user["id"])
    # 标记会话是否仍在活跃
    session["is_live"] = session_id in _active_sessions
    # 尝试读取 MissionState JSON 文件获取更多详情
    session_file = _sessions_dir / f"{session_id}.json"
    if session_file.is_file():
        try:
            mission_data = json.loads(session_file.read_text(encoding="utf-8"))
            session["mission_state"] = mission_data
        except (json.JSONDecodeError, OSError):
            pass
    return session


@app.get("/api/session/{session_id}/messages")
async def get_session_messages(
    session_id: str,
    after_seq: int = 0,
    limit: int = 200,
    current_user: dict = Depends(get_current_user),
):
    """获取会话消息历史。"""
    await _verify_session_owner(session_id, current_user["id"])
    messages = await asyncio.to_thread(
        lambda: session_store.get_messages(session_id, after_seq=after_seq, limit=limit)
    )
    return {"messages": messages}


@app.delete("/api/session/{session_id}")
async def delete_session(session_id: str, current_user: dict = Depends(get_current_user)):
    """删除会话。"""
    await _verify_session_owner(session_id, current_user["id"])
    # 如果会话仍在运行，先取消并等待
    ctx = _active_sessions.get(session_id)
    if ctx and ctx.task and not ctx.task.done():
        ctx.task.cancel()
        try:
            await ctx.task
        except (asyncio.CancelledError, Exception):
            pass
        _active_sessions.pop(session_id, None)
    # 删除 DB 记录
    await asyncio.to_thread(session_store.delete_session, session_id)
    # 删除 JSON 文件
    session_file = _sessions_dir / f"{session_id}.json"
    if session_file.is_file():
        session_file.unlink()
    return {"status": "deleted"}


@app.post("/api/session/{session_id}/cancel")
async def cancel_session(session_id: str, current_user: dict = Depends(get_current_user)):
    """取消正在运行的会话。"""
    await _verify_session_owner(session_id, current_user["id"])
    ctx = _active_sessions.get(session_id)
    if ctx is None or ctx.task is None or ctx.task.done():
        raise HTTPException(status_code=404, detail="会话不存在或已结束")
    ctx.task.cancel()
    return {"status": "cancelled"}


# ══════════════════════════════════════════════════
#  旧端点兼容（deprecated）
# ══════════════════════════════════════════════════

@app.post("/api/mission/start")
async def start_mission_compat(req: MissionStartRequest, current_user: dict = Depends(get_current_user)):
    """[deprecated] 旧版启动端点，代理到 session/start + 返回 SSE 流。"""
    result = await session_start(req, current_user)
    session_id = result["session_id"]
    ctx = _active_sessions.get(session_id)
    if ctx:
        return StreamingResponse(
            _session_event_generator(session_id, ctx.event_queue),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
        )
    return result


@app.get("/api/mission/stream")
async def stream_events_compat(current_user: dict = Depends(get_current_user)):
    """[deprecated] 旧版全局事件流，建议使用 /api/session/{id}/stream。"""
    # 如果有活跃会话，代理到第一个活跃会话的流
    for sid, ctx in _active_sessions.items():
        if ctx.user_id == current_user["id"]:
            return StreamingResponse(
                _session_event_generator(sid, ctx.event_queue),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
            )
    # 无活跃会话时返回旧全局流
    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.post("/api/mission/cancel")
async def cancel_mission_compat(current_user: dict = Depends(get_current_user)):
    """[deprecated] 旧版取消端点，代理到最近活跃会话。"""
    # 查找当前用户最近的活跃会话
    for sid, ctx in _active_sessions.items():
        if ctx.user_id == current_user["id"] and ctx.task and not ctx.task.done():
            ctx.task.cancel()
            return {"status": "cancelled", "session_id": sid}
    return {"status": "no_task", "message": "没有正在运行的任务可以取消"}


@app.get("/api/mission/state")
async def mission_state_compat(current_user: dict = Depends(get_current_user)):
    """[deprecated] 旧版状态端点，代理到最近会话的 state。"""
    # 优先查找当前用户的活跃会话
    for sid, ctx in _active_sessions.items():
        if ctx.user_id == current_user["id"]:
            session_file = _sessions_dir / f"{sid}.json"
            if session_file.is_file():
                try:
                    return json.loads(session_file.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    pass
    # 兜底读取旧路径
    if _mission_store_path.is_file():
        try:
            return json.loads(_mission_store_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"phase": "idle", "message": "无运行中的任务"}


@app.get("/api/mission/history")
async def mission_history(limit: int = 20, current_user: dict = Depends(get_current_user)):
    """读取长期记忆中的任务历史。"""
    if _long_memory_path.is_file():
        try:
            data = json.loads(_long_memory_path.read_text(encoding="utf-8"))
            missions = data.get("missions", [])
            return {"missions": missions[-limit:], "total": len(missions)}
        except (json.JSONDecodeError, OSError):
            pass
    return {"missions": [], "total": 0}


@app.post("/api/mission/upload")
async def upload_target(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """上传目标文件。"""
    MAX_SIZE = 100 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="文件过大，上限 100MB")
    safe_name = Path(file.filename or "upload").name
    dest = _upload_dir / f"{uuid.uuid4().hex[:8]}_{safe_name}"
    dest.write_bytes(content)
    return {"filename": safe_name, "path": str(dest), "size": len(content), "message": f"文件已上传：{dest}"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8080, reload=False, log_level="info")
