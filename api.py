""" Web API FastAPI SSE — 多会话并行架构 """
from __future__ import annotations

import asyncio
import json
import sys
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
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
    UserCreate,
    UserLogin,
    TokenResponse,
)

from main import run_mission
import session_store
from integrations.agentscope_service import (
    agentscope_app,
    agentscope_lifespan,
    control_router as agentscope_control_router,
)
from integrations.agentscope_service.account_events import publish_account_event

# ── SessionContext 与会话注册表 ──

@dataclass
class SessionContext:
    session_id: str
    user_id: int
    input_queue: asyncio.Queue
    task: asyncio.Task | None = None
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    stream_buffers: dict[str, str] = field(default_factory=dict)
    tool_buffers: dict[str, dict[str, str]] = field(default_factory=dict)
    approval_decision_submitted: bool = False
    agent_tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    # 运行时追加指令状态（非审批用户消息 → 中断 Agent → 注入后恢复）
    steering_state: dict[str, Any] = field(default_factory=lambda: {"pending": None, "processed": False})
    # 用户已点击停止：AgentScope 可能吞掉 CancelledError 使 run_mission 正常返回，
    # 此标记确保 _run_and_cleanup 终态强制收敛为 cancelled 而非 failed。
    cancel_requested: bool = False
    # 上一条已处理的用户消息内容（P4：忽略前端双击等产生的连续重复指令）
    last_user_content: str = ""

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
    "expert_joined",
    "plan_updated",
    # Agent 流式输出事件
    "text_start", "text_end",
    "thinking_start", "thinking_end",
    # 工具调用事件
    "tool_call_start", "tool_call_end",
    # 靶机信息事件
    "target_info", "flag_found",
    # NSSCTF 在线提交结果
    "nss_submit",
})

# 系统级事件（role="system"），其余持久化事件 role="agent"
_SYSTEM_ROLE_EVENTS = frozenset({
    "mission_start", "mission_end", "mission_cancelled",
    "phase_change", "error",
    "approval_required", "approval_resolved",
    "expert_joined",
})


def _persist_event(session_id: str, event_type: str, payload: dict) -> int | None:
    """持久化重要事件并返回消息序号，供重连去重与补偿。"""
    if event_type not in _PERSIST_EVENT_TYPES:
        return None
    agent_name = payload.get("agent", "")
    # 根据事件类型提取内容和确定 role
    if event_type == "mission_start":
        content = f"目标: {payload.get('target', '')} | 任务: {payload.get('goal', '')}"
    elif event_type == "mission_end":
        content = f"状态: {payload.get('status', '未知')}"
    elif event_type == "mission_cancelled":
        content = payload.get("message", "任务已被取消")
    elif event_type == "phase_change":
        content = payload.get("phase", "")
        agent_name = "system"
    elif event_type == "expert_joined":
        content = json.dumps({
            "expert_name": payload.get("expert_name") or agent_name,
            "specialty": payload.get("specialty", ""),
        }, ensure_ascii=False)
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
        content = json.dumps({
            "tool_call_id": payload.get("tool_call_id", ""),
            "tool_name": payload.get("tool_name", ""),
        }, ensure_ascii=False)
    elif event_type == "tool_call_end":
        content = json.dumps({
            "tool_call_id": payload.get("tool_call_id", ""),
            "tool_name": payload.get("tool_name", ""),
            "full_args": payload.get("full_args", ""),
        }, ensure_ascii=False)
    elif event_type == "approval_required":
        # 保存完整事件数据（含 scan_summary、plan_items、reason），供断线重连时恢复审批弹窗
        content = json.dumps(payload, ensure_ascii=False)
    elif event_type == "approval_resolved":
        # 保存审批结果，供前端恢复时判断是否已审批
        content = json.dumps({"approved": payload.get("approved", False), "decision": payload.get("decision", "")}, ensure_ascii=False)
    elif event_type == "nss_submit":
        # 保存 NSSCTF 提交结果，供历史回放
        content = json.dumps(payload, ensure_ascii=False)
    else:
        content = payload.get("content", payload.get("message", ""))
    # 系统事件 role="system"，Agent 流式/消息事件 role="agent"
    role = "system" if event_type in _SYSTEM_ROLE_EVENTS else "agent"
    return session_store.add_message(
        session_id, role, content, event_type, agent_name,
    )


# ── 靶机信息持久化 ──

def _persist_target_info(session_id: str, payload: dict) -> None:
    """将靶机信息持久化到 sessions 表的 target_info 列。"""
    try:
        existing = session_store.get_session(session_id)
        current_info = {}
        if existing and existing.get("target_info"):
            try:
                current_info = json.loads(existing["target_info"])
            except (json.JSONDecodeError, TypeError):
                current_info = {}
        # 兼容早期错误写入的嵌套结构。
        nested_target = current_info.pop("target_info", None)
        if isinstance(nested_target, dict):
            current_info.update(nested_target)
        nested_phase = current_info.pop("phase_change", None)
        if isinstance(nested_phase, dict) and nested_phase.get("phase"):
            current_info["phase"] = nested_phase["phase"]
        nested_flag = current_info.pop("flag_found", None)
        if isinstance(nested_flag, dict):
            flag = nested_flag.get("flag") or nested_flag.get("content")
            if flag:
                current_info["flag"] = flag
        current_info.update(payload)
        session_store.update_session(
            session_id, target_info=json.dumps(current_info, ensure_ascii=False),
        )
    except Exception:
        pass


# ── Session-aware 事件回调工厂 ──

def _make_session_callback(session_id: str, ctx: SessionContext):
    """为指定会话创建事件回调闭包，同时推送 SSE 和持久化到 DB。

    内置 Agent 流式全文缓冲：
    text_delta/thinking_delta 负责累积，text_end/thinking_end 自动将
    完整文本注入 payload["full_text"]，持久化时以一条 text_end 替代
    数百条 delta，大幅减少 DB 写次数，同时保证刷新后 Agent 日志面板
    可完整回放。

    text_start/thinking_start 也一并持久化（无 content），用于历史恢复
    时在 Agent 日志面板创建气泡入口。
    """
    def callback(event_type: str, **payload: Any) -> None:
        # 全文缓冲：text_delta / thinking_delta → 累积
        if event_type in ("text_delta", "thinking_delta"):
            agent = payload.get("agent", "")
            key = f"{event_type.removesuffix('_delta')}:{agent}"
            ctx.stream_buffers[key] = ctx.stream_buffers.get(key, "") + (
                payload.get("delta") or payload.get("content") or ""
            )
        # 全文终结：text_end → 注入 full_text 并清除缓冲区
        elif event_type in ("text_end", "thinking_end"):
            agent = payload.get("agent", "")
            key = f"{event_type.removesuffix('_end')}:{agent}"
            full = ctx.stream_buffers.pop(key, "")
            if full:
                payload["full_text"] = full
            # 也推到 SSE（前端依靠 SSE 拿到含 full_text 的 text_end）
            # 注意：persist 由下面的 _persist_event 调用负责，不依赖 SSE
        # start 时清旧缓冲（防止上一条异常截断后残留）
        elif event_type in ("text_start", "thinking_start"):
            agent = payload.get("agent", "")
            key = f"{event_type.removesuffix('_start')}:{agent}"
            ctx.stream_buffers[key] = ""

        # 工具参数按调用 ID 累积，结束时一次性持久化完整快照。
        if event_type == "tool_call_start":
            tool_call_id = payload.get("tool_call_id", "")
            if tool_call_id:
                ctx.tool_buffers[tool_call_id] = {
                    "agent": payload.get("agent", ""),
                    "tool_name": payload.get("tool_name", ""),
                    "full_args": "",
                }
        elif event_type == "tool_call_delta":
            tool_call_id = payload.get("tool_call_id", "")
            if tool_call_id:
                tool = ctx.tool_buffers.setdefault(tool_call_id, {
                    "agent": payload.get("agent", ""),
                    "tool_name": "",
                    "full_args": "",
                })
                tool["full_args"] += payload.get("delta") or ""
        elif event_type == "tool_call_end":
            tool_call_id = payload.get("tool_call_id", "")
            tool = ctx.tool_buffers.pop(tool_call_id, None)
            if tool:
                payload["full_args"] = tool.get("full_args", "")
                if not payload.get("tool_name"):
                    payload["tool_name"] = tool.get("tool_name", "")

        payload["session_id"] = session_id
        # 先持久化再广播，确保刷新/重连可以从数据库补偿事件。
        seq = _persist_event(session_id, event_type, payload)
        event = {"type": event_type, **payload}
        if seq is not None:
            event["seq"] = seq
        # 靶机信息采用扁平增量结构持久化，前端可直接恢复。
        if event_type == "mission_start":
            _persist_target_info(session_id, {
                "target": payload.get("target", ""),
                "goal": payload.get("goal", ""),
                "phase": "planning",
                "exploitation_approved": False,
            })
        elif event_type == "target_info":
            _persist_target_info(session_id, {
                key: value for key, value in payload.items()
                if key not in {"session_id", "agent", "type"}
            })
        elif event_type == "phase_change":
            _persist_target_info(session_id, {"phase": payload.get("phase", "")})
            session_store.update_session(
                session_id,
                phase=payload.get("phase", ""),
            )
            publish_account_event(
                ctx.user_id,
                "account_phase_change",
                session_id=session_id,
                phase=payload.get("phase", ""),
                previous_phase=payload.get("previous_phase", ""),
                reason=payload.get("reason", ""),
                source_id=str(seq or ""),
            )
        elif event_type == "session_title":
            title = str(payload.get("title") or "安全测试任务")
            session_store.update_session(session_id, title=title)
            publish_account_event(
                ctx.user_id,
                "account_session_title",
                session_id=session_id,
                title=title,
                source_id=str(seq or ""),
            )
        elif event_type == "flag_found":
            flag = payload.get("flag") or payload.get("content")
            if flag:
                _persist_target_info(session_id, {"flag": flag})
        # 审批状态持久化：approval_required 时保存完整事件数据，approval_resolved 时清除
        if event_type == "approval_required":
            ctx.approval_decision_submitted = False
            session_store.update_session(
                session_id,
                pending_approval=json.dumps(payload, ensure_ascii=False),
            )
        elif event_type == "approval_resolved":
            ctx.approval_decision_submitted = True
            session_store.update_session(session_id, pending_approval=None)
            if payload.get("approved"):
                _persist_target_info(session_id, {"exploitation_approved": True})

        # 每个浏览器连接拥有独立队列，所有订阅者收到完全相同的事件。
        for subscriber in tuple(ctx.subscribers):
            subscriber.put_nowait(event.copy())

    return callback


def _message_to_event(message: dict) -> dict:
    """将持久化消息转换为 SSE 事件，用于连接建立时补偿。"""
    event_type = (
        "user_message"
        if message.get("role") == "user"
        else message.get("event_type") or "message"
    )
    content = message.get("content", "")
    event: dict[str, Any] = {
        "type": event_type,
        "session_id": message.get("session_id", ""),
        "agent": message.get("agent_name", ""),
        "seq": message.get("seq", 0),
    }
    if event_type in ("text_end", "thinking_end"):
        event["full_text"] = content
    elif event_type == "phase_change":
        event["phase"] = content
    elif event_type in ("approval_required", "approval_resolved", "plan_updated", "nss_submit", "expert_joined"):
        try:
            event.update(json.loads(content))
        except (json.JSONDecodeError, TypeError):
            event["content"] = content
    elif event_type in ("tool_call_start", "tool_call_end"):
        try:
            event.update(json.loads(content))
        except (json.JSONDecodeError, TypeError):
            # 兼容旧记录：content 仅保存工具名称。
            event["tool_name"] = content
    elif event_type == "error":
        event["message"] = content
    else:
        event["content"] = content
    return event


async def _session_event_generator(
    session_id: str,
    ctx: SessionContext,
    after_seq: int = 0,
):
    """为单个客户端建立独立订阅，并补偿刷新建连间隙事件。"""
    queue: asyncio.Queue = asyncio.Queue()
    ctx.subscribers.add(queue)
    # 注册订阅和读取补偿消息之间不 await，不会产生事件丢失窗口。
    catchup = session_store.get_messages(session_id, after_seq=after_seq, limit=5000)
    stream_snapshot = dict(ctx.stream_buffers)
    tool_snapshot = {
        tool_call_id: dict(tool)
        for tool_call_id, tool in ctx.tool_buffers.items()
    }
    try:
        for message in catchup:
            yield f"data: {json.dumps(_message_to_event(message), ensure_ascii=False)}\n\n"
        for key, full_text in stream_snapshot.items():
            stream_type, agent = key.split(":", 1)
            snapshot = {
                "type": "stream_snapshot",
                "stream_type": stream_type,
                "agent": agent,
                "full_text": full_text,
                "session_id": session_id,
            }
            yield f"data: {json.dumps(snapshot, ensure_ascii=False)}\n\n"
        for tool_call_id, tool in tool_snapshot.items():
            snapshot = {
                "type": "tool_call_snapshot",
                "tool_call_id": tool_call_id,
                "tool_name": tool.get("tool_name", ""),
                "agent": tool.get("agent", ""),
                "full_args": tool.get("full_args", ""),
                "session_id": session_id,
            }
            yield f"data: {json.dumps(snapshot, ensure_ascii=False)}\n\n"
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15.0)
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            except asyncio.TimeoutError:
                yield ": heartbeat\n\n"
    finally:
        ctx.subscribers.discard(queue)


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
        from Tools.AgenticMemory import save_mission
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
                           model_ver: str, provider: str, callback, initial_context: str | None = None,
                           nss_context: dict | None = None):
    """运行任务并处理清理逻辑。"""
    status_val = "completed"
    phase = "completed"
    summary = ""
    flag = None
    success = None
    mission_state = None
    try:
        mission_state = await run_mission(
            target=target, goal=goal, model_ver=model_ver,
            provider=provider, event_callback=callback,
            session_id=session_id, input_queue=ctx.input_queue,
            initial_context=initial_context,
            agent_tasks=ctx.agent_tasks,
            steering_state=ctx.steering_state,
            nss_context=nss_context,
        )
        # AgentScope 的 reply_stream 可能吞掉 CancelledError 而正常返回，
        # 此时必须按用户停止意图收敛终态为 cancelled（而非 failed）。
        if ctx.cancel_requested:
            status_val = "cancelled"
            phase = "cancelled"
            callback("mission_cancelled", message="任务已被用户取消", agent="system")
        else:
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
        if mission_state is None or status_val == "cancelled":
            existing = session_store.get_session(session_id) or {}
            current_title = str(existing.get("title") or "安全测试任务")
            if current_title == str(existing.get("target") or ""):
                current_title = "安全测试任务"
            prefix = f"[{session_id[:8]}]"
            if not current_title.startswith(prefix):
                current_title = f"{prefix} {current_title}"
            outcome = "任务已取消" if status_val == "cancelled" else "任务异常结束"
            callback(
                "session_title",
                title=f"{current_title} - {outcome}",
                agent="system",
            )
        # 异常或取消时也固化尚未收到 end 的工具参数，避免历史缺失。
        for tool_call_id, tool in tuple(ctx.tool_buffers.items()):
            callback(
                "tool_call_end",
                agent=tool.get("agent", ""),
                tool_call_id=tool_call_id,
                tool_name=tool.get("tool_name", ""),
            )
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


@asynccontextmanager
async def _app_lifespan(_: FastAPI):
    async with agentscope_lifespan():
        yield


app = FastAPI(
    title="灵枢 Lingshu — Web 控制台",
    description="多智能体授权安全测试系统前端 API",
    version="0.5.0",
    lifespan=_app_lifespan,
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
    "/api_client.js",
    "/agent_transport.js",
    "/iconpark-icons.js",
    "/logo2.png",
    "/logored.png",
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
app.include_router(agentscope_control_router)
app.mount("/agentscope", agentscope_app)

# ── 初始化会话数据库 ──
session_store.init_sessions_db()

# ── 请求模型 ──
class MissionStartRequest(BaseModel):
    target: str = Field(..., description="授权目标 IP / IP:端口 / 主机名 / 文件路径")
    goal: str = Field(default="获取 Flag", description="任务目标描述")
    provider: str = Field(default="deepseek", description="模型提供商: deepseek | qwen")
    model: str = Field(default="Min", description="思考级别: Low | Min | Max")
    source_session_id: str | None = Field(default=None, description="重跑来源会话ID，用于注入前次任务上下文")
    nss_context: dict | None = Field(default=None, description="NSSCTF Arena 上下文（attempt_id/token/api_base），供 Orchestrator 在线提交 Flag")


class ChatMessage(BaseModel):
    content: str


# ── 前次任务上下文构建（"再打一次"重跑用）──
_CONTEXT_MAX_TOTAL = 4000
_CONTEXT_FINDING_MAX = 500
_CONTEXT_ATTACK_MAX = 300
_CONTEXT_MAX_ITEMS = 5


def _build_initial_context(source_session_id: str, user_id: str) -> str | None:
    """从旧会话的 MissionState JSON 构建前次任务摘要上下文。

    Returns:
        摘要文本；会话不存在/无权访问/读失败时返回 None（静默降级）。
    """
    session = session_store.get_session(source_session_id)
    if not session or session.get("user_id") != user_id:
        return None
    session_file = _sessions_dir / f"{source_session_id}.json"
    if not session_file.is_file():
        return None
    try:
        data = json.loads(session_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    lines: list[str] = []
    lines.append(f"前次目标：{data.get('target', '未知')}")
    lines.append(f"前次任务目标：{data.get('goal', '未知')}")
    phase = data.get("phase", "未知")
    success = data.get("success")
    flag = data.get("flag")
    result_desc = "成功" if success else ("失败" if success is False else "未完成（中断）")
    lines.append(f"前次结果：{result_desc}（终态阶段: {phase}）")
    if flag:
        lines.append(f"前次已获取 Flag：{flag}")

    findings = data.get("findings", [])[-_CONTEXT_MAX_ITEMS:]
    if findings:
        lines.append("")
        lines.append("【前次侦察发现】")
        for f in findings:
            src = f.get("source", "?")
            report = (f.get("report") or "")[:_CONTEXT_FINDING_MAX].strip()
            if report:
                lines.append(f"- [{src}] {report}")

    attack_chain = data.get("attack_chain", [])[-_CONTEXT_MAX_ITEMS:]
    if attack_chain:
        lines.append("")
        lines.append("【前次攻击链】")
        for step in attack_chain:
            obj = (step.get("objective") or "")[:120].strip()
            report = (step.get("report") or "")[:_CONTEXT_ATTACK_MAX].strip()
            lines.append(f"- 目标: {obj}")
            if report:
                lines.append(f"  结果: {report}")

    summary = (data.get("summary") or "").strip()
    if summary:
        lines.append("")
        lines.append(f"【前次任务总结】{summary[:1000]}")

    text = "\n".join(lines)
    if len(text) > _CONTEXT_MAX_TOTAL:
        text = text[:_CONTEXT_MAX_TOTAL] + "\n... (上下文已截断)"
    return text


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
        return HTMLResponse(
            html_path.read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-store, max-age=0"},
        )
    return HTMLResponse("<h1>前端页面未找到</h1>", status_code=404)


@app.get("/session_state.js")
async def session_state_js():
    js_path = _PROJECT_ROOT / "frontend" / "session_state.js"
    if js_path.is_file():
        return FileResponse(
            js_path,
            media_type="application/javascript",
            headers={"Cache-Control": "no-store, max-age=0"},
        )
    return Response(status_code=404)


@app.get("/api_client.js")
async def api_client_js():
    js_path = _PROJECT_ROOT / "frontend" / "api_client.js"
    return FileResponse(
        js_path,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


@app.get("/agent_transport.js")
async def agent_transport_js():
    js_path = _PROJECT_ROOT / "frontend" / "agent_transport.js"
    return FileResponse(
        js_path,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


@app.get("/iconpark-icons.js")
async def iconpark_icons_js():
    js_path = _PROJECT_ROOT / "frontend" / "iconpark-icons.js"
    if js_path.is_file():
        return FileResponse(
            js_path,
            media_type="application/javascript",
            headers={"Cache-Control": "no-store, max-age=0"},
        )
    return Response(status_code=404)


@app.get("/logo2.png")
async def light_logo():
    return FileResponse(
        _PROJECT_ROOT / "logo2.png",
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/logored.png")
async def dark_logo():
    return FileResponse(
        _PROJECT_ROOT / "logored.png",
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=3600"},
    )


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
        title=f"[{session_id[:8]}] 安全测试任务",
        session_id=session_id,
    )

    # 构建 session-aware callback
    callback = _make_session_callback(session_id, ctx)

    # "再打一次"：构建前次任务上下文（静默降级，失败不阻塞启动）
    initial_context = None
    if req.source_session_id:
        initial_context = await asyncio.to_thread(
            _build_initial_context, req.source_session_id, current_user["id"],
        )

    # 推送启动事件
    callback("mission_start", target=req.target, goal=req.goal,
             provider=req.provider, model=req.model)

    # 创建后台任务
    task = asyncio.create_task(
        _run_and_cleanup(session_id, ctx, req.target, req.goal, req.model, req.provider, callback,
                         initial_context=initial_context, nss_context=req.nss_context)
    )
    ctx.task = task

    return {"session_id": session_id, "status": "started"}


@app.get("/api/session/{session_id}/stream")
async def session_stream(
    session_id: str,
    after_seq: int = 0,
    current_user: dict = Depends(get_current_user),
):
    """会话 SSE 事件流。"""
    await _verify_session_owner(session_id, current_user["id"])
    ctx = _active_sessions.get(session_id)
    if ctx is None:
        raise HTTPException(status_code=404, detail="会话不存在或已结束")
    return StreamingResponse(
        _session_event_generator(session_id, ctx, after_seq),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.post("/api/session/{session_id}/message")
async def send_message(session_id: str, msg: ChatMessage, current_user: dict = Depends(get_current_user)):
    """向指定会话发送用户消息——支持审批决策和运行时追加指令（steering）。"""
    await _verify_session_owner(session_id, current_user["id"])
    ctx = _active_sessions.get(session_id)
    if ctx is None:
        raise HTTPException(status_code=404, detail="会话不存在或已结束")

    content = msg.content.strip()

    # ── 审批决策 ──
    if content in {"批准", "补充侦察", "拒绝"}:
        session = await asyncio.to_thread(session_store.get_session, session_id)
        if ctx.approval_decision_submitted or not session.get("pending_approval"):
            return {"status": "approval_already_resolved"}
        ctx.approval_decision_submitted = True
    else:
        # P4：忽略与上一条完全相同的连续重复指令（前端双击/重试导致），
        # 避免重复注入 steering、重复取消 Agent 任务。
        if ctx.last_user_content == content:
            return {"status": "duplicate", "message": "已忽略与上一条相同的重复消息"}
        ctx.last_user_content = content

    # 持久化消息
    seq = await asyncio.to_thread(
        session_store.add_message, session_id, "user", content,
    )
    event = {
        "type": "user_message",
        "session_id": session_id,
        "content": msg.content,
        "seq": seq,
    }
    for subscriber in tuple(ctx.subscribers):
        subscriber.put_nowait(event.copy())

    # ── 运行时追加指令（非审批消息 + 会话活跃 → 中断 Agent 并注入） ──
    if ctx.task and not ctx.task.done() and content not in {"批准", "补充侦察", "拒绝"}:
        ctx.steering_state["pending"] = content
        ctx.steering_state["processed"] = False
        # 取消所有 Agent reply task（含 Orchestrator 自身）：让主循环感知中断后
        # 将用户指令作为新一轮输入注入。dispatch_* 工具内的 _check_steering 是
        # 快速路径（若中断恰好落在工具内则就地注入），主循环负责兜底注入。
        for agent_task in tuple(ctx.agent_tasks):
            if not agent_task.done():
                agent_task.cancel()
        return {"status": "steering", "message": "指令已注入，当前操作将被中断"}

    await ctx.input_queue.put(msg.content)
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
    # 解析 target_info（如果存在）
    if session.get("target_info"):
        try:
            session["target_info"] = json.loads(session["target_info"])
        except (json.JSONDecodeError, TypeError):
            session["target_info"] = {}
    else:
        session["target_info"] = {}
    target_info = session["target_info"]
    nested_target = target_info.pop("target_info", None)
    if isinstance(nested_target, dict):
        target_info.update(nested_target)
    nested_phase = target_info.pop("phase_change", None)
    if isinstance(nested_phase, dict) and nested_phase.get("phase"):
        target_info["phase"] = nested_phase["phase"]
    nested_flag = target_info.pop("flag_found", None)
    if isinstance(nested_flag, dict):
        old_flag = nested_flag.get("flag") or nested_flag.get("content")
        if old_flag:
            target_info["flag"] = old_flag
    target_info.setdefault("target", session.get("target", ""))
    target_info.setdefault("goal", session.get("goal", ""))
    target_info.setdefault("phase", session.get("phase", ""))
    if session.get("flag"):
        target_info["flag"] = session["flag"]
    mission_state = session.get("mission_state") or {}
    if mission_state.get("flag"):
        target_info["flag"] = mission_state["flag"]
    if "exploitation_approved" in mission_state:
        target_info["exploitation_approved"] = bool(
            mission_state["exploitation_approved"]
        )
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
    messages, snapshots = await asyncio.to_thread(
        session_store.get_history_snapshot,
        session_id,
        after_seq,
        limit,
    )
    return {"messages": messages, "snapshots": snapshots}


@app.get("/api/session/{session_id}/pending_approval")
async def get_pending_approval(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """检查会话是否有待处理的审批请求。"""
    await _verify_session_owner(session_id, current_user["id"])
    # 直接查询 sessions 表的 pending_approval 字段
    session = await asyncio.to_thread(session_store.get_session, session_id)
    if not session or not session.get("pending_approval"):
        return {"pending": False}
    if session.get("status") != "active" or session_id not in _active_sessions:
        await asyncio.to_thread(
            session_store.update_session, session_id, pending_approval=None,
        )
        return {"pending": False}
    # 解析并返回完整事件数据
    try:
        payload = json.loads(session["pending_approval"])
        event = {
            "session_id": payload.get("session_id", session_id),
            "scan_summary": payload.get("scan_summary", {}),
            "plan_items": payload.get("plan_items", []),
            "reason": payload.get("reason", ""),
            "agent": payload.get("agent", "Orchestrator"),
        }
        return {"pending": True, "event": event}
    except (json.JSONDecodeError, TypeError):
        return {"pending": False}


@app.delete("/api/session/{session_id}")
async def delete_session(session_id: str, current_user: dict = Depends(get_current_user)):
    """删除会话。"""
    await _verify_session_owner(session_id, current_user["id"])
    # 如果会话仍在运行，先取消并等待
    ctx = _active_sessions.get(session_id)
    if ctx:
        deleted_event = {"type": "session_deleted", "session_id": session_id}
        for subscriber in tuple(ctx.subscribers):
            subscriber.put_nowait(deleted_event.copy())
        # 防止任务取消过程继续向旧浏览器广播审批等迟到事件。
        ctx.subscribers.clear()
        _active_sessions.pop(session_id, None)
    if ctx and ctx.task and not ctx.task.done():
        ctx.task.cancel()
        try:
            await ctx.task
        except (asyncio.CancelledError, Exception):
            pass
    # 删除 DB 记录
    await asyncio.to_thread(session_store.delete_session, session_id)
    # 删除 JSON 文件
    session_file = _sessions_dir / f"{session_id}.json"
    if session_file.is_file():
        session_file.unlink()
    return {"status": "deleted"}


@app.post("/api/session/{session_id}/cancel")
async def cancel_session(session_id: str, current_user: dict = Depends(get_current_user)):
    """取消正在运行的会话（立即生效，进程清理在后台完成）。

    立即返回：发出取消信号 + 移出活跃会话 + 标记 DB 状态。
    后台任务自身的 finally 会继续清理 shell 进程组并最终落库。
    """
    await _verify_session_owner(session_id, current_user["id"])
    ctx = _active_sessions.get(session_id)
    if ctx is None or ctx.task is None or ctx.task.done():
        raise HTTPException(status_code=404, detail="会话不存在或已结束")

    # 0) 记录停止意图：AgentScope 可能吞掉 CancelledError，
    #    _run_and_cleanup 据此将终态强制收敛为 cancelled。
    ctx.cancel_requested = True

    # 1) 按 AgentScope 官方机制，直接取消承载 reply_stream 的 task。
    for agent_task in tuple(ctx.agent_tasks):
        if not agent_task.done():
            agent_task.cancel()

    # 2) 同时取消外层任务，打断阶段调度和非 Agent 等待。
    ctx.task.cancel()

    # 3) 立即移出活跃会话，前端刷新即可看到 is_live=false
    _active_sessions.pop(session_id, None)

    # 4) 快速落库为已取消（后台 finally 会再次幂等更新）
    await asyncio.to_thread(
        session_store.update_session,
        session_id,
        status="cancelled",
        phase="cancelled",
        pending_approval=None,
    )
    return {"status": "cancelled", "message": "停止请求已生效，正在后台清理任务进程"}


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
            _session_event_generator(session_id, ctx),
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
                _session_event_generator(sid, ctx),
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
