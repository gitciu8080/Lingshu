""" Web API FastAPI SSE — 多会话并行架构 """
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import subprocess
import time
import uuid
from datetime import datetime
from contextlib import asynccontextmanager, suppress
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

from core.auth import (
    get_current_user,
    create_user,
    verify_password,
    create_access_token,
    decode_access_token,
    get_user_by_username,
    list_users,
    reset_user_password,
    delete_user,
    PasswordReset,
    UserCreate,
    UserLogin,
    TokenResponse,
)

from main import run_mission
from core.config import RuntimeConfig
from core.workspace_service import get_workspace_service, WorkspaceCapacityError
from core.api_workspace import (
    list_artifacts as _list_workspace_artifacts,
    resolve_artifact_path as _resolve_artifact_path,
    workspace_summary as _workspace_summary,
)
from Tools.tooling import (
    interrupt_agent_tasks,
)
import core.session_store as session_store
import core.persistence_service as ps
from core.session_events import (
    message_operation as _event_persistence_operation,
    session_create_operation,
    session_update_operation,
    target_info_operation,
)
from integrations.agentscope_service import (
    agentscope_app,
    agentscope_lifespan,
    control_router as agentscope_control_router,
)
from integrations.agentscope_service.account_events import publish_account_event
from integrations.antsword_service import get_antsword_service
from Tools.KnowledgeBase import get_rag_service
from core.TaskState import infer_exploitation_approval_status
from Tools.tool_catalog import get_tool_catalog
from Tools.target import normalize_target
from core.model_registry import (
    ModelRegistryError,
    active_llm_providers,
    create_model_config,
    delete_model_config,
    get_model_config,
    list_model_configs,
    update_model_config,
)

logger = logging.getLogger(__name__)

# ── SessionContext 与会话注册表 ──

@dataclass
class SessionContext:
    session_id: str
    user_id: int
    input_queue: asyncio.Queue
    task: asyncio.Task | None = None
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    stream_buffers: dict[str, str] = field(default_factory=dict)
    # stream key → 稳定 block id。必须跨 start/delta/end 传递，历史恢复时
    # 才不会把同一 Agent 的多次推理合并覆盖成一条。
    stream_blocks: dict[str, str] = field(default_factory=dict)
    stream_counter: int = 0
    # 旧 WebUI 通道的未完成流快照写入节流状态。模型可能按单个字符返回，
    # 不能让每个 delta 都重新打开 SQLite、覆盖完整正文并提交事务。
    stream_snapshot_writes: dict[str, tuple[float, int]] = field(default_factory=dict)
    tool_buffers: dict[str, dict[str, Any]] = field(default_factory=dict)
    # SSE 审批事件发出后，SQLite 投影可能仍在异步写入队列中。实时决策必须
    # 以此内存态为准，不能等待 pending_approval 已经落盘。
    pending_approval_request: dict[str, Any] | None = None
    approval_decision_submitted: bool = False
    agent_tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    # 运行时追加指令状态（非审批用户消息 → 中断 Agent → 注入后恢复）
    steering_state: dict[str, Any] = field(
        default_factory=lambda: {"pending": None, "processed": False, "queue": []},
    )
    # 用户已点击停止：AgentScope 可能吞掉 CancelledError 使 run_mission 正常返回，
    # 此标记确保 _run_and_cleanup 终态强制收敛为 cancelled 而非 failed。
    cancel_requested: bool = False
    deleting: bool = False
    sse_resyncs: int = 0
    # 上一条已处理的用户消息内容（P4：忽略前端双击等产生的连续重复指令）
    last_user_content: str = ""

# 活跃会话注册表：session_id → SessionContext
_active_sessions: dict[str, SessionContext] = {}
_sessions_dir = _PROJECT_ROOT / ".TaskMemory" / "sessions"
_sessions_dir.mkdir(parents=True, exist_ok=True)

_STREAM_BUFFER_MAX_CHARS = max(
    16_384, int(os.getenv("LINGSHU_STREAM_BUFFER_MAX_CHARS", "1048576")),
)
_TOOL_ARGS_MAX_CHARS = max(
    4096, int(os.getenv("LINGSHU_TOOL_ARGS_MAX_CHARS", "262144")),
)
_SSE_SUBSCRIBER_QUEUE_SIZE = max(
    32, int(os.getenv("LINGSHU_SSE_SUBSCRIBER_QUEUE_SIZE", "512")),
)


def _publish_session_event(ctx: SessionContext, event: dict[str, Any]) -> None:
    """Bound per-browser backlog; a slow client must resync from SQLite."""
    for subscriber in tuple(ctx.subscribers):
        try:
            subscriber.put_nowait(event.copy())
            continue
        except asyncio.QueueFull:
            pass
        while True:
            try:
                subscriber.get_nowait()
            except asyncio.QueueEmpty:
                break
        ctx.sse_resyncs += 1
        subscriber.put_nowait({
            "type": "resync_required",
            "session_id": ctx.session_id,
            "reason": "slow_subscriber",
        })
        if not subscriber.full():
            subscriber.put_nowait(event.copy())

# 用户并发上限
MAX_CONCURRENT_SESSIONS_PER_USER = 5
_session_creation_lock = asyncio.Lock()
# 浏览器双击、网络重试等会在极短时间内发送相同创建请求。前端有加载锁，
# 此处再做服务端幂等兜底，避免并发下创建多条相同会话。
_recent_session_creations: dict[tuple[Any, ...], tuple[float, str]] = {}
_DUPLICATE_SESSION_WINDOW_SECONDS = 12.0

# ── 旧端点兼容路径常量 ──
_mission_store_path = _PROJECT_ROOT / ".TaskMemory" / "current_mission.json"
_long_memory_path = _PROJECT_ROOT / ".LongMemory" / "agentic_memory.json"
_upload_dir = _PROJECT_ROOT / "WorkDir" / "uploads"
_upload_dir.mkdir(parents=True, exist_ok=True)
_reports_dir = _PROJECT_ROOT / ".Reports"
_reports_dir.mkdir(parents=True, exist_ok=True)
_workspace_janitor_task: asyncio.Task[None] | None = None
_background_tasks: set[asyncio.Task[Any]] = set()


def _spawn_background(coro, *, name: str) -> asyncio.Task[Any]:
    task = asyncio.create_task(coro, name=name)
    _background_tasks.add(task)
    def completed(done: asyncio.Task[Any]) -> None:
        _background_tasks.discard(done)
        if done.cancelled():
            return
        error = done.exception()
        if error is not None:
            logger.error(
                "后台任务 %s 异常: %s", done.get_name(), error,
                exc_info=(type(error), error, error.__traceback__),
            )
    task.add_done_callback(completed)
    return task


def _protected_upload_paths() -> set[Path]:
    protected: set[Path] = set()
    upload_root = _upload_dir.resolve()
    for value in session_store.list_session_targets():
        try:
            candidate = Path(value).resolve()
        except (OSError, ValueError):
            continue
        if candidate == upload_root or upload_root in candidate.parents:
            protected.add(candidate)
    return protected


async def _workspace_janitor_loop() -> None:
    interval = max(
        30.0,
        float(os.getenv("LINGSHU_WORKSPACE_JANITOR_INTERVAL_SECONDS", "300")),
    )
    service = get_workspace_service()
    while True:
        try:
            protected = await asyncio.to_thread(_protected_upload_paths)
            result = await service.run_janitor(
                upload_root=_upload_dir,
                protected_uploads=protected,
            )
            if result["closed_workspaces"] or result["removed_files"] or result["failures"]:
                logger.info("Workspace janitor 完成: %s", result)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Workspace janitor 执行失败")
        await asyncio.sleep(interval)


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


async def _flush_persistence() -> None:
    """等待此前排队的持久化操作完成，用于报告、删除和关闭边界。"""
    await ps.flush_persistence()


async def _write_session_message(
    session_id: str,
    role: str,
    content: str,
    event_type: str = "message",
    agent_name: str = "",
) -> int:
    operation = _event_persistence_operation(
        session_id,
        event_type,
        {"agent": agent_name, "_content_override": content},
        role=role,
    )
    if operation is None:
        raise ValueError(f"不支持持久化的事件类型: {event_type}")
    results = await ps.submit([operation], wait=True)
    return int((results or [0])[0] or 0)


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
        if ctx.deleting:
            return
        stream_key = ""
        persistence_operations: list[dict] = []
        # 全文缓冲：text_delta / thinking_delta → 累积
        if event_type in ("text_delta", "thinking_delta"):
            agent = payload.get("agent", "")
            stream_key = f"{event_type.removesuffix('_delta')}:{agent}"
            block_id = ctx.stream_blocks.get(stream_key)
            if block_id:
                payload["block_id"] = block_id
            delta = str(payload.get("delta") or payload.get("content") or "")
            # Docker 版风格的原地字符串累加：命中 CPython 的 unicode 原地
            # 扩容优化，每 delta 成本 O(delta)，避免列表 + 全量 join。
            current = ctx.stream_buffers.get(stream_key, "")
            remaining = max(0, _STREAM_BUFFER_MAX_CHARS - len(current))
            if remaining:
                ctx.stream_buffers[stream_key] = current + delta[:remaining]
            if block_id:
                now = time.monotonic()
                full_text = ctx.stream_buffers.get(stream_key, "")
                last_write, last_size = ctx.stream_snapshot_writes.get(
                    stream_key, (0.0, 0),
                )
                # 与 Agent Service 历史镜像保持相同策略：最多约每 200ms
                # 写一次；大块输出累计 512 字符时提前落盘。首个非空
                # delta 会立即写入，崩溃恢复能力不受影响。
                if (
                    now - last_write >= 0.2
                    or len(full_text) - last_size >= 512
                ):
                    persistence_operations.append({
                        "type": "snapshot_upsert",
                        "session_id": session_id,
                        "reply_id": "",
                        "block_id": block_id,
                        "agent_name": agent,
                        "stream_type": event_type.removesuffix("_delta"),
                        "content": full_text,
                    })
                    ctx.stream_snapshot_writes[stream_key] = (now, len(full_text))
        # 全文终结：text_end → 注入 full_text 并清除缓冲区
        elif event_type in ("text_end", "thinking_end"):
            agent = payload.get("agent", "")
            stream_key = f"{event_type.removesuffix('_end')}:{agent}"
            block_id = ctx.stream_blocks.pop(stream_key, "")
            if block_id:
                payload["block_id"] = block_id
                persistence_operations.append({
                    "type": "snapshot_delete",
                    "session_id": session_id,
                    "block_id": block_id,
                })
            full = ctx.stream_buffers.pop(stream_key, "")
            if full:
                payload["full_text"] = full
            # 也推到 SSE（前端依靠 SSE 拿到含 full_text 的 text_end）
            # 注意：persist 由下面的 _persist_event 调用负责，不依赖 SSE
        # start 时清旧缓冲（防止上一条异常截断后残留）
        elif event_type in ("text_start", "thinking_start"):
            agent = payload.get("agent", "")
            stream_key = f"{event_type.removesuffix('_start')}:{agent}"
            # 若上一个块异常中断，保留其已持久化快照并新开一条记录。
            ctx.stream_counter += 1
            block_id = f"{stream_key}:{ctx.stream_counter}"
            ctx.stream_blocks[stream_key] = block_id
            ctx.stream_buffers[stream_key] = ""
            ctx.stream_snapshot_writes.pop(stream_key, None)
            payload["block_id"] = block_id

        # 工具参数按调用 ID 累积，结束时一次性持久化完整快照。
        if event_type == "tool_call_start":
            tool_call_id = payload.get("tool_call_id", "")
            if tool_call_id:
                ctx.tool_buffers[tool_call_id] = {
                    "agent": payload.get("agent", ""),
                    "tool_name": payload.get("tool_name", ""),
                    "full_args_parts": [],
                    "full_args_size": 0,
                    "output": "",
                }
        elif event_type == "tool_call_delta":
            tool_call_id = payload.get("tool_call_id", "")
            if tool_call_id:
                tool = ctx.tool_buffers.setdefault(tool_call_id, {
                    "agent": payload.get("agent", ""),
                    "tool_name": "",
                    "full_args_parts": [],
                    "full_args_size": 0,
                    "output": "",
                })
                delta = str(payload.get("delta") or "")
                size = int(tool.get("full_args_size") or 0)
                remaining = max(0, _TOOL_ARGS_MAX_CHARS - size)
                if remaining:
                    chunk = delta[:remaining]
                    tool.setdefault("full_args_parts", []).append(chunk)
                    tool["full_args_size"] = size + len(chunk)
        elif event_type == "tool_call_end":
            tool_call_id = payload.get("tool_call_id", "")
            tool = ctx.tool_buffers.pop(tool_call_id, None)
            if tool:
                payload["full_args"] = "".join(tool.get("full_args_parts", []))
                if not payload.get("tool_name"):
                    payload["tool_name"] = tool.get("tool_name", "")
            # 部分 ToolCallEndEvent 不携带输出；保留空字符串以稳定前端结构。
            payload["output"] = payload.get("output", "") or (tool or {}).get("output", "")

        payload["session_id"] = session_id
        # 实时路径只提交结构化操作；队列满载时由 writer 异步背压，绝不
        # 回退到事件循环中的同步 SQLite 写入。
        message_operation = _event_persistence_operation(
            session_id, event_type, payload,
        )
        if message_operation is not None:
            persistence_operations.append(message_operation)
        event = {"type": event_type, **payload}
        # 靶机信息采用扁平增量结构持久化，前端可直接恢复。
        if event_type == "mission_start":
            persistence_operations.append(target_info_operation(session_id, {
                "target": payload.get("target", ""),
                "goal": payload.get("goal", ""),
                "phase": "planning",
                "exploitation_approved": False,
                "exploitation_approval_status": "not_requested",
            }))
            publish_account_event(
                ctx.user_id, "account_session_started",
                session_id=session_id,
            )
        elif event_type == "target_info":
            persistence_operations.append(target_info_operation(session_id, {
                key: value for key, value in payload.items()
                if key not in {"session_id", "agent", "type"}
            }))
        elif event_type == "phase_change":
            persistence_operations.extend([
                target_info_operation(session_id, {"phase": payload.get("phase", "")}),
                session_update_operation(session_id, phase=payload.get("phase", "")),
            ])
            publish_account_event(
                ctx.user_id,
                "account_phase_change",
                session_id=session_id,
                phase=payload.get("phase", ""),
                previous_phase=payload.get("previous_phase", ""),
                reason=payload.get("reason", ""),
                source_id=str(payload.get("source_id") or ""),
            )
        elif event_type == "session_title":
            title = str(payload.get("title") or "安全测试任务")
            persistence_operations.append(session_update_operation(session_id, title=title))
            publish_account_event(
                ctx.user_id,
                "account_session_title",
                session_id=session_id,
                title=title,
                source_id=str(payload.get("source_id") or ""),
            )
        elif event_type == "flag_found":
            flag = payload.get("flag") or payload.get("content")
            if flag:
                persistence_operations.append(target_info_operation(session_id, {"flag": flag}))
        if event_type in {"mission_end", "mission_cancelled"}:
            publish_account_event(
                ctx.user_id, "account_session_terminal",
                session_id=session_id,
                status=payload.get("status") or (
                    "cancelled" if event_type == "mission_cancelled" else "failed"
                ),
                success=payload.get("success"),
            )
        # 审批状态持久化：approval_required 时保存完整事件数据，approval_resolved 时清除
        if event_type == "approval_required":
            ctx.approval_decision_submitted = False
            ctx.pending_approval_request = dict(payload)
            requested_at = datetime.now().astimezone().isoformat()
            approval_type = str(payload.get("approval_type") or (payload.get("scan_summary") or {}).get("approval_type") or "exploitation")
            pending_field = "pending_scope_approval" if approval_type == "scope" else "pending_exploitation_approval"
            persistence_operations.append(session_update_operation(
                session_id,
                pending_approval=json.dumps(payload, ensure_ascii=False),
                **{pending_field: json.dumps(payload, ensure_ascii=False)},
                **({
                    "scope_approval_status": "pending",
                    "scope_approval_decision": "",
                    "scope_approval_requested_at": requested_at,
                    "scope_approval_resolved_at": "",
                } if approval_type == "scope" else {
                    "approval_status": "pending",
                    "approval_decision": "",
                    "approval_requested_at": requested_at,
                    "approval_resolved_at": "",
                }),
            ))
            if approval_type == "scope":
                persistence_operations.append(target_info_operation(session_id, {
                    "scope_approval_status": "pending",
                    "scope_approval_request": payload.get("scan_summary", {}).get("scope_request", {}),
                }))
            else:
                persistence_operations.append(target_info_operation(session_id, {
                    "exploitation_approval_status": "pending",
                    "exploitation_approval_decision": "",
                    "exploitation_approval_requested_at": requested_at,
                    "exploitation_approval_resolved_at": "",
                }))
        elif event_type == "approval_resolved":
            ctx.approval_decision_submitted = True
            ctx.pending_approval_request = None
            decision = str(payload.get("decision") or "").strip()
            approval_status = (
                "approved" if payload.get("approved") else
                "recon_requested" if "补充侦察" in decision else "denied"
            )
            resolved_at = datetime.now().astimezone().isoformat()
            approval_type = str(payload.get("approval_type") or (payload.get("scan_summary") or {}).get("approval_type") or "exploitation")
            if approval_type == "scope":
                persistence_operations.append(session_update_operation(
                    session_id, pending_approval=None,
                    pending_scope_approval=None,
                    scope_approval_status="approved" if payload.get("approved") else "denied",
                    scope_approval_decision=decision,
                    scope_approval_resolved_at=resolved_at,
                ))
                persistence_operations.append(target_info_operation(session_id, {
                    "scope_approval_status": "approved" if payload.get("approved") else "denied",
                    "scope_approval_decision": decision,
                }))
            else:
                persistence_operations.append(session_update_operation(
                    session_id, pending_approval=None,
                    pending_exploitation_approval=None,
                    approval_status=approval_status,
                    approval_decision=decision,
                    approval_resolved_at=resolved_at,
                ))
                persistence_operations.append(target_info_operation(session_id, {
                    "exploitation_approved": bool(payload.get("approved")),
                    "exploitation_approval_status": approval_status,
                    "exploitation_approval_decision": decision,
                    "exploitation_approval_resolved_at": resolved_at,
                }))

        if persistence_operations:
            # Docker 版风格：入队批量提交；队列未启动/满载时线程池直写兜底。
            if not ps.queue_persistence_operations(persistence_operations):
                ps.fallback_direct_write(persistence_operations)

        # 每个浏览器连接拥有独立队列，所有订阅者收到完全相同的事件。
        _publish_session_event(ctx, event)

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
    if event_type in ("text_start", "thinking_start", "text_end", "thinking_end"):
        try:
            event.update(json.loads(content))
        except (json.JSONDecodeError, TypeError):
            # 兼容已落库的旧版本：结束事件 content 直接就是正文。
            if event_type.endswith("_end"):
                event["full_text"] = content
        # 旧记录没有 block_id 时，按持久化序号分块，避免 React 将同一 Agent
        # 的所有历史推理覆盖到最后一条。
        if not event.get("block_id"):
            event["block_id"] = f"legacy:{event_type}:{message.get('seq', 0)}"
    elif event_type == "phase_change":
        event["phase"] = content
    elif event_type in ("approval_required", "approval_resolved", "plan_updated", "nss_submit", "slab_submit", "expert_joined", "report_ready"):
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
    queue: asyncio.Queue = asyncio.Queue(maxsize=_SSE_SUBSCRIBER_QUEUE_SIZE)
    ctx.subscribers.add(queue)
    # 注册订阅和读取补偿消息之间不 await，不会产生事件丢失窗口。
    catchup = await asyncio.to_thread(
        session_store.get_messages,
        session_id,
        after_seq,
        5000,
    )
    stream_snapshot = [
        (key, full_text, ctx.stream_blocks.get(key, ""))
        for key, full_text in ctx.stream_buffers.items()
    ]
    tool_snapshot = {
        tool_call_id: dict(tool)
        for tool_call_id, tool in ctx.tool_buffers.items()
    }
    try:
        for message in catchup:
            yield f"data: {json.dumps(_message_to_event(message), ensure_ascii=False)}\n\n"
        for key, full_text, block_id in stream_snapshot:
            stream_type, agent = key.split(":", 1)
            snapshot = {
                "type": "stream_snapshot",
                "stream_type": stream_type,
                "agent": agent,
                "block_id": block_id,
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
                "full_args": "".join(tool.get("full_args_parts", [])),
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


def _attach_model_metadata(
    session: dict,
    runtime: RuntimeConfig | None = None,
) -> None:
    """为会话补充前端可直接展示的思考强度和实际模型名称。"""
    provider = str(session.get("provider") or "deepseek").strip().lower()
    stored_model = str(session.get("model") or "Min").strip()
    canonical_levels = {"low": "Low", "min": "Min", "max": "Max"}
    model_level = canonical_levels.get(stored_model.lower())

    if model_level is None:
        # 兼容早期直接将真实模型名写入 model 字段的会话。
        model_level = str(session.get("model_level") or "自定义")
        model_name = stored_model
    else:
        try:
            model_name = (runtime or RuntimeConfig.from_env()).model_name(
                model_level,
                provider=provider,
            )
        except (TypeError, ValueError):
            model_name = stored_model

    session["model_level"] = model_level
    session["model_name"] = model_name


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
                           nss_context: dict | None = None, slab_context: dict | None = None, resume: bool = False,
                           qwen_tool_call_mode: str | None = None,
                           authorized_target: str | None = None):
    """运行任务并处理清理逻辑。"""
    status_val = "completed"
    phase = "completed"
    summary = ""
    flag = None
    success = None
    mission_state = None
    mission_end_sent = False
    try:
        mission_state = await run_mission(
            target=target, goal=goal, model_ver=model_ver,
            provider=provider, event_callback=callback,
            qwen_tool_call_mode=qwen_tool_call_mode,
            session_id=session_id, input_queue=ctx.input_queue,
            initial_context=initial_context,
            agent_tasks=ctx.agent_tasks,
            steering_state=ctx.steering_state,
            nss_context=nss_context,
            slab_context=slab_context,
            resume=resume,
            user_id=ctx.user_id,
            authorized_target=authorized_target,
        )
        # 如果 Orchestrator 已经确定完成并取得 Flag，迟到的前端取消请求不得覆盖成功终态。
        mission_completed = bool(
            getattr(mission_state, "success", False)
            and str(getattr(getattr(mission_state, "phase", ""), "value", getattr(mission_state, "phase", "")))
            == "completed"
        )
        # AgentScope 的 reply_stream 可能吞掉 CancelledError，仅对未完成任务应用取消收敛。
        if ctx.cancel_requested and not mission_completed:
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
            # Summary 报告已由 run_mission 收尾阶段生成（含 PDF 落盘与 report_ready
            # 事件），此处仅落库并通知前端任务结束。
            callback(
                "mission_end",
                message="任务执行已结束",
                status=status_val,
                agent="system",
            )
            mission_end_sent = True
    except asyncio.CancelledError:
        # Summary 属于任务完成后的报告阶段。即使用户在报告生成期间触发
        # 取消，也不能覆盖已经由 Orchestrator 固化的成功终态。
        mission_completed = bool(
            mission_state is not None
            and getattr(mission_state, "success", False)
            and str(getattr(getattr(mission_state, "phase", ""), "value", getattr(mission_state, "phase", "")))
            == "completed"
        )
        if mission_completed:
            status_val = "completed"
            phase = "completed"
            summary = mission_state.summary or summary
            callback(
                "report_error",
                message="Summary Agent 在任务完成后被中断，已保留成功终态和结构化摘要",
                agent="system",
            )
        else:
            status_val = "cancelled"
            phase = "cancelled"
            callback("mission_cancelled", message="任务已被用户取消", agent="system")
    except Exception as exc:
        confirmed_success = bool(
            mission_state is not None
            and getattr(mission_state, "success", False)
            and str(getattr(getattr(mission_state, "phase", ""), "value", getattr(mission_state, "phase", "")))
            == "completed"
        )
        if confirmed_success:
            status_val = "completed"
            phase = "completed"
            success = True
            flag = getattr(mission_state, "flag", flag)
            summary = getattr(mission_state, "summary", summary) or summary
            callback(
                "report_error", message=f"任务成功后的收尾步骤异常：{exc}", agent="system",
            )
        else:
            status_val = "failed"
            phase = "failed"
            callback("error", message=f"任务异常：{exc}", agent="system")
    finally:
        if mission_state is None or status_val == "cancelled":
            existing = await asyncio.to_thread(session_store.get_session, session_id) or {}
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
        if not mission_end_sent:
            callback("mission_end", message="任务已结束", status=status_val)
        await _flush_persistence()
        terminal_fields: dict[str, Any] = {
            "status": status_val,
            "phase": phase,
            "success": success,
            "flag": flag,
            "summary": summary,
        }
        stored_approval = await asyncio.to_thread(session_store.get_session, session_id) or {}
        if any(stored_approval.get(key) for key in ("pending_approval", "pending_scope_approval", "pending_exploitation_approval")):
            terminal_fields.update(
                pending_approval=None,
                pending_scope_approval=None,
                pending_exploitation_approval=None,
            )
            if stored_approval.get("approval_status") == "pending":
                terminal_fields.update(
                    approval_status="cancelled",
                    approval_decision="任务结束前审批未完成",
                    approval_resolved_at=datetime.now().astimezone().isoformat(),
                )
            if stored_approval.get("scope_approval_status") == "pending":
                terminal_fields.update(
                    scope_approval_status="cancelled",
                    scope_approval_decision="任务结束前审批未完成",
                    scope_approval_resolved_at=datetime.now().astimezone().isoformat(),
                )
        await ps.submit([
            session_update_operation(session_id, **terminal_fields),
        ], wait=True)
        # 保存到长期记忆
        try:
            await asyncio.to_thread(
                _save_long_term_memory,
                session_id, target, goal, phase, success, flag, summary,
            )
        except Exception:
            pass
        # 终态事件已经广播且写入持久化队列，无需为 SSE 人为保留整套 Agent
        # 上下文；前端断线后直接从历史投影恢复。
        _active_sessions.pop(session_id, None)


@asynccontextmanager
async def _app_lifespan(_: FastAPI):
    global _workspace_janitor_task
    await ps.start_persistence()
    try:
        repaired = await ps.reconcile_mission_states(_sessions_dir)
    except Exception:
        await ps.stop_persistence()
        raise
    if repaired:
        logger.info("启动时已从 Mission JSON 校正 %d 条会话索引", repaired)
    _workspace_janitor_task = asyncio.create_task(
        _workspace_janitor_loop(), name="lingshu-workspace-janitor",
    )
    antsword = get_antsword_service()
    try:
        try:
            await antsword.start()
        except Exception as exc:  # AntSword 故障不应阻止 WebUI 和其他 Agent 启动
            antsword.last_error = str(exc)
            logger.exception("AntSword MCP 自动启动失败")

        async with agentscope_lifespan():
            rag = get_rag_service(_PROJECT_ROOT)
            # 知识库是可选子系统；嵌入端点或 Milvus Lite 不可用时不能阻塞
            # FastAPI 的 startup。后台初始化完成后，/api/knowledge/status
            # 会反映 available/error，检索接口在 ready 前安全返回不可用状态。
            rag_start_task = asyncio.create_task(
                rag.start(), name="lingshu-rag-startup",
            )
            def _log_rag_startup(task: asyncio.Task) -> None:
                if task.cancelled():
                    return
                error = task.exception()
                if error is not None:
                    logger.error(
                        "知识库后台初始化异常: %s", error,
                        exc_info=(type(error), error, error.__traceback__),
                    )

            rag_start_task.add_done_callback(_log_rag_startup)
            try:
                yield
            finally:
                active_tasks = [
                    ctx.task for ctx in _active_sessions.values()
                    if ctx.task is not None and not ctx.task.done()
                ]
                for task in active_tasks:
                    task.cancel()
                if active_tasks:
                    await asyncio.gather(*active_tasks, return_exceptions=True)
                _active_sessions.clear()
                if _workspace_janitor_task is not None:
                    _workspace_janitor_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await _workspace_janitor_task
                    _workspace_janitor_task = None
                await get_workspace_service().close_all()
                if not rag_start_task.done():
                    rag_start_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await rag_start_task
                for task in tuple(_background_tasks):
                    task.cancel()
                if _background_tasks:
                    await asyncio.gather(*tuple(_background_tasks), return_exceptions=True)
                await rag.close()
                await ps.stop_persistence()
    finally:
        if _workspace_janitor_task is not None:
            _workspace_janitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await _workspace_janitor_task
            _workspace_janitor_task = None
        await get_workspace_service().close_all()
        await ps.stop_persistence()
        await antsword.stop()


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


@app.get("/api/integrations/antsword/status")
async def antsword_status(current_user: dict = Depends(get_current_user)):
    """返回 API 托管的 AntSword MCP 进程与端口状态。"""
    del current_user
    return await get_antsword_service().status()


@app.get("/api/tooling/catalog")
async def tooling_catalog(current_user: dict = Depends(get_current_user)):
    """返回已登录用户可查看的可用能力，不暴露宿主机绝对路径。"""
    del current_user
    items = await asyncio.to_thread(get_tool_catalog().snapshot)
    return {
        "tools": [
            {
                key: item[key]
                for key in (
                    "id", "category", "kind", "status", "command", "roles",
                    "risk", "approval_required", "description", "usage_hint",
                    "alternatives",
                )
            }
            for item in items
            if item["status"] == "available"
        ],
    }

# ── JWT 认证中间件 ──
_AUTH_SKIP_PATHS = (
    "/",
    "/index.html",
    "/session_state.js",
    "/api_client.js",
    "/agent_transport.js",
    "/iconpark-icons.js",
    "/assets",
    "/logo2.png",
    "/logored.png",
    "/uploads",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/favicon.ico",
    "/auth/login",
    "/auth/register",
    "/api/version",
    "/superadmin",
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

        if int(payload.get("auth_epoch", -1)) != int(user.get("auth_epoch", 0)):
            return Response(
                status_code=401,
                content=json.dumps({"detail": "登录状态已失效，请重新登录"}),
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
    attachment_target: str | None = Field(
        default=None,
        description="已上传附件的服务器路径；与 target 同时提供时，target 作为网络授权目标",
    )
    goal: str = Field(default="获取 Flag", description="任务目标描述")
    provider: str = Field(default="deepseek", pattern="^[a-z][a-z0-9_-]{1,31}$", description="模型提供商标识")
    model: str = Field(default="Min", pattern="^(Low|Min|Max)$", description="思考级别: Low | Min | Max；Zhipu 未显式指定时默认 Max")
    qwen_tool_call_mode: str | None = Field(
        default=None, pattern="^(simple|standard)$",
        description="Qwen 工具调用难度: simple（扁平兼容）| standard（批量嵌套）",
    )
    source_session_id: str | None = Field(default=None, description="重跑来源会话ID，用于注入前次任务上下文")
    nss_context: dict | None = Field(default=None, description="NSSCTF Arena 上下文（attempt_id/token/api_base），供 Orchestrator 在线提交 Flag")
    slab_context: dict | None = Field(default=None, description="slab-match 平台上下文（exercise_id/access_key/api_base），供 Orchestrator 在线提交 Flag")


def _normalize_user_authorized_target(value: str) -> str:
    """规范化用户输入，并将其作为本次任务的初始授权目标。

    ``run_mission`` 会据此把网络目标（及域名解析出的 IP）登记到
    ``ScopeRegistry``。在 API 入口先做一次相同的规范化，保证会话记录、
    SSE 启动事件和实际执行目标使用同一字符串。
    """
    try:
        spec = normalize_target(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"目标地址无效：{exc}") from exc

    if spec.kind == "network":
        if not spec.host:
            raise HTTPException(status_code=422, detail="网络目标缺少主机名或 IP 地址")
        return f"{spec.host}:{spec.port}" if spec.port is not None else spec.host
    return spec.original_input


def _normalize_uploaded_target(value: str) -> str:
    """校验前端提交的附件路径只能指向本服务的上传目录。"""
    candidate = Path(value).expanduser().resolve()
    upload_root = _upload_dir.resolve()
    if candidate == upload_root or upload_root not in candidate.parents:
        raise HTTPException(status_code=422, detail="附件路径不在受管理的上传目录内")
    if not candidate.exists():
        raise HTTPException(status_code=422, detail="上传附件已不存在，请重新上传")
    return str(candidate)


class ChatMessage(BaseModel):
    content: str
    approval_selection: dict[str, Any] | None = None


class ModelRuntimeSettingsPayload(BaseModel):
    temperature: float = Field(default=0.7, ge=0, le=2)
    top_p: float = Field(default=0.95, gt=0, le=1)
    max_tokens: int = Field(default=0, ge=0, le=1048576)
    max_retries: int = Field(default=3, ge=0, le=10)
    context_size: int = Field(default=128000, ge=1024, le=10485760)
    timeout_seconds: float = Field(default=600, ge=1, le=3600)
    thinking_enabled: bool = True


class ModelAPIConfigPayload(BaseModel):
    """超级管理员维护的模型端点；api_key 为空时编辑操作保留原密钥。"""

    name: str = Field(min_length=2, max_length=80)
    category: str = Field(pattern="^(llm|embedding)$")
    provider: str = Field(min_length=2, max_length=32)
    api_style: str = Field(pattern="^(chat_completions|responses|embeddings)$")
    base_url: str = Field(min_length=8, max_length=500)
    gateway_mode: str = Field(default="base_url", pattern="^(base_url|full_endpoint)$")
    native_tools: list[str] = Field(default_factory=list, max_length=8)
    api_key: str | None = Field(default=None, max_length=4096)
    clear_api_key: bool = False
    model_low: str = Field(default="", max_length=300)
    model_min: str = Field(default="", max_length=300)
    model_max: str = Field(default="", max_length=300)
    model_name: str = Field(default="", max_length=300)
    dimensions: int = Field(default=0, ge=0, le=65536)
    pass_dimensions: bool = True
    enabled: bool = False
    settings: ModelRuntimeSettingsPayload = Field(default_factory=ModelRuntimeSettingsPayload)


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


# ── 版本信息（登录页无需认证） ──
_runtime_version_cache: dict[str, str] | None = None


@app.get("/api/version")
async def get_runtime_version():
    global _runtime_version_cache
    if _runtime_version_cache is not None:
        return _runtime_version_cache
    branch = os.getenv("LINGSHU_GIT_BRANCH", "unknown")
    commit = os.getenv("LINGSHU_GIT_COMMIT", "unknown")
    try:
        branch_result = await asyncio.to_thread(
            subprocess.run,
            ["git", "-C", str(_PROJECT_ROOT), "branch", "--show-current"],
            capture_output=True, text=True, timeout=2, check=False,
        )
        commit_result = await asyncio.to_thread(
            subprocess.run,
            ["git", "-C", str(_PROJECT_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=2, check=False,
        )
        branch = branch_result.stdout.strip() or branch
        commit = commit_result.stdout.strip() or commit
    except (OSError, subprocess.SubprocessError):
        pass
    _runtime_version_cache = {"branch": branch, "commit": commit}
    return _runtime_version_cache


# ── 认证路由 ──
@app.post("/auth/register", response_model=TokenResponse)
async def register(data: UserCreate):
    invite_code = os.getenv("LINGSHU_REGISTRATION_INVITE_CODE", "").strip()
    if not invite_code or data.invite_code.strip() != invite_code:
        raise HTTPException(status_code=403, detail="当前未开放公开注册，请使用有效邀请码")
    try:
        # bcrypt 哈希属于 CPU 密集操作，不能阻塞 FastAPI 事件循环。
        user = await asyncio.to_thread(
            create_user, data.username, data.password, data.email,
        )
        token, expires_in = create_access_token(user["id"], user["username"], user["role"], user.get("auth_epoch", 0))
        return TokenResponse(access_token=token, username=user["username"], expires_in=expires_in)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auth/login", response_model=TokenResponse)
async def login(data: UserLogin):
    from core.auth import get_user_by_username as _get_user

    def authenticate_and_touch() -> dict | None:
        user = _get_user(data.username)
        if not user or not verify_password(data.password, user["password_hash"]):
            return None
        # 与密码校验放入同一工作线程，避免 SQLite 与 bcrypt 分别阻塞
        # 主事件循环。
        from core.auth import get_db
        from datetime import datetime, timezone
        conn = get_db()
        try:
            conn.execute(
                "UPDATE users SET last_login = ? WHERE username = ?",
                (datetime.now(timezone.utc).isoformat(), data.username),
            )
            conn.commit()
        finally:
            conn.close()
        return user

    user = await asyncio.to_thread(authenticate_and_touch)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    token, expires_in = create_access_token(user["id"], user["username"], user["role"], user.get("auth_epoch", 0))
    return TokenResponse(access_token=token, username=user["username"], expires_in=expires_in)


@app.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user


@app.post("/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    return {"message": "登出成功"}


def _require_superadmin(current_user: dict) -> dict:
    """系统用户操作仅允许独立的 superadmin 角色执行。"""
    if current_user.get("role") != "superadmin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="需要超级管理员权限")
    return current_user


@app.get("/api/superadmin/users")
async def superadmin_users(current_user: dict = Depends(get_current_user)):
    _require_superadmin(current_user)
    return {"users": await asyncio.to_thread(list_users)}


@app.get("/api/superadmin/tooling/status")
async def superadmin_tooling_status(
    refresh: bool = False,
    current_user: dict = Depends(get_current_user),
):
    """返回完整工具健康状态；refresh=true 时重新探测版本与路径。"""
    _require_superadmin(current_user)
    items = await asyncio.to_thread(
        get_tool_catalog().snapshot,
        refresh=refresh,
        include_version=True,
    )
    counts: dict[str, int] = {}
    for item in items:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {"tools": items, "counts": counts, "manifest_schema_version": 1}


@app.get("/api/superadmin/runtime-health")
async def superadmin_runtime_health(current_user: dict = Depends(get_current_user)):
    """Expose persistence backlog, SQLite mode and workspace/disk lifecycle metrics."""
    _require_superadmin(current_user)
    workspace = get_workspace_service()
    workspace_health, sqlite_status = await asyncio.gather(
        workspace.health(
            extra_paths={"uploads": _upload_dir, "reports": _reports_dir, "task_memory": _sessions_dir},
        ),
        asyncio.to_thread(session_store.sqlite_health),
    )
    return {
        "status": "degraded" if (
            workspace_health["disk"]["waterline_reached"]
        ) else "ok",
        "persistence": {**sqlite_status, **ps.health()},
        "workspace": workspace_health,
        "realtime": {
            "active_sessions": len(_active_sessions),
            "subscribers": sum(len(ctx.subscribers) for ctx in _active_sessions.values()),
            "resyncs": sum(ctx.sse_resyncs for ctx in _active_sessions.values()),
            "buffer_chars": sum(
                len(text)
                for ctx in _active_sessions.values()
                for text in ctx.stream_buffers.values()
            ),
        },
    }


@app.put("/api/superadmin/users/{user_id}/password")
async def superadmin_reset_password(
    user_id: int,
    data: PasswordReset,
    current_user: dict = Depends(get_current_user),
):
    _require_superadmin(current_user)
    await asyncio.to_thread(reset_user_password, user_id, data.password)
    return {"message": "密码已重置；该用户的既有登录状态已失效"}


@app.delete("/api/superadmin/users/{user_id}")
async def superadmin_delete_user(user_id: int, current_user: dict = Depends(get_current_user)):
    _require_superadmin(current_user)
    if user_id == current_user["id"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="不能删除当前超级管理员账户")
    users = await asyncio.to_thread(list_users)
    target = next((item for item in users if item["id"] == user_id), None)
    if target and target.get("role") == "superadmin":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="不能删除超级管理员账户")
    await asyncio.to_thread(delete_user, user_id)
    return {"message": "用户已删除"}


def _model_payload(data: ModelAPIConfigPayload) -> dict[str, Any]:
    payload = data.model_dump() if hasattr(data, "model_dump") else data.dict()
    fields_set = getattr(data, "model_fields_set", getattr(data, "__fields_set__", set()))
    if "settings" not in fields_set:
        payload.pop("settings", None)
    return payload


async def _reload_embedding_after_change(category: str) -> dict[str, Any] | None:
    """嵌入配置保存后热重载 RAG；失败状态随响应返回，不回滚已保存配置。"""
    if category != "embedding":
        return None
    rag = get_rag_service(_PROJECT_ROOT)
    await rag.reload_runtime()
    return rag.status()


@app.get("/api/superadmin/model-configs")
async def superadmin_model_configs(
    category: str | None = None,
    current_user: dict = Depends(get_current_user),
):
    _require_superadmin(current_user)
    if category not in {None, "llm", "embedding"}:
        raise HTTPException(status_code=422, detail="category 仅支持 llm 或 embedding")
    configs = await asyncio.to_thread(list_model_configs, category)
    return {"configs": configs}


@app.get("/api/model-providers")
async def model_providers(current_user: dict = Depends(get_current_user)):
    """仅返回 Web 模型注册表中已启用的 Provider。"""
    del current_user
    providers: dict[str, dict[str, Any]] = {}
    for item in await asyncio.to_thread(active_llm_providers):
        providers[item["provider"]] = {
            "id": item["provider"], "label": item["name"],
            "api_style": item["api_style"], "builtin": item["provider"] in {"deepseek", "qwen", "zhipu"},
        }
    return {"providers": list(providers.values())}


@app.post("/api/superadmin/model-configs", status_code=status.HTTP_201_CREATED)
async def superadmin_create_model_config(
    data: ModelAPIConfigPayload,
    current_user: dict = Depends(get_current_user),
):
    _require_superadmin(current_user)
    payload = _model_payload(data)
    try:
        config = await asyncio.to_thread(create_model_config, payload, current_user["id"])
        rag_status = await _reload_embedding_after_change(config["category"])
        return {"config": config, "rag_status": rag_status}
    except ModelRegistryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.put("/api/superadmin/model-configs/{config_id}")
async def superadmin_update_model_config(
    config_id: int,
    data: ModelAPIConfigPayload,
    current_user: dict = Depends(get_current_user),
):
    _require_superadmin(current_user)
    payload = _model_payload(data)
    try:
        config = await asyncio.to_thread(
            update_model_config, config_id, payload, current_user["id"],
        )
        rag_status = await _reload_embedding_after_change(config["category"])
        return {"config": config, "rag_status": rag_status}
    except ModelRegistryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/superadmin/model-configs/{config_id}")
async def superadmin_delete_model_config(
    config_id: int,
    current_user: dict = Depends(get_current_user),
):
    _require_superadmin(current_user)
    existing = await asyncio.to_thread(get_model_config, config_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="模型 API 配置不存在")
    try:
        await asyncio.to_thread(delete_model_config, config_id, current_user["id"])
        rag_status = await _reload_embedding_after_change(existing["category"])
        return {"message": "模型 API 配置已删除", "rag_status": rag_status}
    except ModelRegistryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ── 路由 ──
@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
async def index():
    # Vite production build takes precedence.  The legacy page remains a
    # temporary fallback so deployments stay usable until their first build.
    html_path = _PROJECT_ROOT / "webui" / "dist" / "index.html"
    if not html_path.is_file():
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
        _PROJECT_ROOT / "webui" / "src" / "logo2.png",
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/logored.png")
async def dark_logo():
    return FileResponse(
        _PROJECT_ROOT / "webui" / "src" / "logored.png",
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/api/knowledge/status")
async def knowledge_status(current_user: dict = Depends(get_current_user)):
    """Return safe status for the shared, read-only `.RAG` corpus."""
    del current_user
    return get_rag_service(_PROJECT_ROOT).status()


class KnowledgeSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    top_k: int = Field(default=5, ge=1, le=10)


@app.post("/api/knowledge/search")
async def knowledge_search(req: KnowledgeSearchRequest, current_user: dict = Depends(get_current_user)):
    del current_user
    rag = get_rag_service(_PROJECT_ROOT)
    if not rag.available:
        raise HTTPException(status_code=503, detail=rag.error or "知识库不可用")
    try:
        return {"results": await rag.search(req.query, req.top_k)}
    except Exception as exc:
        # RAG 是可选子系统：检索失败不应把内部 traceback 直接抛给浏览器，
        # 同时必须留下完整服务端日志，便于定位上游 Embedding/Milvus 问题。
        logger.exception("本地知识库检索失败")
        raise HTTPException(
            status_code=503,
            detail=f"本地知识库检索失败，请稍后重试或同步索引：{exc}",
        ) from exc


@app.post("/api/knowledge/reindex")
async def knowledge_reindex(current_user: dict = Depends(get_current_user)):
    del current_user
    rag = get_rag_service(_PROJECT_ROOT)
    if not rag.available:
        # 初始化失败后允许用户通过“重建索引”直接重试，无需重启整个 API。
        await rag.restart()
    if not rag.available:
        raise HTTPException(status_code=503, detail=rag.error or "知识库不可用")
    return await rag.sync()


# ══════════════════════════════════════════════════
#  新版多会话 API
# ══════════════════════════════════════════════════

@app.post("/api/session/start")
async def session_start(req: MissionStartRequest, current_user: dict = Depends(get_current_user)):
    """创建并启动新会话。"""
    try:
        get_workspace_service().ensure_capacity()
    except WorkspaceCapacityError as exc:
        raise HTTPException(status_code=507, detail=str(exc)) from exc
    fields_set = getattr(req, "model_fields_set", set())
    model_level = "Max" if req.provider == "zhipu" and "model" not in fields_set else req.model
    enabled_providers = {
        item["provider"] for item in await asyncio.to_thread(active_llm_providers)
    }
    if req.provider not in enabled_providers:
        raise HTTPException(
            status_code=422,
            detail=f"模型提供商未在 Web 管理中启用：{req.provider}",
        )
    # target 可以是直接输入的网络目标，也可以是上传文件返回的路径。
    # 当 attachment_target 存在时，target 明确表示网络授权目标，附件只
    # 作为本地分析对象传入 run_mission，二者不再互相覆盖。
    attachment_target = _normalize_uploaded_target(req.attachment_target) if req.attachment_target else None
    authorized_target = _normalize_user_authorized_target(req.target)
    execution_target = attachment_target or authorized_target
    if attachment_target:
        try:
            target_spec = normalize_target(authorized_target)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"授权目标无效：{exc}") from exc
        if target_spec.kind != "network":
            raise HTTPException(status_code=422, detail="上传附件并填写授权目标时，授权目标必须是 IP、IP:端口或主机名")
    async with _session_creation_lock:
        fingerprint = (
            current_user["id"], authorized_target, execution_target, req.goal.strip(),
            req.provider, model_level, req.source_session_id or "",
        )
        now = time.monotonic()
        # 清除过期请求指纹，限制内存增长。
        for key, (created_at, _) in tuple(_recent_session_creations.items()):
            if now - created_at > _DUPLICATE_SESSION_WINDOW_SECONDS:
                _recent_session_creations.pop(key, None)
        duplicate = _recent_session_creations.get(fingerprint)
        if duplicate and now - duplicate[0] <= _DUPLICATE_SESSION_WINDOW_SECONDS:
            return {"session_id": duplicate[1], "status": "existing"}
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
            input_queue=asyncio.Queue(maxsize=128),
        )

        # 注册到活跃会话
        _active_sessions[session_id] = ctx
        _recent_session_creations[fingerprint] = (now, session_id)

    # 持久化到 DB（传入 API 层生成的 session_id）
    workspace_id = get_workspace_service().workspace_id(current_user["id"], session_id)
    try:
        await ps.submit([
            session_create_operation(
                session_id, user_id=current_user["id"], target=authorized_target,
                goal=req.goal, provider=req.provider, model=model_level,
                title=f"[{session_id[:8]}] 安全测试任务",
            ),
            target_info_operation(session_id, {
                "authorized_target": authorized_target,
                "attachment_target": attachment_target or "",
            }),
            session_update_operation(
                session_id, workspace_id=workspace_id, workspace_version=2,
                resume_status="fresh", checkpoint_seq=0,
            ),
        ], wait=True)
    except Exception as exc:
        async with _session_creation_lock:
            if _active_sessions.get(session_id) is ctx:
                _active_sessions.pop(session_id, None)
            if _recent_session_creations.get(fingerprint, (None, None))[1] == session_id:
                _recent_session_creations.pop(fingerprint, None)
        raise HTTPException(status_code=503, detail="会话持久化暂不可用，请稍后重试") from exc

    # 构建 session-aware callback
    callback = _make_session_callback(session_id, ctx)

    # "再打一次"：构建前次任务上下文（静默降级，失败不阻塞启动）
    initial_context = None
    if req.source_session_id:
        initial_context = await asyncio.to_thread(
            _build_initial_context, req.source_session_id, current_user["id"],
        )

    # 推送启动事件
    callback("mission_start", target=authorized_target, goal=req.goal,
             attachment_target=attachment_target or "",
             provider=req.provider, model=model_level, qwen_tool_call_mode=req.qwen_tool_call_mode)

    # 创建后台任务
    task = asyncio.create_task(
        _run_and_cleanup(session_id, ctx, execution_target, req.goal, model_level, req.provider, callback,
                         initial_context=initial_context, nss_context=req.nss_context,
                         slab_context=req.slab_context,
                         qwen_tool_call_mode=req.qwen_tool_call_mode,
                         authorized_target=(authorized_target if attachment_target else None))
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
        # approval_required 通过 SSE 发出后，持久化服务才异步投影到 SQLite。
        # 自动审批客户端会在收到 SSE 的同一轮立即回传，不能因 SQLite 尚未提交
        # 而误判为“已处理”。活跃会话的内存态是实时权威，SQLite 仅用于恢复。
        if ctx.approval_decision_submitted or ctx.pending_approval_request is None:
            return {"status": "approval_already_resolved"}
        ctx.approval_decision_submitted = True
    else:
        # P4：忽略与上一条完全相同的连续重复指令（前端双击/重试导致），
        # 避免重复注入 steering、重复取消 Agent 任务。
        if ctx.last_user_content == content:
            return {"status": "duplicate", "message": "已忽略与上一条相同的重复消息"}
        ctx.last_user_content = content

    # 持久化消息
    seq = await _write_session_message(session_id, "user", content, "user_message", "user")
    event = {
        "type": "user_message",
        "session_id": session_id,
        "content": msg.content,
        "seq": seq,
    }
    _publish_session_event(ctx, event)

    # ── 运行时追加指令（非审批消息 + 会话活跃 → 中断 Agent 并注入） ──
    if ctx.task and not ctx.task.done() and content not in {"批准", "补充侦察", "拒绝"}:
        steering_queue = ctx.steering_state.setdefault("queue", [])
        steering_queue.append(content)
        ctx.steering_state["pending"] = steering_queue[0]
        ctx.steering_state["processed"] = False
        # reply/task 名称由 stream_agent_reply / run_interruptible_agent_reply
        # 统一命名。优先向正在工作的子 Agent 回执，而非只显示指挥智能体。
        working_agents: list[str] = []
        for agent_task in tuple(ctx.agent_tasks):
            if agent_task.done():
                continue
            task_name = agent_task.get_name()
            if task_name.startswith("agent-reply:"):
                name = task_name.removeprefix("agent-reply:")
            elif task_name.startswith("agent-call:"):
                name = task_name.removeprefix("agent-call:")
            else:
                continue
            if name and name not in working_agents:
                working_agents.append(name)
        child_agents = [name for name in working_agents if name != "Orchestrator"]
        acknowledgement_agents = child_agents or (["Orchestrator"] if working_agents else [])
        # 取消所有 Agent reply task（含 Orchestrator 自身）：让主循环感知中断后
        # 将用户指令作为新一轮输入注入。dispatch_* 工具内的 _check_steering 是
        # 快速路径（若中断恰好落在工具内则就地注入），主循环负责兜底注入。
        # 根据 AgentScope 的中断语义，这里只取消承载 reply_stream 的 task；
        # 不在 HTTP 请求中等待嵌套 Agent/工具完全收尾，避免下一条情报被卡住。
        # run_mission 的 finally 仍会在任务结束时等待并回收全部 task/进程组。
        interrupted = interrupt_agent_tasks(ctx.agent_tasks)
        ack_seq = await _write_session_message(
            session_id, "system", "新情报已接收：正在中断当前步骤并交给行动指挥处理。",
            "steering_received", "system",
        )
        ack = {
            "type": "steering_received",
            "session_id": session_id,
            "content": "新情报已接收：正在中断当前步骤并交给行动指挥处理。",
            "seq": ack_seq,
        }
        _publish_session_event(ctx, ack)
        # 这不是伪造模型推理，而是执行层对“当前实际工作者已接收中断”的
        # 明确回执；每条同样持久化，刷新会话后仍可辨认情报交给了谁。
        for agent_name in acknowledgement_agents:
            agent_seq = await _write_session_message(
                session_id, "agent",
                "已接收操作员的新情报，当前步骤已中断；正在将上下文交回行动指挥重新规划。",
                "agent_acknowledged", agent_name,
            )
            agent_ack = {
                "type": "agent_acknowledged",
                "session_id": session_id,
                "agent": agent_name,
                "content": "已接收操作员的新情报，当前步骤已中断；正在将上下文交回行动指挥重新规划。",
                "seq": agent_seq,
            }
            _publish_session_event(ctx, agent_ack)
        return {
            "status": "steering",
            "interrupted_tasks": interrupted,
            "queued_messages": len(steering_queue),
            "message": "已请求中断当前 Agent，并将新情报加入调度队列",
        }

    queue_content = msg.content
    if content in {"批准", "补充侦察", "拒绝"} and msg.approval_selection:
        queue_content = json.dumps(
            {"decision": content, **msg.approval_selection},
            ensure_ascii=False,
        )
    await ctx.input_queue.put(queue_content)
    return {"status": "sent"}


@app.get("/api/sessions")
async def list_sessions(
    status_filter: str | None = None,
    limit: int = 30,
    offset: int = 0,
    current_user: dict = Depends(get_current_user),
):
    """列出用户所有会话。"""
    page_size = max(1, min(limit, 100))
    page_offset = max(0, offset)
    # 多读取一条来判断是否还有下一页，避免每次滚动都做 COUNT(*)。
    sessions = await asyncio.to_thread(
        lambda: session_store.list_sessions(
            current_user["id"], status=status_filter, limit=page_size + 1, offset=page_offset,
        )
    )
    has_more = len(sessions) > page_size
    sessions = sessions[:page_size]
    # 为活跃会话添加实时状态标记
    runtime = RuntimeConfig.from_env()
    for s in sessions:
        s["is_live"] = s["id"] in _active_sessions
        _attach_model_metadata(s, runtime)
    return {
        "sessions": sessions,
        "has_more": has_more,
        "next_offset": page_offset + len(sessions),
    }


@app.get("/api/session/{session_id}")
async def get_session_detail(session_id: str, current_user: dict = Depends(get_current_user)):
    """获取会话详情。"""
    session = await _verify_session_owner(session_id, current_user["id"])
    # 标记会话是否仍在活跃
    session["is_live"] = session_id in _active_sessions
    _attach_model_metadata(session)
    report_path = _reports_dir / f"{session_id}.pdf"
    session["report_available"] = report_path.is_file()
    if session["report_available"]:
        session["report_url"] = f"/api/session/{session_id}/report"
    # 尝试读取 MissionState JSON 文件获取更多详情
    session_file = _sessions_dir / f"{session_id}.json"
    if session_file.is_file():
        try:
            mission_data = await asyncio.to_thread(
                lambda: json.loads(session_file.read_text(encoding="utf-8")),
            )
            session["mission_state"] = mission_data
            session["markdown_available"] = bool(
                (mission_data.get("summary") or "").strip()
            )
            if session["markdown_available"]:
                session["markdown_url"] = (
                    f"/api/session/{session_id}/report/markdown"
                )
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
    if mission_state := (session.get("mission_state") or {}):
        target_info.setdefault("mission_mode", mission_state.get("mission_mode", ""))
        target_info.setdefault("category_decision", mission_state.get("category_decision", {}))
    if session.get("flag"):
        target_info["flag"] = session["flag"]
    mission_state = session.get("mission_state") or {}
    legacy_pending = False
    if session.get("pending_approval"):
        try:
            legacy_payload = json.loads(session["pending_approval"])
            legacy_pending = str(
                (legacy_payload.get("scan_summary") or {}).get("approval_type", "exploitation")
            ) != "scope"
        except (TypeError, json.JSONDecodeError):
            legacy_pending = True
    approval_status = infer_exploitation_approval_status(
        mission_state,
        pending=bool(session.get("pending_exploitation_approval")) or legacy_pending,
        active=(
            session.get("status") == "active"
            and str(mission_state.get("phase") or session.get("phase") or "")
            not in {"completed", "failed", "cancelled"}
        ),
    )
    # 新 SQLite 投影优先于无显式状态的旧 Mission；启动校正会将推导值
    # 写回索引，详情接口也即时兼容尚未重启服务的旧会话。
    if not mission_state.get("exploitation_approval_status"):
        indexed_status = str(session.get("approval_status") or "")
        if indexed_status and indexed_status != "not_requested":
            approval_status = indexed_status
    mission_state["exploitation_approval_status"] = approval_status
    mission_state.setdefault(
        "exploitation_approval_decision", session.get("approval_decision") or "",
    )
    mission_state.setdefault(
        "exploitation_approval_requested_at", session.get("approval_requested_at") or "",
    )
    mission_state.setdefault(
        "exploitation_approval_resolved_at", session.get("approval_resolved_at") or "",
    )
    session["approval_status"] = approval_status
    target_info["exploitation_approval_status"] = approval_status
    target_info["exploitation_approval_decision"] = mission_state.get(
        "exploitation_approval_decision", "",
    )
    if mission_state.get("flag"):
        target_info["flag"] = mission_state["flag"]
    if "exploitation_approved" in mission_state:
        target_info["exploitation_approved"] = bool(
            mission_state["exploitation_approved"]
        )
    # v0.3.0：Workspace v2 摘要（不暴露宿主绝对路径）
    session["workspace"] = _workspace_summary(
        get_workspace_service(), session["user_id"], session_id,
    )
    return session


@app.get("/api/session/{session_id}/report")
async def download_session_report(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """下载当前用户所属会话的 Summary Agent PDF 报告。"""
    await _verify_session_owner(session_id, current_user["id"])
    report_path = _reports_dir / f"{session_id}.pdf"
    if not report_path.is_file():
        raise HTTPException(status_code=404, detail="该会话尚未生成 PDF 报告")
    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"lingshu-report-{session_id}.pdf",
    )


@app.get("/api/session/{session_id}/report/markdown")
async def download_session_report_markdown(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """下载当前用户所属会话的 Summary Agent Markdown 报告。"""
    await _verify_session_owner(session_id, current_user["id"])
    markdown = ""
    session_file = _sessions_dir / f"{session_id}.json"
    if session_file.is_file():
        try:
            mission_data = await asyncio.to_thread(
                lambda: json.loads(session_file.read_text(encoding="utf-8")),
            )
            markdown = (mission_data.get("summary") or "").strip()
        except (json.JSONDecodeError, OSError):
            markdown = ""
    if not markdown:
        raise HTTPException(status_code=404, detail="该会话尚未生成 Markdown 报告")
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="lingshu-report-{session_id}.md"'
        },
    )


@app.get("/api/session/{session_id}/messages")
async def get_session_messages(
    session_id: str,
    after_seq: int = 0,
    before_seq: int | None = None,
    limit: int = 200,
    current_user: dict = Depends(get_current_user),
):
    """获取会话消息历史。"""
    await _verify_session_owner(session_id, current_user["id"])
    page_size = max(20, min(limit, 500))
    messages, snapshots, has_more = await asyncio.to_thread(
        session_store.get_history_page,
        session_id,
        before_seq=before_seq,
        after_seq=max(0, after_seq),
        limit=page_size,
        # 翻阅旧页时未完成快照不会变化，无需重复传输。
        include_snapshots=before_seq is None,
    )
    # 与 SSE 补偿保持同一事件协议；尤其要把 role=user 的记录还原为
    # user_message 气泡，而不是让 React 将其误作 system/message。
    converted = [_message_to_event(message) for message in messages]
    return {
        "messages": converted,
        "snapshots": snapshots,
        "has_more": has_more,
        "oldest_seq": int(messages[0]["seq"]) if messages else None,
        "newest_seq": int(messages[-1]["seq"]) if messages else None,
    }


def _jsonl_export_record(message: dict) -> dict[str, Any]:
    """将数据库行转换为竞赛可提交的单行 JSON，同时保留 raw 原始行。"""
    event_type = message.get("event_type") or (
        "user_message" if message.get("role") == "user" else "message"
    )
    record: dict[str, Any] = {
        "timestamp": message.get("created_at", ""),
        "type": event_type,
        "role": message.get("role", ""),
        "agent": message.get("agent_name", ""),
        "seq": message.get("seq", 0),
    }
    content = message.get("content", "")
    # 结构化事件的 content 是 JSON；展开后便于评审直接阅读，raw 保证原样可追溯。
    if event_type in {
        "tool_call_start", "tool_call_end", "approval_required",
        "approval_resolved", "plan_updated", "nss_submit", "slab_submit", "report_ready",
    }:
        try:
            payload = json.loads(content)
        except (TypeError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
            if event_type == "tool_call_end":
                record.update({
                    "tool": payload.get("tool_name", ""),
                    "tool_call_id": payload.get("tool_call_id", ""),
                    "arguments": payload.get("full_args", ""),
                    "output": payload.get("output", ""),
                })
            elif event_type == "tool_call_start":
                record.update({
                    "tool": payload.get("tool_name", ""),
                    "tool_call_id": payload.get("tool_call_id", ""),
                })
            else:
                record["payload"] = payload
        else:
            record["content"] = content
    elif event_type in {"text_end", "thinking_end"}:
        try:
            payload = json.loads(content)
        except (TypeError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
            record["content"] = payload.get("full_text", "")
            record["block_id"] = payload.get("block_id", "")
        else:
            record["content"] = content
    else:
        record["content"] = content
    record["raw"] = {
        "session_id": message.get("session_id", ""),
        "seq": message.get("seq", 0),
        "role": message.get("role", ""),
        "content": content,
        "event_type": message.get("event_type", ""),
        "agent_name": message.get("agent_name", ""),
        "source_id": message.get("source_id", ""),
        "created_at": message.get("created_at", ""),
    }
    return record


@app.get("/api/session/{session_id}/jsonl")
async def download_session_jsonl(
    session_id: str,
    prefix: str = "",
    current_user: dict = Depends(get_current_user),
):
    """导出完整原始会话 JSONL，包含用户、Agent、推理、工具参数及工具输出。"""
    session = await _verify_session_owner(session_id, current_user["id"])
    messages = await asyncio.to_thread(session_store.get_all_messages, session_id)
    snapshots = await asyncio.to_thread(session_store.get_stream_snapshots, session_id)

    import importlib.metadata
    try:
        agentscope_version = importlib.metadata.version("agentscope")
    except importlib.metadata.PackageNotFoundError:
        agentscope_version = "unknown"

    header = {
        "timestamp": session.get("created_at", ""),
        "type": "session_header",
        "session_id": session_id,
        "title": session.get("title", ""),
        "target": session.get("target", ""),
        "goal": session.get("goal", ""),
        "question_numbers": [
            item for item in re.split(r"[,，\s]+", prefix.strip()) if item
        ],
        "tool": "Lingshu / AgentScope",
        "agentscope_version": agentscope_version,
        "note": "完整会话导出；文件名直接使用会话 ID；raw 字段保留数据库原始事件。",
    }

    def lines():
        yield json.dumps(header, ensure_ascii=False) + "\n"
        for message in messages:
            yield json.dumps(_jsonl_export_record(message), ensure_ascii=False) + "\n"
        # 未结束的流仅在任务仍运行时存在；也导出，避免导出时丢失已生成的部分内容。
        for snapshot in snapshots:
            yield json.dumps({
                "timestamp": snapshot.get("updated_at", ""),
                "type": "stream_snapshot",
                "role": "agent",
                "agent": snapshot.get("agent_name", ""),
                "stream_type": snapshot.get("stream_type", ""),
                "block_id": snapshot.get("block_id", ""),
                "content": snapshot.get("content", ""),
            }, ensure_ascii=False) + "\n"

    safe_prefix = "".join(ch for ch in prefix.strip() if ch.isalnum() or ch in "-_")[:40]
    filename = f"{safe_prefix + '-' if safe_prefix else ''}{session_id}.jsonl"
    return StreamingResponse(
        lines(),
        media_type="application/x-ndjson; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/session/{session_id}/pending_approval")
async def get_pending_approval(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """检查会话是否有待处理的审批请求。"""
    await _verify_session_owner(session_id, current_user["id"])
    # 新字段按审批类型拆分，pending_approval 保留用于旧会话兼容。
    session = await asyncio.to_thread(session_store.get_session, session_id)
    if not session:
        return {"pending": False}
    pending_raw = (
        session.get("pending_scope_approval")
        or session.get("pending_exploitation_approval")
        or session.get("pending_approval")
    )
    if not pending_raw:
        return {"pending": False}
    if session.get("status") != "active" or session_id not in _active_sessions:
        fields: dict[str, Any] = {
            "pending_approval": None,
            "pending_scope_approval": None,
            "pending_exploitation_approval": None,
        }
        if session.get("approval_status") == "pending":
            fields.update(
                approval_status="cancelled",
                approval_decision="任务结束前审批未完成",
                approval_resolved_at=datetime.now().astimezone().isoformat(),
            )
        if session.get("scope_approval_status") == "pending":
            fields.update(
                scope_approval_status="cancelled",
                scope_approval_decision="任务结束前审批未完成",
                scope_approval_resolved_at=datetime.now().astimezone().isoformat(),
            )
        await ps.submit([
            session_update_operation(session_id, **fields),
        ], wait=True)
        return {"pending": False}
    # 解析并返回完整事件数据
    try:
        payload = json.loads(pending_raw)
        event = {
            "session_id": payload.get("session_id", session_id),
            "scan_summary": payload.get("scan_summary", {}),
            "approval_type": (payload.get("scan_summary") or {}).get("approval_type", "exploitation"),
            "plan_items": payload.get("plan_items", []),
            "reason": payload.get("reason", ""),
            "agent": payload.get("agent", "Orchestrator"),
        }
        return {"pending": True, "event": event}
    except (json.JSONDecodeError, TypeError):
        await ps.submit([
            session_update_operation(
                session_id,
                pending_approval=None,
                pending_scope_approval=None,
                pending_exploitation_approval=None,
                approval_status="cancelled",
                approval_decision="审批请求数据损坏，已安全取消",
                approval_resolved_at=datetime.now().astimezone().isoformat(),
            ),
        ], wait=True)
        return {"pending": False}


@app.delete("/api/session/{session_id}")
async def delete_session(session_id: str, current_user: dict = Depends(get_current_user)):
    """删除会话。

    固定流程（v0.3.0）：校验所有权 → 停止任务和 MCP（关闭 Workspace）→
    将 Workspace 原子移动到内部 trash → 删除消息和状态记录 → 更新 blob
    引用（孤儿 blob 后台物理删除）→ 返回。
    """
    await _verify_session_owner(session_id, current_user["id"])
    # 如果会话仍在运行，先取消并等待
    ctx = _active_sessions.get(session_id)
    if ctx:
        ctx.deleting = True
        deleted_event = {"type": "session_deleted", "session_id": session_id}
        _publish_session_event(ctx, deleted_event)
        # 防止任务取消过程继续向旧浏览器广播审批等迟到事件。
        ctx.subscribers.clear()
        _active_sessions.pop(session_id, None)
    if ctx and ctx.task and not ctx.task.done():
        ctx.task.cancel()
        try:
            await ctx.task
        except (asyncio.CancelledError, Exception):
            pass
    # v0.3.0：关闭并原子移动 Workspace 到 trash（MCP 随 close 释放）
    svc = get_workspace_service()
    trash_path: Path | None = None
    try:
        trash_path = await svc.delete(current_user["id"], session_id)
    except FileNotFoundError:
        pass  # 工作区不存在不阻塞删除
    # 删除 DB 记录（返回孤儿 blob：最后引用被移除的共享 blob）
    await _flush_persistence()
    orphaned_blobs = await asyncio.to_thread(
        session_store.delete_session, session_id,
    )
    # 后台清除孤儿 blob 与 trash（不阻塞响应）
    if orphaned_blobs:
        _spawn_background(
            _purge_orphaned_blobs(svc, orphaned_blobs),
            name=f"lingshu-purge-blobs:{session_id}",
        )
    # 删除 JSON 文件
    session_file = _sessions_dir / f"{session_id}.json"
    if session_file.is_file():
        await asyncio.to_thread(session_file.unlink)
    report_file = _reports_dir / f"{session_id}.pdf"
    if report_file.is_file():
        if trash_path is None:
            trash_path = svc.root / "trash" / f"{session_id}-{int(time.time())}"
            trash_path.mkdir(parents=True, exist_ok=True)
        report_trash = trash_path / "reports"
        report_trash.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(os.replace, report_file, report_trash / report_file.name)
    publish_account_event(
        current_user["id"], "account_session_deleted", session_id=session_id,
    )
    return {"status": "deleted"}


async def _purge_orphaned_blobs(
    svc: Any,
    orphaned_blobs: list[str],
) -> None:
    """后台物理删除不再被引用的共享 blob（删除失败静默保留，可重试）。"""
    for sha256 in orphaned_blobs:
        try:
            svc.remove_blob_if_unreferenced(sha256, referenced=False)
        except Exception:  # noqa: BLE001
            pass


@app.get("/api/session/{session_id}/artifacts")
async def get_session_artifacts(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """列出会话的可下载产物（相对路径 + 大小 + 修改时间）。"""
    await _verify_session_owner(session_id, current_user["id"])
    return {
        "session_id": session_id,
        "artifacts": _list_workspace_artifacts(
            get_workspace_service(), current_user["id"], session_id,
        ),
    }


@app.get("/api/session/{session_id}/artifacts/file")
async def get_session_artifact_file(
    session_id: str,
    path: str,
    current_user: dict = Depends(get_current_user),
):
    """下载会话产物（仅限工作区内相对路径，拒绝逃逸）。"""
    await _verify_session_owner(session_id, current_user["id"])
    try:
        target = _resolve_artifact_path(
            get_workspace_service(), current_user["id"], session_id, path,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="产物不存在") from None
    except (PermissionError, ValueError):
        raise HTTPException(status_code=403, detail="路径超出工作区范围") from None
    return FileResponse(target, filename=Path(path).name)


@app.post("/api/session/{session_id}/resume")
async def resume_session(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """继续任务：校验所有权与可恢复状态后，把会话重新投入运行。

    v0.3.0 语义：
    - 终态（completed/failed/cancelled）不重复执行，返回已终态；
    - uncertain 存在不确定动作，要求用户明确确认（resume_status 置
      resumable 后调用方走正常恢复路径）；
    - 其余状态（fresh/running/resumable）重新创建后台任务。
    具体恢复执行由 run_mission 的 resume 分支完成；此处负责闸门与状态登记。
    """
    session = await _verify_session_owner(session_id, current_user["id"])
    if session_id in _active_sessions:
        raise HTTPException(status_code=409, detail="会话正在运行中")
    summary = _workspace_summary(
        get_workspace_service(), current_user["id"], session_id,
    )
    status = (summary or {}).get("resume_status", "fresh")
    if status == "uncertain":
        raise HTTPException(
            status_code=409,
            detail="会话存在未确认的不确定动作，请先确认或放弃后重试",
        )
    terminal_phases = {"completed", "failed", "cancelled"}
    if session.get("phase") in terminal_phases or status == "terminal":
        return {
            "session_id": session_id,
            "status": "terminal",
            "phase": session.get("phase"),
        }
    # 登记恢复状态并重新启动任务
    await ps.submit([
        session_update_operation(session_id, resume_status="running"),
    ], wait=True)
    goal = session.get("goal") or ""
    provider = session.get("provider") or "deepseek"
    model = session.get("model") or "Min"
    target = session.get("target") or ""
    # 新建任务可能把网络授权目标与上传附件分开保存；恢复时必须重新
    # 使用附件作为执行目标，否则只会拿 IP 去做本地附件分析。
    target_info: dict[str, Any] = {}
    raw_target_info = session.get("target_info")
    if raw_target_info:
        try:
            parsed_target_info = json.loads(raw_target_info) if isinstance(raw_target_info, str) else raw_target_info
            if isinstance(parsed_target_info, dict):
                target_info = parsed_target_info
        except (TypeError, ValueError, json.JSONDecodeError):
            target_info = {}
    authorized_target = str(target_info.get("authorized_target") or target or "")
    attachment_target = str(target_info.get("attachment_target") or "").strip() or None
    execution_target = _normalize_uploaded_target(attachment_target) if attachment_target else target
    ctx = SessionContext(
        session_id=session_id,
        user_id=current_user["id"],
        input_queue=asyncio.Queue(maxsize=128),
    )
    _active_sessions[session_id] = ctx
    callback = _make_session_callback(session_id, ctx)
    callback("mission_resume", target=authorized_target, goal=goal,
             attachment_target=attachment_target or "")
    task = asyncio.create_task(
        _run_and_cleanup(session_id, ctx, execution_target, goal, model, provider, callback,
                         resume=True, authorized_target=(authorized_target if attachment_target else None)),
    )
    ctx.task = task
    return {"session_id": session_id, "status": "resumed"}


@app.post("/api/session/{session_id}/cancel")
async def cancel_session(session_id: str, current_user: dict = Depends(get_current_user)):
    """取消会话并等待 Agent、工具任务与 shell 进程组完成清理。"""
    await _verify_session_owner(session_id, current_user["id"])
    stored_session = await asyncio.to_thread(session_store.get_session, session_id)
    if stored_session and stored_session.get("phase") in {"completed", "failed", "cancelled"}:
        return {
            "session_id": session_id,
            "status": stored_session.get("phase"),
            "message": "任务已经结束，不能再取消；总结报告可继续生成。",
        }
    ctx = _active_sessions.get(session_id)
    if ctx is None or ctx.task is None or ctx.task.done():
        raise HTTPException(status_code=404, detail="会话不存在或已结束")

    # 0) 记录停止意图：AgentScope 可能吞掉 CancelledError，
    #    _run_and_cleanup 据此将终态强制收敛为 cancelled。
    ctx.cancel_requested = True

    # 将停止意图写入与 Orchestrator 共享的状态。这个标记优先级高于
    # steering，防止 CancelledError 被误判成“中途指令”后恢复运行。
    ctx.steering_state["cancel_requested"] = True
    ctx.steering_state["pending"] = None
    ctx.steering_state["processed"] = False
    ctx.steering_state["queue"] = []

    # 1) 按 AgentScope 官方机制，直接取消承载 reply_stream 的 task。
    for agent_task in tuple(ctx.agent_tasks):
        if not agent_task.done():
            agent_task.cancel()

    # 2) 同时取消外层任务，打断阶段调度和非 Agent 等待。
    ctx.task.cancel()

    # 3) 先落库为已取消；保留 ctx 直到 finally 完成，这样 SSE 能收到终态。
    await ps.submit([
        session_update_operation(
            session_id, status="cancelled", phase="cancelled", pending_approval=None,
        ),
    ], wait=True)
    # 4) 等待 run_mission finally 完成 Agent task、逆向服务和 shell 进程组清理。
    # 接口成功返回即表示本会话后台执行已经真正结束。
    try:
        await asyncio.wait_for(asyncio.shield(ctx.task), timeout=20)
    except asyncio.CancelledError:
        pass
    except asyncio.TimeoutError as exc:
        # 再次发送取消，且不谎报“已停止”。ctx 保留以便 finally 后续清理。
        ctx.task.cancel()
        raise HTTPException(
            status_code=504,
            detail="任务停止超时，后台清理仍在进行，请稍后重试",
        ) from exc
    finally:
        if ctx.task.done():
            _active_sessions.pop(session_id, None)
    return {"status": "cancelled", "message": "任务及其后台 Agent/命令进程已全部停止"}


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
                    return await asyncio.to_thread(
                        lambda: json.loads(session_file.read_text(encoding="utf-8")),
                    )
                except (json.JSONDecodeError, OSError):
                    pass
    # 兜底读取旧路径
    if _mission_store_path.is_file():
        try:
            return await asyncio.to_thread(
                lambda: json.loads(_mission_store_path.read_text(encoding="utf-8")),
            )
        except (json.JSONDecodeError, OSError):
            pass
    return {"phase": "idle", "message": "无运行中的任务"}


@app.get("/api/mission/history")
async def mission_history(limit: int = 20, current_user: dict = Depends(get_current_user)):
    """读取长期记忆中的任务历史。"""
    if _long_memory_path.is_file():
        try:
            data = await asyncio.to_thread(
                lambda: json.loads(_long_memory_path.read_text(encoding="utf-8")),
            )
            missions = data.get("missions", [])
            return {"missions": missions[-limit:], "total": len(missions)}
        except (json.JSONDecodeError, OSError):
            pass
    return {"missions": [], "total": 0}


@app.post("/api/mission/upload")
async def upload_target(
    files: list[UploadFile] = File(...),
    current_user: dict = Depends(get_current_user),
):
    """批量上传目标文件；多文件返回独立批次目录作为任务目标。"""
    del current_user
    max_file_size = max(
        1, int(os.getenv("LINGSHU_UPLOAD_MAX_FILE_BYTES", str(100 * 1024 * 1024))),
    )
    max_total_size = max(
        max_file_size,
        int(os.getenv("LINGSHU_UPLOAD_MAX_BATCH_BYTES", str(300 * 1024 * 1024))),
    )
    if not files:
        raise HTTPException(status_code=400, detail="至少选择一个文件")
    if len(files) > 20:
        raise HTTPException(status_code=413, detail="单次最多上传 20 个文件")

    workspace = get_workspace_service()
    try:
        await asyncio.to_thread(workspace.ensure_capacity)
    except WorkspaceCapacityError as exc:
        raise HTTPException(status_code=507, detail=str(exc)) from exc
    batch_dir = _upload_dir / uuid.uuid4().hex[:16]
    batch_dir.mkdir(parents=True, exist_ok=False)
    uploaded: list[dict[str, Any]] = []
    total_size = 0
    try:
        for index, upload in enumerate(files, 1):
            safe_name = Path(upload.filename or f"upload-{index}").name
            if safe_name in {"", ".", ".."}:
                safe_name = f"upload-{index}"
            destination = batch_dir / safe_name
            if destination.exists():
                destination = batch_dir / f"{index}_{safe_name}"
            file_size = 0
            reserved_bytes = 0
            with destination.open("xb") as handle:
                while chunk := await upload.read(1024 * 1024):
                    file_size += len(chunk)
                    total_size += len(chunk)
                    if file_size > max_file_size:
                        raise HTTPException(
                            status_code=413,
                            detail=f"文件 {safe_name} 超过配置上限 {max_file_size} 字节",
                        )
                    if total_size > max_total_size:
                        raise HTTPException(status_code=413, detail="文件总大小超过配置上限")
                    if len(chunk) > reserved_bytes:
                        reserve = max(16 * 1024 * 1024, len(chunk))
                        try:
                            await asyncio.to_thread(
                                workspace.ensure_capacity, reserve,
                            )
                        except WorkspaceCapacityError as exc:
                            raise HTTPException(status_code=507, detail=str(exc)) from exc
                        reserved_bytes += reserve
                    await asyncio.to_thread(handle.write, chunk)
                    reserved_bytes -= len(chunk)
            uploaded.append({"filename": safe_name, "path": str(destination), "size": file_size})
    except Exception:
        for child in batch_dir.iterdir():
            if child.is_file():
                child.unlink()
        batch_dir.rmdir()
        raise
    finally:
        for upload in files:
            await upload.close()

    target_path = uploaded[0]["path"] if len(uploaded) == 1 else str(batch_dir)
    return {
        "files": uploaded,
        "count": len(uploaded),
        "total_size": total_size,
        "target": target_path,
        "path": target_path,
        "message": f"已上传 {len(uploaded)} 个文件",
    }


# Vite fingerprints every production asset.  Serve only files beneath the
# expected dist directory, then let client-side React Router handle routes.
@app.get("/assets/{asset_path:path}")
async def vite_asset(asset_path: str):
    root = (_PROJECT_ROOT / "webui" / "dist" / "assets").resolve()
    candidate = (root / asset_path).resolve()
    if root not in candidate.parents or not candidate.is_file():
        raise HTTPException(status_code=404, detail="静态资源未找到")
    return FileResponse(candidate, headers={"Cache-Control": "public, max-age=31536000, immutable"})


@app.get("/{frontend_path:path}", response_class=HTMLResponse)
async def react_spa(frontend_path: str):
    """SPA fallback, deliberately declared after all API routes."""
    del frontend_path
    html_path = _PROJECT_ROOT / "webui" / "dist" / "index.html"
    if html_path.is_file():
        return HTMLResponse(html_path.read_text(encoding="utf-8"), headers={"Cache-Control": "no-store"})
    raise HTTPException(status_code=404, detail="React 前端尚未构建")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8080, reload=False, log_level="info")
