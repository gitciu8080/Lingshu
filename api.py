""" Web API FastAPI SSE — 多会话并行架构 """
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import sys
import subprocess
import time
import uuid
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

from auth import (
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
from config import RuntimeConfig
from workspace_service import get_workspace_service
from api_workspace import (
    list_artifacts as _list_workspace_artifacts,
    resolve_artifact_path as _resolve_artifact_path,
    workspace_summary as _workspace_summary,
)
from Tools.tooling import (
    interrupt_agent_tasks,
)
import session_store
from integrations.agentscope_service import (
    agentscope_app,
    agentscope_lifespan,
    control_router as agentscope_control_router,
)
from integrations.agentscope_service.account_events import publish_account_event
from integrations.antsword_service import get_antsword_service
from Tools.KnowledgeBase import get_rag_service
from Tools.tool_catalog import get_tool_catalog
from Tools.target import normalize_target
from model_registry import (
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
    tool_buffers: dict[str, dict[str, str]] = field(default_factory=dict)
    approval_decision_submitted: bool = False
    agent_tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    # 运行时追加指令状态（非审批用户消息 → 中断 Agent → 注入后恢复）
    steering_state: dict[str, Any] = field(
        default_factory=lambda: {"pending": None, "processed": False, "queue": []},
    )
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
    # slab-match 在线提交结果
    "slab_submit",
    "report_ready",
})

# 系统级事件（role="system"），其余持久化事件 role="agent"
_SYSTEM_ROLE_EVENTS = frozenset({
    "mission_start", "mission_end", "mission_cancelled",
    "phase_change", "error",
    "approval_required", "approval_resolved",
    "expert_joined",
    "report_ready",
})

_persistence_queue: asyncio.Queue[list[dict]] | None = None
_persistence_task: asyncio.Task | None = None


def _event_persistence_operation(
    session_id: str,
    event_type: str,
    payload: dict,
) -> dict | None:
    """将事件转换为可批量写入的纯数据操作。"""
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
        # block_id 与正文必须一起存储；只存纯正文会使刷新回放无法区分
        # 同一 Agent 的多段推理/输出，最终被前端覆盖为一条。
        content = json.dumps({
            "block_id": payload.get("block_id", ""),
            "full_text": payload.get("full_text", payload.get("content", "")),
        }, ensure_ascii=False)
    elif event_type in ("text_start", "thinking_start"):
        content = json.dumps({"block_id": payload.get("block_id", "")}, ensure_ascii=False)
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
            "output": payload.get("output", ""),
        }, ensure_ascii=False)
    elif event_type == "approval_required":
        # 保存完整事件数据（含 scan_summary、plan_items、reason），供断线重连时恢复审批弹窗
        content = json.dumps(payload, ensure_ascii=False)
    elif event_type == "approval_resolved":
        # 保存审批结果，供前端恢复时判断是否已审批
        content = json.dumps({
            "approved": payload.get("approved", False),
            "decision": payload.get("decision", ""),
            "selected_plan_id": payload.get("selected_plan_id", ""),
            "priority_order": payload.get("priority_order", []),
        }, ensure_ascii=False)
    elif event_type == "nss_submit":
        # 保存 NSSCTF 提交结果，供历史回放
        content = json.dumps(payload, ensure_ascii=False)
    elif event_type == "slab_submit":
        # 保存 slab-match 提交结果，供历史回放
        content = json.dumps(payload, ensure_ascii=False)
    elif event_type == "report_ready":
        content = json.dumps(payload, ensure_ascii=False)
    else:
        content = payload.get("content", payload.get("message", ""))
    # 系统事件 role="system"，Agent 流式/消息事件 role="agent"
    role = "system" if event_type in _SYSTEM_ROLE_EVENTS else "agent"
    return {
        "type": "message",
        "session_id": session_id,
        "role": role,
        "content": content,
        "event_type": event_type,
        "agent_name": agent_name,
        "source_id": "",
    }


def _persist_event(session_id: str, event_type: str, payload: dict) -> int | None:
    """同步持久化兼容入口；API lifespan 内实时路径使用批量队列。"""
    operation = _event_persistence_operation(session_id, event_type, payload)
    if operation is None:
        return None
    return session_store.apply_persistence_batch([operation])[0]


def _queue_persistence_operations(operations: list[dict]) -> bool:
    """将操作加入批量队列；测试或队列满时由调用方同步回退。"""
    if not operations or _persistence_queue is None:
        return False
    try:
        _persistence_queue.put_nowait(operations)
        return True
    except asyncio.QueueFull:
        logger.warning("持久化队列已满，回退同步写入")
        return False


async def _persistence_worker() -> None:
    """聚合短时间内的会话事件，以单个 SQLite 事务批量提交。"""
    assert _persistence_queue is not None
    queue = _persistence_queue
    while True:
        first = await queue.get()
        groups = [first]
        operation_count = len(first)
        deadline = asyncio.get_running_loop().time() + 0.02
        while operation_count < 128:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                group = await asyncio.wait_for(queue.get(), timeout=remaining)
            except asyncio.TimeoutError:
                break
            groups.append(group)
            operation_count += len(group)
        operations = [operation for group in groups for operation in group]
        try:
            await asyncio.to_thread(session_store.apply_persistence_batch, operations)
        except Exception:
            logger.exception("批量持久化失败，正在重试")
            await asyncio.sleep(0.05)
            try:
                await asyncio.to_thread(session_store.apply_persistence_batch, operations)
            except Exception:
                logger.exception("批量持久化重试失败")
        finally:
            for _ in groups:
                queue.task_done()


async def _flush_persistence() -> None:
    """等待此前排队的持久化操作完成，用于报告、删除和关闭边界。"""
    if _persistence_queue is not None:
        await _persistence_queue.join()


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


def _safe_update_session(session_id: str, **fields: Any) -> bool:
    """更新会话索引；SQLite 暂时不可用时不得中断权威 Mission 工作流。"""
    try:
        session_store.update_session(session_id, **fields)
        return True
    except sqlite3.Error:
        logger.exception(
            "会话索引更新失败，Mission JSON 与运行任务保持继续: session_id=%s fields=%s",
            session_id,
            sorted(fields),
        )
        return False


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
        stream_key = ""
        persistence_operations: list[dict] = []
        queued_persistence = _persistence_queue is not None
        # 全文缓冲：text_delta / thinking_delta → 累积
        if event_type in ("text_delta", "thinking_delta"):
            agent = payload.get("agent", "")
            stream_key = f"{event_type.removesuffix('_delta')}:{agent}"
            block_id = ctx.stream_blocks.get(stream_key)
            if block_id:
                payload["block_id"] = block_id
            ctx.stream_buffers[stream_key] = ctx.stream_buffers.get(stream_key, "") + (
                payload.get("delta") or payload.get("content") or ""
            )
            if block_id:
                now = time.monotonic()
                full_text = ctx.stream_buffers[stream_key]
                last_write, last_size = ctx.stream_snapshot_writes.get(
                    stream_key, (0.0, 0),
                )
                # 与 Agent Service 历史镜像保持相同策略：最多约每 200ms
                # 写一次；大块输出累计 512 字符时提前落盘。首个非空
                # delta 会立即写入，崩溃恢复能力不受影响。
                if now - last_write >= 0.2 or len(full_text) - last_size >= 512:
                    if queued_persistence:
                        persistence_operations.append({
                            "type": "snapshot_upsert",
                            "session_id": session_id,
                            "reply_id": "",
                            "block_id": block_id,
                            "agent_name": agent,
                            "stream_type": event_type.removesuffix("_delta"),
                            "content": full_text,
                        })
                    else:
                        session_store.upsert_stream_snapshot(
                            session_id, "", block_id, agent,
                            event_type.removesuffix("_delta"), full_text,
                        )
                    ctx.stream_snapshot_writes[stream_key] = (now, len(full_text))
        # 全文终结：text_end → 注入 full_text 并清除缓冲区
        elif event_type in ("text_end", "thinking_end"):
            agent = payload.get("agent", "")
            stream_key = f"{event_type.removesuffix('_end')}:{agent}"
            block_id = ctx.stream_blocks.pop(stream_key, "")
            if block_id:
                payload["block_id"] = block_id
                if queued_persistence:
                    persistence_operations.append({
                        "type": "snapshot_delete",
                        "session_id": session_id,
                        "block_id": block_id,
                    })
                else:
                    session_store.delete_stream_snapshot(session_id, block_id)
            full = ctx.stream_buffers.pop(stream_key, "")
            ctx.stream_snapshot_writes.pop(stream_key, None)
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
                    "full_args": "",
                    "output": "",
                }
        elif event_type == "tool_call_delta":
            tool_call_id = payload.get("tool_call_id", "")
            if tool_call_id:
                tool = ctx.tool_buffers.setdefault(tool_call_id, {
                    "agent": payload.get("agent", ""),
                    "tool_name": "",
                    "full_args": "",
                    "output": "",
                })
                tool["full_args"] += payload.get("delta") or ""
        elif event_type == "tool_call_end":
            tool_call_id = payload.get("tool_call_id", "")
            tool = ctx.tool_buffers.pop(tool_call_id, None)
            if tool:
                payload["full_args"] = tool.get("full_args", "")
                if not payload.get("tool_name"):
                    payload["tool_name"] = tool.get("tool_name", "")
            # 部分 ToolCallEndEvent 不携带输出；保留空字符串以稳定前端结构。
            payload["output"] = payload.get("output", "") or (tool or {}).get("output", "")

        payload["session_id"] = session_id
        # API 正常运行时交给后台队列批量提交；未启动 lifespan 的单元测试、
        # 脚本调用以及队列满载时保留同步可靠回退。
        seq = None
        message_operation = _event_persistence_operation(
            session_id, event_type, payload,
        )
        if queued_persistence:
            if message_operation is not None:
                persistence_operations.append(message_operation)
            if persistence_operations and not _queue_persistence_operations(
                persistence_operations,
            ):
                results = session_store.apply_persistence_batch(persistence_operations)
                if message_operation is not None:
                    seq = results[-1]
        else:
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
            _safe_update_session(
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
            _safe_update_session(session_id, title=title)
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
            _safe_update_session(
                session_id,
                pending_approval=json.dumps(payload, ensure_ascii=False),
            )
        elif event_type == "approval_resolved":
            ctx.approval_decision_submitted = True
            _safe_update_session(session_id, pending_approval=None)
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
    queue: asyncio.Queue = asyncio.Queue()
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
                           qwen_tool_call_mode: str | None = None):
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
            await asyncio.to_thread(
                _safe_update_session,
                session_id,
                status=status_val,
                phase=phase,
                success=success,
                flag=flag,
                summary=summary,
            )
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
        if not mission_end_sent:
            callback("mission_end", message="任务已结束", status=status_val)
        await _flush_persistence()
        await asyncio.to_thread(
            lambda: _safe_update_session(
                session_id, status=status_val, phase=phase,
                success=success, flag=flag, summary=summary,
            )
        )
        # 保存到长期记忆
        try:
            _save_long_term_memory(session_id, target, goal, phase, success, flag, summary)
        except Exception:
            pass
        # 正常结束时短暂保留 SSE；用户主动停止必须立即完成清理并返回。
        if status_val != "cancelled":
            await asyncio.sleep(5)
        if session_id in _active_sessions:
            del _active_sessions[session_id]


@asynccontextmanager
async def _app_lifespan(_: FastAPI):
    global _persistence_queue, _persistence_task
    _persistence_queue = asyncio.Queue(maxsize=10000)
    _persistence_task = asyncio.create_task(
        _persistence_worker(),
        name="lingshu-sqlite-persistence",
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
                if not rag_start_task.done():
                    rag_start_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await rag_start_task
                await rag.close()
                if _persistence_queue is not None:
                    await _persistence_queue.join()
                if _persistence_task is not None:
                    _persistence_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await _persistence_task
                _persistence_task = None
                _persistence_queue = None
    finally:
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
@app.get("/api/version")
async def get_runtime_version():
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
    return {"branch": branch, "commit": commit}


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
    from auth import get_user_by_username as _get_user

    def authenticate_and_touch() -> dict | None:
        user = _get_user(data.username)
        if not user or not verify_password(data.password, user["password_hash"]):
            return None
        # 与密码校验放入同一工作线程，避免 SQLite 与 bcrypt 分别阻塞
        # 主事件循环。
        from auth import get_db
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
    # 用户在“新建任务”中输入的 IP / 域名即为本次任务的初始授权目标。
    # 这里不会触发 ScopeAuditor；该审核器只用于后续发现的新增内网目标。
    authorized_target = _normalize_user_authorized_target(req.target)
    async with _session_creation_lock:
        fingerprint = (
            current_user["id"], authorized_target, req.goal.strip(),
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
            input_queue=asyncio.Queue(),
        )

        # 注册到活跃会话
        _active_sessions[session_id] = ctx
        _recent_session_creations[fingerprint] = (now, session_id)

    # 持久化到 DB（传入 API 层生成的 session_id）
    workspace_id = get_workspace_service().workspace_id(current_user["id"], session_id)
    await asyncio.to_thread(
        session_store.create_session,
        user_id=current_user["id"],
        target=authorized_target,
        goal=req.goal,
        provider=req.provider,
        model=model_level,
        title=f"[{session_id[:8]}] 安全测试任务",
        session_id=session_id,
    )
    # v0.3.0：登记 Workspace v2 标识与恢复状态（fresh=新建）
    await asyncio.to_thread(
        session_store.update_session,
        session_id,
        workspace_id=workspace_id,
        workspace_version=2,
        resume_status="fresh",
        checkpoint_seq=0,
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
    callback("mission_start", target=authorized_target, goal=req.goal,
             provider=req.provider, model=model_level, qwen_tool_call_mode=req.qwen_tool_call_mode)

    # 创建后台任务
    task = asyncio.create_task(
        _run_and_cleanup(session_id, ctx, authorized_target, req.goal, model_level, req.provider, callback,
                         initial_context=initial_context, nss_context=req.nss_context,
                         slab_context=req.slab_context,
                         qwen_tool_call_mode=req.qwen_tool_call_mode)
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
        ack_seq = await asyncio.to_thread(
            session_store.add_message,
            session_id,
            "system",
            "新情报已接收：正在中断当前步骤并交给行动指挥处理。",
            "steering_received",
            "system",
        )
        ack = {
            "type": "steering_received",
            "session_id": session_id,
            "content": "新情报已接收：正在中断当前步骤并交给行动指挥处理。",
            "seq": ack_seq,
        }
        for subscriber in tuple(ctx.subscribers):
            subscriber.put_nowait(ack.copy())
        # 这不是伪造模型推理，而是执行层对“当前实际工作者已接收中断”的
        # 明确回执；每条同样持久化，刷新会话后仍可辨认情报交给了谁。
        for agent_name in acknowledgement_agents:
            agent_seq = await asyncio.to_thread(
                session_store.add_message,
                session_id,
                "agent",
                "已接收操作员的新情报，当前步骤已中断；正在将上下文交回行动指挥重新规划。",
                "agent_acknowledged",
                agent_name,
            )
            agent_ack = {
                "type": "agent_acknowledged",
                "session_id": session_id,
                "agent": agent_name,
                "content": "已接收操作员的新情报，当前步骤已中断；正在将上下文交回行动指挥重新规划。",
                "seq": agent_seq,
            }
            for subscriber in tuple(ctx.subscribers):
                subscriber.put_nowait(agent_ack.copy())
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
            mission_data = json.loads(session_file.read_text(encoding="utf-8"))
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
    if session.get("flag"):
        target_info["flag"] = session["flag"]
    mission_state = session.get("mission_state") or {}
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
            mission_data = json.loads(session_file.read_text(encoding="utf-8"))
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
        "note": "完整会话导出；question_numbers 需按竞赛题号补充；raw 字段保留数据库原始事件。",
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
    """删除会话。

    固定流程（v0.3.0）：校验所有权 → 停止任务和 MCP（关闭 Workspace）→
    将 Workspace 原子移动到内部 trash → 删除消息和状态记录 → 更新 blob
    引用（孤儿 blob 后台物理删除）→ 返回。
    """
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
    # v0.3.0：关闭并原子移动 Workspace 到 trash（MCP 随 close 释放）
    svc = get_workspace_service()
    try:
        await svc.delete(current_user["id"], session_id)
    except FileNotFoundError:
        pass  # 工作区不存在不阻塞删除
    # 删除 DB 记录（返回孤儿 blob：最后引用被移除的共享 blob）
    await _flush_persistence()
    orphaned_blobs = await asyncio.to_thread(
        session_store.delete_session, session_id,
    )
    # 后台清除孤儿 blob 与 trash（不阻塞响应）
    if orphaned_blobs:
        asyncio.get_running_loop().create_task(
            _purge_orphaned_blobs(svc, orphaned_blobs),
        )
    # 删除 JSON 文件
    session_file = _sessions_dir / f"{session_id}.json"
    if session_file.is_file():
        session_file.unlink()
    report_file = _reports_dir / f"{session_id}.pdf"
    if report_file.is_file():
        report_file.unlink()
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
    await asyncio.to_thread(
        session_store.update_session, session_id, resume_status="running",
    )
    goal = session.get("goal") or ""
    provider = session.get("provider") or "deepseek"
    model = session.get("model") or "Min"
    target = session.get("target") or ""
    ctx = SessionContext(
        session_id=session_id,
        user_id=current_user["id"],
        input_queue=asyncio.Queue(),
    )
    _active_sessions[session_id] = ctx
    callback = _make_session_callback(session_id, ctx)
    callback("mission_resume", target=target, goal=goal)
    task = asyncio.create_task(
        _run_and_cleanup(session_id, ctx, target, goal, model, provider, callback,
                         resume=True),
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
    await asyncio.to_thread(
        session_store.update_session,
        session_id,
        status="cancelled",
        phase="cancelled",
        pending_approval=None,
    )
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
async def upload_target(
    files: list[UploadFile] = File(...),
    current_user: dict = Depends(get_current_user),
):
    """批量上传目标文件；多文件返回独立批次目录作为任务目标。"""
    del current_user
    max_file_size = 100 * 1024 * 1024
    max_total_size = 300 * 1024 * 1024
    if not files:
        raise HTTPException(status_code=400, detail="至少选择一个文件")
    if len(files) > 20:
        raise HTTPException(status_code=413, detail="单次最多上传 20 个文件")

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
            with destination.open("xb") as handle:
                while chunk := await upload.read(1024 * 1024):
                    file_size += len(chunk)
                    total_size += len(chunk)
                    if file_size > max_file_size:
                        raise HTTPException(status_code=413, detail=f"文件 {safe_name} 超过 100MB")
                    if total_size > max_total_size:
                        raise HTTPException(status_code=413, detail="文件总大小超过 300MB")
                    handle.write(chunk)
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
