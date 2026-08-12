"""Agent facade that exposes a complete Lingshu mission as one reply."""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from collections.abc import AsyncGenerator
from typing import Any

from agentscope.agent import Agent
from agentscope.event import AgentEvent, ReplyEndEvent, ReplyStartEvent
from agentscope.message import Msg
from agentscope.types import ErrorInfo, ErrorType, ReplyFinishedReason

from main import run_mission
import session_store

from .events import EventTranslator
from .history import RoleHistoryRecorder
from .runtime import MissionRuntime, register_runtime, unregister_runtime

logger = logging.getLogger(__name__)


def _terminal_session_title(session_id: str, outcome: str) -> str:
    session = session_store.get_session(session_id) or {}
    title = str(session.get("title") or "安全测试任务")
    if title == str(session.get("target") or ""):
        title = "安全测试任务"
    prefix = f"[{session_id[:8]}]"
    if not title.startswith(prefix):
        title = f"{prefix} {title}"
    return f"{title} - {outcome}"


def _mission_options(inputs: Msg | list[Msg] | None) -> dict[str, Any]:
    msgs = inputs if isinstance(inputs, list) else [inputs] if isinstance(inputs, Msg) else []
    if not msgs:
        raise ValueError("A Lingshu mission requires a UserMsg input")
    msg = msgs[-1]
    if msg.role != "user":
        raise ValueError("A Lingshu mission must be started by a user message")
    options = dict(msg.metadata.get("lingshu") or {})
    text = msg.get_text_content() or ""
    goal_text = text.strip() or "获取 Flag"
    # Web 控制台（AgentScope web_ui 等）发送的纯文本消息不会携带 metadata，
    # 此时从消息文本解析授权目标：支持「目标: IP / target: IP」前缀。
    # 灵枢自家前端仍通过 metadata.lingshu 注入，不触发此回退。
    if not options.get("target"):
        target_match = re.search(r"(?:目标|target)\s*[:：]\s*(\S+)", text, re.IGNORECASE)
        if target_match:
            options["target"] = target_match.group(1).strip().rstrip("。，,;；")
            goal_text = (
                re.sub(r"(?:目标|target)\s*[:：]\s*\S+\s*", "", text, flags=re.IGNORECASE)
                .strip()
                or "获取 Flag"
            )
    options.setdefault("goal", goal_text)
    if not options.get("target"):
        raise ValueError("UserMsg.metadata.lingshu.target is required")
    return options


class LingshuMissionAgent(Agent):
    """Expose the existing audited multi-agent workflow through Agent Service."""

    async def reply_stream(
        self,
        inputs=None,
        structured_schema=None,
        yield_final_msg: bool = False,
    ) -> AsyncGenerator[AgentEvent | Msg, None]:
        del structured_schema, yield_final_msg
        options = _mission_options(inputs)
        session_id = self.state.session_id
        reply_id = uuid.uuid4().hex
        self.state.reply_id = reply_id
        translator = EventTranslator(reply_id)
        history = RoleHistoryRecorder(session_id, reply_id)
        event_queue: asyncio.Queue[AgentEvent] = asyncio.Queue()
        runtime = MissionRuntime(input_queue=asyncio.Queue())

        def callback(event_type: str, **payload: Any) -> None:
            event = translator.translate(event_type, payload)
            source_id = str(
                getattr(event, "block_id", "")
                or getattr(event, "tool_call_id", "")
                or getattr(event, "id", "")
            )
            try:
                history.record(event_type, payload, source_id)
            except Exception:
                logger.exception("Failed to persist role history for %s", session_id)
            if event_type == "approval_required":
                runtime.pending_approval = payload
                runtime.approval_decision_submitted = False
                runtime.approval_decision = None
            elif event_type == "approval_resolved":
                runtime.pending_approval = None
            event_queue.put_nowait(event)

        mission_task: asyncio.Task | None = None
        await register_runtime(session_id, runtime)
        try:
            yield ReplyStartEvent(
                session_id=session_id,
                reply_id=reply_id,
                name=self.name,
            )
            if not history.enabled:
                raise RuntimeError(
                    "AgentScope mission session is missing its role-history mirror",
                )
            callback(
                "mission_start",
                target=str(options["target"]),
                goal=str(options.get("goal") or "获取 Flag"),
                provider=str(options.get("provider") or "deepseek"),
                model=str(options.get("model_ver") or options.get("model") or "Min"),
                agent="system",
            )
            mission_task = asyncio.create_task(
                run_mission(
                    target=str(options["target"]),
                    goal=str(options.get("goal") or "获取 Flag"),
                    model_ver=str(options.get("model_ver") or options.get("model") or "Min"),
                    provider=str(options.get("provider") or "deepseek"),
                    event_callback=callback,
                    session_id=session_id,
                    input_queue=runtime.input_queue,
                    initial_context=options.get("initial_context"),
                    agent_tasks=runtime.agent_tasks,
                    steering_state=runtime.steering_state,
                    nss_context=options.get("nss_context"),
                    authorization_source="agent_service",
                ),
                name=f"lingshu-mission:{session_id}",
            )
            while not mission_task.done() or not event_queue.empty():
                try:
                    yield await asyncio.wait_for(event_queue.get(), timeout=0.2)
                except asyncio.TimeoutError:
                    continue
            mission = await mission_task
            callback(
                "mission_end",
                status=mission.phase.value,
                success=mission.success,
                flag=mission.flag,
                agent="system",
            )
            while not event_queue.empty():
                yield event_queue.get_nowait()
            summary = mission.summary or (
                f"任务结束，阶段 {mission.phase.value}，"
                f"结果：{'成功' if mission.success else '未成功'}。"
            )
            block_id = translator._block_id("system", "summary", start=True)
            try:
                history.record(
                    "message",
                    {"agent": "system", "content": summary},
                    block_id,
                )
            except Exception:
                logger.exception("Failed to persist mission summary for %s", session_id)
            from agentscope.event import TextBlockDeltaEvent, TextBlockEndEvent, TextBlockStartEvent

            yield TextBlockStartEvent(reply_id=reply_id, block_id=block_id)
            yield TextBlockDeltaEvent(reply_id=reply_id, block_id=block_id, delta=summary)
            yield TextBlockEndEvent(reply_id=reply_id, block_id=block_id)
            yield ReplyEndEvent(
                session_id=session_id,
                reply_id=reply_id,
                finished_reason=ReplyFinishedReason.COMPLETED,
            )
        except asyncio.CancelledError:
            if mission_task is not None:
                mission_task.cancel()
                try:
                    await mission_task
                except asyncio.CancelledError:
                    pass
            callback(
                "session_title",
                title=_terminal_session_title(session_id, "任务已取消"),
                agent="system",
            )
            callback("mission_cancelled", message="任务已被用户取消", agent="system")
            while not event_queue.empty():
                yield event_queue.get_nowait()
            yield ReplyEndEvent(
                session_id=session_id,
                reply_id=reply_id,
                finished_reason=ReplyFinishedReason.INTERRUPTED,
            )
        except Exception as exc:
            callback(
                "session_title",
                title=_terminal_session_title(session_id, "任务异常结束"),
                agent="system",
            )
            callback("error", message=str(exc), agent="system")
            while not event_queue.empty():
                yield event_queue.get_nowait()
            yield ReplyEndEvent(
                session_id=session_id,
                reply_id=reply_id,
                finished_reason=ReplyFinishedReason.ERROR,
                error=ErrorInfo(type=ErrorType.INTERNAL, message=str(exc)),
            )
        finally:
            if mission_task is not None and not mission_task.done():
                mission_task.cancel()
                try:
                    await mission_task
                except asyncio.CancelledError:
                    pass
            await unregister_runtime(session_id, runtime)
