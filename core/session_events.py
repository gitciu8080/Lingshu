"""Canonical mapping from mission events to SQLite projection operations."""

from __future__ import annotations

import json
import uuid
from typing import Any


PERSIST_EVENT_TYPES = frozenset({
    "mission_start", "mission_end", "mission_cancelled", "phase_change",
    "message", "error", "approval_required", "approval_resolved",
    "expert_joined", "plan_updated", "text_start", "text_end",
    "thinking_start", "thinking_end", "tool_call_start", "tool_call_end",
    "target_info", "flag_found", "nss_submit", "slab_submit", "report_ready",
    "user_message", "steering_received", "agent_acknowledged", "scope_updated",
    # Agent reply 生命周期诊断：用于定位模型响应、工具回填与 ReAct 收尾之间
    # 的断点。内容为脱敏结构化元数据，不含 prompt/思考全文。
    "agent_reply_started", "agent_reply_finished", "agent_reply_error",
    "agent_reply_cancelled",
})

SYSTEM_ROLE_EVENTS = frozenset({
    "mission_start", "mission_end", "mission_cancelled", "phase_change",
    "error", "approval_required", "approval_resolved", "expert_joined",
    "report_ready",
})


def message_operation(
    session_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    source_id: str = "",
    operation_id: str = "",
    role: str | None = None,
) -> dict[str, Any] | None:
    if event_type not in PERSIST_EVENT_TYPES:
        return None
    agent_name = str(payload.get("agent") or "")
    if "_content_override" in payload:
        content = payload["_content_override"]
    elif event_type == "mission_start":
        content = f"目标: {payload.get('target', '')} | 任务: {payload.get('goal', '')}"
    elif event_type == "mission_end":
        content = f"状态: {payload.get('status', '未知')}"
    elif event_type == "mission_cancelled":
        content = payload.get("message", "任务已被取消")
    elif event_type == "phase_change":
        content, agent_name = payload.get("phase", ""), "system"
    elif event_type == "expert_joined":
        content = json.dumps({
            "expert_name": payload.get("expert_name") or agent_name,
            "specialty": payload.get("specialty", ""),
        }, ensure_ascii=False)
        agent_name = "system"
    elif event_type == "error":
        content = payload.get("message", "")
    elif event_type in {"text_end", "thinking_end"}:
        content = json.dumps({
            "block_id": payload.get("block_id", source_id),
            "full_text": payload.get("full_text", payload.get("content", "")),
        }, ensure_ascii=False)
    elif event_type in {"text_start", "thinking_start"}:
        content = json.dumps(
            {"block_id": payload.get("block_id", source_id)}, ensure_ascii=False,
        )
    elif event_type == "plan_updated":
        content = json.dumps({
            "items": payload.get("items", []), "phase": payload.get("phase", ""),
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
            "result_returned": payload.get("result_returned", False),
            "result_chars": payload.get("result_chars", 0),
            "result_field": payload.get("result_field", ""),
        }, ensure_ascii=False)
    elif event_type in {
        "approval_required", "nss_submit", "slab_submit", "report_ready",
        "agent_reply_started", "agent_reply_finished", "agent_reply_error",
        "agent_reply_cancelled",
    }:
        content = json.dumps(payload, ensure_ascii=False)
    elif event_type == "approval_resolved":
        content = json.dumps({
            "approved": payload.get("approved", False),
            "decision": payload.get("decision", ""),
            "selected_plan_id": payload.get("selected_plan_id", ""),
            "priority_order": payload.get("priority_order", []),
        }, ensure_ascii=False)
    else:
        content = payload.get("content", payload.get("message", ""))
    return {
        "type": "message",
        "operation_id": operation_id or uuid.uuid4().hex,
        "session_id": session_id,
        "role": role or ("system" if event_type in SYSTEM_ROLE_EVENTS else "agent"),
        "content": str(content),
        "event_type": event_type,
        "agent_name": agent_name,
        "source_id": source_id,
    }


def session_update_operation(session_id: str, **fields: Any) -> dict[str, Any]:
    return {
        "type": "session_update", "operation_id": uuid.uuid4().hex,
        "session_id": session_id, "fields": fields,
    }


def session_create_operation(session_id: str, **fields: Any) -> dict[str, Any]:
    return {
        "type": "session_create", "operation_id": uuid.uuid4().hex,
        "session_id": session_id, "fields": fields,
    }


def target_info_operation(session_id: str, values: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "target_info_merge", "operation_id": uuid.uuid4().hex,
        "session_id": session_id, "values": values,
    }
