"""Translate Lingshu callback events into AgentScope AgentEvent objects."""

from __future__ import annotations

import base64
import uuid
from collections import defaultdict
from typing import Any

from agentscope.event import (
    CustomEvent,
    TextBlockDeltaEvent,
    TextBlockEndEvent,
    TextBlockStartEvent,
    ThinkingBlockDeltaEvent,
    ThinkingBlockEndEvent,
    ThinkingBlockStartEvent,
    ToolCallDeltaEvent,
    ToolCallEndEvent,
    ToolCallStartEvent,
)


class LingshuCustomEvent(CustomEvent):
    """A service custom event associated with the current outer reply."""

    reply_id: str


_BUSINESS_EVENT_NAMES = {
    "mission_start": "lingshu.mission.started",
    "mission_end": "lingshu.mission.completed",
    "mission_cancelled": "lingshu.mission.cancelled",
    "phase_change": "lingshu.phase.changed",
    "session_title": "lingshu.session.title_changed",
    "expert_joined": "lingshu.expert.joined",
    "plan_updated": "lingshu.plan.updated",
    "target_info": "lingshu.target.updated",
    "scope_updated": "lingshu.scope.updated",
    "approval_required": "lingshu.approval.required",
    "approval_resolved": "lingshu.approval.resolved",
    "flag_found": "lingshu.flag.found",
    "nss_submit": "lingshu.nss.submitted",
    "error": "lingshu.error",
    "message": "lingshu.agent.message",
}


class EventTranslator:
    """Maintain block identity while translating one mission callback stream."""

    def __init__(self, reply_id: str) -> None:
        self.reply_id = reply_id
        self._counts: dict[tuple[str, str], int] = defaultdict(int)
        self._blocks: dict[tuple[str, str], str] = {}
        self._tool_ids: dict[tuple[str, str], str] = {}

    @staticmethod
    def _encode_agent(agent: str) -> str:
        return base64.urlsafe_b64encode(agent.encode("utf-8")).decode("ascii").rstrip("=")

    def _block_id(self, agent: str, kind: str, *, start: bool = False) -> str:
        key = (agent, kind)
        if start or key not in self._blocks:
            self._counts[key] += 1
            encoded_agent = self._encode_agent(agent)
            self._blocks[key] = (
                f"lingshu.{encoded_agent}.{kind}."
                f"{self._counts[key]}.{uuid.uuid4().hex[:8]}"
            )
        return self._blocks[key]

    def _tool_id(self, raw_id: str, agent: str, *, start: bool = False) -> str:
        key = (agent, raw_id)
        if start or key not in self._tool_ids:
            encoded_agent = self._encode_agent(agent)
            token = raw_id or uuid.uuid4().hex
            self._tool_ids[key] = f"lingshu.{encoded_agent}.tool.{token}"
        return self._tool_ids[key]

    def translate(self, event_type: str, payload: dict[str, Any]):
        agent = str(payload.get("agent") or "Lingshu")
        if event_type == "text_start":
            return TextBlockStartEvent(
                reply_id=self.reply_id,
                block_id=self._block_id(agent, "text", start=True),
                metadata={"agent": agent},
            )
        if event_type == "text_delta":
            return TextBlockDeltaEvent(
                reply_id=self.reply_id,
                block_id=self._block_id(agent, "text"),
                delta=str(payload.get("delta") or payload.get("content") or ""),
                metadata={"agent": agent},
            )
        if event_type == "text_end":
            return TextBlockEndEvent(
                reply_id=self.reply_id,
                block_id=self._block_id(agent, "text"),
                metadata={"agent": agent},
            )
        if event_type == "thinking_start":
            return ThinkingBlockStartEvent(
                reply_id=self.reply_id,
                block_id=self._block_id(agent, "thinking", start=True),
                metadata={"agent": agent},
            )
        if event_type == "thinking_delta":
            return ThinkingBlockDeltaEvent(
                reply_id=self.reply_id,
                block_id=self._block_id(agent, "thinking"),
                delta=str(payload.get("delta") or payload.get("content") or ""),
                metadata={"agent": agent},
            )
        if event_type == "thinking_end":
            return ThinkingBlockEndEvent(
                reply_id=self.reply_id,
                block_id=self._block_id(agent, "thinking"),
                metadata={"agent": agent},
            )
        if event_type == "tool_call_start":
            raw_id = str(payload.get("tool_call_id") or "")
            return ToolCallStartEvent(
                reply_id=self.reply_id,
                tool_call_id=self._tool_id(raw_id, agent, start=True),
                tool_call_name=str(payload.get("tool_name") or "unknown"),
                metadata={"agent": agent},
            )
        if event_type == "tool_call_delta":
            raw_id = str(payload.get("tool_call_id") or "")
            return ToolCallDeltaEvent(
                reply_id=self.reply_id,
                tool_call_id=self._tool_id(raw_id, agent),
                delta=str(payload.get("delta") or ""),
                metadata={"agent": agent},
            )
        if event_type == "tool_call_end":
            raw_id = str(payload.get("tool_call_id") or "")
            return ToolCallEndEvent(
                reply_id=self.reply_id,
                tool_call_id=self._tool_id(raw_id, agent),
                metadata={"agent": agent},
            )

        name = _BUSINESS_EVENT_NAMES.get(event_type, f"lingshu.{event_type}")
        return LingshuCustomEvent(
            reply_id=self.reply_id,
            name=name,
            value={"legacy_type": event_type, **payload},
        )
