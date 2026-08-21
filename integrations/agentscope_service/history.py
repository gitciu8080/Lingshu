"""Incremental, role-aware history compatible with legacy sessions."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from typing import Any

import core.session_store as session_store
from .account_events import publish_account_event


class RoleHistoryRecorder:
    """Persist inner-agent events while the outer AgentScope reply is running."""

    def __init__(self, session_id: str, reply_id: str = "") -> None:
        self.session_id = session_id
        self.reply_id = reply_id
        try:
            session = session_store.get_session(session_id)
            self.enabled = session is not None
            self.user_id = session.get("user_id") if session else None
        except Exception:
            self.enabled = False
            self.user_id = None
        self._streams: dict[tuple[str, str], str] = defaultdict(str)
        self._stream_ids: dict[tuple[str, str], str] = {}
        self._snapshot_writes: dict[tuple[str, str], tuple[float, int]] = {}
        self._last_text: dict[str, str] = {}
        self._text_parts: dict[str, list[str]] = defaultdict(list)
        self._tools: dict[tuple[str, str], dict[str, str]] = {}

    def _add(
        self,
        event_type: str,
        content: str,
        agent: str,
        role: str = "agent",
        source_id: str = "",
    ) -> None:
        if self.enabled:
            session_store.add_message(
                self.session_id,
                role,
                content,
                event_type,
                agent,
                source_id,
            )

    def record(
        self,
        event_type: str,
        payload: dict[str, Any],
        source_id: str = "",
    ) -> None:
        if not self.enabled:
            return
        agent = str(payload.get("agent") or "Lingshu")
        if event_type == "session_title":
            title = str(payload.get("title") or "安全测试任务")
            session_store.update_session(self.session_id, title=title)
            if self.user_id is not None:
                publish_account_event(
                    self.user_id,
                    "account_session_title",
                    session_id=self.session_id,
                    title=title,
                    source_id=source_id,
                )
            return
        if event_type in {"text_start", "thinking_start"}:
            kind = "thinking" if event_type.startswith("thinking") else "text"
            self._streams[(agent, kind)] = ""
            self._stream_ids[(agent, kind)] = source_id
            session_store.upsert_stream_snapshot(
                self.session_id,
                self.reply_id,
                source_id,
                agent,
                kind,
                "",
            )
            self._snapshot_writes[(agent, kind)] = (time.monotonic(), 0)
            return
        if event_type in {"text_delta", "thinking_delta"}:
            kind = "thinking" if event_type.startswith("thinking") else "text"
            self._streams[(agent, kind)] += str(payload.get("delta") or "")
            block_id = self._stream_ids.get((agent, kind), source_id)
            now = time.monotonic()
            last_write, last_size = self._snapshot_writes.get((agent, kind), (0.0, 0))
            content = self._streams[(agent, kind)]
            if now - last_write >= 0.2 or len(content) - last_size >= 512:
                session_store.upsert_stream_snapshot(
                    self.session_id,
                    self.reply_id,
                    block_id,
                    agent,
                    kind,
                    content,
                )
                self._snapshot_writes[(agent, kind)] = (now, len(content))
            return
        if event_type in {"text_end", "thinking_end"}:
            kind = "thinking" if event_type.startswith("thinking") else "text"
            content = self._streams.pop((agent, kind), "")
            block_id = self._stream_ids.pop((agent, kind), source_id)
            if content:
                self._add(event_type, content, agent, source_id=block_id)
                if kind == "text":
                    self._last_text[agent] = content
                    self._text_parts[agent].append(content)
            session_store.delete_stream_snapshot(self.session_id, block_id)
            self._snapshot_writes.pop((agent, kind), None)
            return
        if event_type == "message":
            content = str(payload.get("content") or payload.get("message") or "")
            emitted = self._text_parts.pop(agent, [])
            joined = "\n".join(emitted)
            compact = "".join(emitted)
            if content and content not in {joined, compact}:
                self._add("message", content, agent, source_id=source_id)
                self._last_text[agent] = content
            return
        if event_type == "tool_call_start":
            tool_id = str(payload.get("tool_call_id") or "")
            key = (agent, tool_id)
            self._tools[key] = {
                "agent": agent,
                "tool_name": str(payload.get("tool_name") or ""),
                "args": "",
            }
            self._add(
                event_type,
                json.dumps(
                    {"tool_call_id": tool_id, "tool_name": payload.get("tool_name", "")},
                    ensure_ascii=False,
                ),
                agent,
                source_id=source_id,
            )
            return
        if event_type == "tool_call_delta":
            tool_id = str(payload.get("tool_call_id") or "")
            key = (agent, tool_id)
            tool = self._tools.setdefault(
                key,
                {"agent": agent, "tool_name": "", "args": ""},
            )
            tool["args"] += str(payload.get("delta") or "")
            return
        if event_type == "tool_call_end":
            tool_id = str(payload.get("tool_call_id") or "")
            key = (agent, tool_id)
            tool = self._tools.pop(
                key,
                {"agent": agent, "tool_name": str(payload.get("tool_name") or ""), "args": ""},
            )
            self._add(
                event_type,
                json.dumps(
                    {
                        "tool_call_id": tool_id,
                        "tool_name": tool.get("tool_name") or payload.get("tool_name", ""),
                        "full_args": tool.get("args", ""),
                    },
                    ensure_ascii=False,
                ),
                str(tool.get("agent") or agent),
                source_id=source_id,
            )
            return

        if event_type == "mission_start":
            content = f"目标: {payload.get('target', '')} | 任务: {payload.get('goal', '')}"
        elif event_type in {"mission_end", "mission_cancelled", "error"}:
            content = str(payload.get("message") or payload.get("status") or event_type)
        elif event_type == "phase_change":
            content = str(payload.get("phase") or "")
        elif event_type in {
            "plan_updated",
            "approval_required",
            "approval_resolved",
            "target_info",
            "scope_updated",
            "flag_found",
            "nss_submit",
            "expert_joined",
        }:
            content = json.dumps(payload, ensure_ascii=False)
        else:
            return

        role = "system" if event_type in {
            "mission_start",
            "mission_end",
            "mission_cancelled",
            "phase_change",
            "approval_required",
            "approval_resolved",
            "error",
            "expert_joined",
        } else "agent"
        self._add(event_type, content, agent, role, source_id)

        if event_type == "phase_change" and self.user_id is not None:
            session_store.update_session(
                self.session_id,
                phase=str(payload.get("phase") or ""),
            )
            publish_account_event(
                self.user_id,
                "account_phase_change",
                session_id=self.session_id,
                phase=str(payload.get("phase") or ""),
                previous_phase=str(payload.get("previous_phase") or ""),
                reason=str(payload.get("reason") or ""),
                source_id=source_id,
            )

        if event_type == "mission_end":
            status = str(payload.get("status") or "failed")
            success = payload.get("success")
            session_store.update_session(
                self.session_id,
                status="completed" if success else "failed",
                phase=status,
                success=success,
                flag=payload.get("flag"),
            )
        elif event_type == "mission_cancelled":
            session_store.update_session(
                self.session_id,
                status="cancelled",
                phase="cancelled",
                success=False,
            )
        elif event_type == "error":
            session_store.update_session(
                self.session_id,
                status="failed",
                phase="failed",
                success=False,
            )
