"""Incremental, role-aware history compatible with legacy sessions."""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from typing import Any

from persistence_service import get_persistence_writer
from session_events import message_operation, session_update_operation
from .account_events import publish_account_event


class RoleHistoryRecorder:
    """Persist inner-agent events while the outer AgentScope reply is running."""

    def __init__(
        self,
        session_id: str,
        reply_id: str = "",
        *,
        enabled: bool = True,
        user_id: int | None = None,
    ) -> None:
        self.session_id = session_id
        self.reply_id = reply_id
        self.enabled = enabled
        self.user_id = user_id
        self._streams: dict[tuple[str, str], list[str]] = defaultdict(list)
        self._stream_sizes: dict[tuple[str, str], int] = defaultdict(int)
        self._stream_limit = max(
            16_384, int(os.getenv("LINGSHU_STREAM_BUFFER_MAX_CHARS", "1048576")),
        )
        self._tool_args_limit = max(
            4096, int(os.getenv("LINGSHU_TOOL_ARGS_MAX_CHARS", "262144")),
        )
        self._stream_ids: dict[tuple[str, str], str] = {}
        self._snapshot_writes: dict[tuple[str, str], tuple[float, int]] = {}
        self._last_text: dict[str, str] = {}
        self._text_parts: dict[str, list[str]] = defaultdict(list)
        self._tools: dict[tuple[str, str], dict[str, Any]] = {}

    def _add(
        self,
        event_type: str,
        content: str,
        agent: str,
        role: str = "agent",
        source_id: str = "",
    ) -> None:
        del role
        if not self.enabled:
            return
        operation = message_operation(
            self.session_id,
            event_type,
            {"agent": agent, "_content_override": content},
            source_id=source_id,
        )
        if operation is not None:
            get_persistence_writer().submit_from_callback([operation])

    def _submit(self, *operations: dict[str, Any]) -> None:
        if self.enabled and operations:
            get_persistence_writer().submit_from_callback(list(operations))

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
            self._submit(session_update_operation(self.session_id, title=title))
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
            self._streams[(agent, kind)] = []
            self._stream_sizes[(agent, kind)] = 0
            self._stream_ids[(agent, kind)] = source_id
            self._submit({
                "type": "snapshot_upsert", "session_id": self.session_id,
                "reply_id": self.reply_id, "block_id": source_id,
                "agent_name": agent, "stream_type": kind, "content": "",
            })
            self._snapshot_writes[(agent, kind)] = (time.monotonic(), 0)
            return
        if event_type in {"text_delta", "thinking_delta"}:
            kind = "thinking" if event_type.startswith("thinking") else "text"
            key = (agent, kind)
            delta = str(payload.get("delta") or "")
            size = self._stream_sizes[key]
            remaining = max(0, self._stream_limit - size)
            if remaining:
                chunk = delta[:remaining]
                self._streams[key].append(chunk)
                self._stream_sizes[key] = size + len(chunk)
            block_id = self._stream_ids.get((agent, kind), source_id)
            now = time.monotonic()
            last_write, last_size = self._snapshot_writes.get((agent, kind), (0.0, 0))
            # 长度判断用累计字节数而非全量 join，避免每个 delta 都做
            # O(n) 拼接（多会话并发流式下为 O(n²) CPU）。
            current_size = self._stream_sizes[(agent, kind)]
            if now - last_write >= 0.2 or current_size - last_size >= 512:
                content = "".join(self._streams[(agent, kind)])
                self._submit({
                    "type": "snapshot_upsert", "session_id": self.session_id,
                    "reply_id": self.reply_id, "block_id": block_id,
                    "agent_name": agent, "stream_type": kind, "content": content,
                })
                self._snapshot_writes[(agent, kind)] = (now, len(content))
            return
        if event_type in {"text_end", "thinking_end"}:
            kind = "thinking" if event_type.startswith("thinking") else "text"
            content = "".join(self._streams.pop((agent, kind), []))
            self._stream_sizes.pop((agent, kind), None)
            block_id = self._stream_ids.pop((agent, kind), source_id)
            if content:
                operation = message_operation(
                    self.session_id, event_type,
                    {"agent": agent, "full_text": content, "block_id": block_id},
                    source_id=block_id,
                )
                if operation is not None:
                    self._submit(operation)
                if kind == "text":
                    self._last_text[agent] = content
                    self._text_parts[agent].append(content)
            self._submit({
                "type": "snapshot_delete", "session_id": self.session_id,
                "block_id": block_id,
            })
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
                "args_parts": [],
                "args_size": 0,
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
                {"agent": agent, "tool_name": "", "args_parts": [], "args_size": 0},
            )
            delta = str(payload.get("delta") or "")
            size = int(tool.get("args_size") or 0)
            remaining = max(0, self._tool_args_limit - size)
            if remaining:
                chunk = delta[:remaining]
                tool.setdefault("args_parts", []).append(chunk)
                tool["args_size"] = size + len(chunk)
            return
        if event_type == "tool_call_end":
            tool_id = str(payload.get("tool_call_id") or "")
            key = (agent, tool_id)
            tool = self._tools.pop(
                key,
                {"agent": agent, "tool_name": str(payload.get("tool_name") or ""), "args_parts": []},
            )
            self._add(
                event_type,
                json.dumps(
                    {
                        "tool_call_id": tool_id,
                        "tool_name": tool.get("tool_name") or payload.get("tool_name", ""),
                        "full_args": "".join(tool.get("args_parts", [])),
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
            self._submit(session_update_operation(
                self.session_id, phase=str(payload.get("phase") or ""),
            ))
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
            self._submit(session_update_operation(
                self.session_id, status="completed" if success else "failed",
                phase=status, success=success, flag=payload.get("flag"),
            ))
        elif event_type == "mission_cancelled":
            self._submit(session_update_operation(
                self.session_id, status="cancelled", phase="cancelled", success=False,
            ))
        elif event_type == "error":
            self._submit(session_update_operation(
                self.session_id, status="failed", phase="failed", success=False,
            ))
