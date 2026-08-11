"""In-process controls for missions running inside Agent Service replies."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MissionRuntime:
    input_queue: asyncio.Queue[str]
    agent_tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    steering_state: dict[str, Any] = field(
        default_factory=lambda: {"pending": None, "processed": False},
    )
    approval_decision_submitted: bool = False
    approval_decision: str | None = None
    pending_approval: dict[str, Any] | None = None


_runtimes: dict[str, MissionRuntime] = {}
_lock = asyncio.Lock()


async def register_runtime(session_id: str, runtime: MissionRuntime) -> None:
    async with _lock:
        if session_id in _runtimes:
            raise RuntimeError(f"Session {session_id!r} already has a running mission")
        _runtimes[session_id] = runtime


async def unregister_runtime(session_id: str, runtime: MissionRuntime) -> None:
    async with _lock:
        if _runtimes.get(session_id) is runtime:
            del _runtimes[session_id]


async def get_runtime(session_id: str) -> MissionRuntime | None:
    async with _lock:
        return _runtimes.get(session_id)
