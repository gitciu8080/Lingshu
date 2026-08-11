"""Account-wide event fan-out for cross-tab/session UI synchronization."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any


_subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}


def publish_account_event(
    user_id: str | int,
    event_type: str,
    **payload: Any,
) -> dict[str, Any]:
    event = {
        "id": uuid.uuid4().hex,
        "type": event_type,
        **payload,
    }
    for queue in tuple(_subscribers.get(str(user_id), ())):
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        queue.put_nowait(event.copy())
    return event


def subscribe_account(user_id: str | int) -> asyncio.Queue[dict[str, Any]]:
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
    _subscribers.setdefault(str(user_id), set()).add(queue)
    return queue


def unsubscribe_account(
    user_id: str | int,
    queue: asyncio.Queue[dict[str, Any]],
) -> None:
    subscribers = _subscribers.get(str(user_id))
    if subscribers is None:
        return
    subscribers.discard(queue)
    if not subscribers:
        _subscribers.pop(str(user_id), None)
