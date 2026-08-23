"""Docker 版风格的轻量批量持久化：模块级队列 + 单 worker 直写 SQLite。

与 Lingshu-Docker 分支 (7b91071) 完全一致的策略：
- 无读写分离、无单写者文件锁、无 outbox/dead-letter、无 degraded 拥塞闸门；
- 事件操作进入模块级 asyncio.Queue，worker 以 20ms/128 操作微批合并，
  经 asyncio.to_thread 直写 session_store.apply_persistence_batch；
- 队列满载时调用方回退：同步上下文走默认线程池直写（不丢数据），
  异步上下文可直接 await submit(wait=True) 同步落库；
- 崩溃时未提交批次随进程丢失，权威状态以 MissionState JSON checkpoint 为准。
"""

from __future__ import annotations

import asyncio
import logging
import os
import json
import sqlite3
from typing import Any
from pathlib import Path

import session_store
from TaskState import infer_exploitation_approval_status

logger = logging.getLogger(__name__)

_QUEUE_SIZE = max(1, int(os.getenv("LINGSHU_PERSISTENCE_QUEUE_SIZE", "10000")))

_queue: asyncio.Queue[list[dict]] | None = None
_task: asyncio.Task | None = None


async def start_persistence() -> None:
    global _queue, _task
    if _queue is not None and _task is not None and not _task.done():
        return
    _queue = asyncio.Queue(maxsize=_QUEUE_SIZE)
    _task = asyncio.create_task(_persistence_worker(), name="lingshu-sqlite-persistence")


async def stop_persistence() -> None:
    global _queue, _task
    await flush_persistence()
    task, _task = _task, None
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    _queue = None


async def flush_persistence() -> None:
    """等待此前排队的持久化操作完成，用于报告、删除和关闭边界。"""
    if _queue is not None:
        await _queue.join()


def queue_persistence_operations(operations: list[dict]) -> bool:
    """将操作加入批量队列；未启动或队列满时返回 False，由调用方回退。"""
    if not operations or _queue is None:
        return False
    try:
        _queue.put_nowait(operations)
        return True
    except asyncio.QueueFull:
        logger.warning("持久化队列已满，回退线程池直写")
        return False


def fallback_direct_write(operations: list[dict]) -> None:
    """队列不可用时的兜底：默认线程池一次性直写，不阻塞事件循环。"""
    if not operations:
        return
    try:
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, session_store.apply_persistence_batch, operations)
    except RuntimeError:
        # 无事件循环（纯同步脚本场景）：退化为阻塞直写。
        session_store.apply_persistence_batch(operations)


async def submit(
    operations: list[dict[str, Any]],
    *,
    wait: bool = False,
) -> list[int | None] | None:
    """提交一批操作。

    wait=True 时绕过队列直接在线程池落库并返回 seq 结果（会话创建/
    审批状态等需要确定性完成的场景）；否则入队异步批量提交。
    """
    if not operations:
        return [] if wait else None
    if wait:
        return await asyncio.to_thread(session_store.apply_persistence_batch, operations)
    if queue_persistence_operations(list(operations)):
        return None
    fallback_direct_write(operations)
    return None


async def _persistence_worker() -> None:
    """聚合短时间内的会话事件，以单个 SQLite 事务批量提交。"""
    assert _queue is not None
    queue = _queue
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
        except sqlite3.Error as exc:
            # 外键冲突等永久性坏行（如会话已删但任务仍在产事件）：
            # 逐条隔离重放，只丢弃真正损坏的操作，健康数据照常落库。
            logger.warning("批量持久化失败（%s），逐条隔离重放", exc)
            await _isolate_operations(operations)
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


async def _isolate_operations(operations: list[dict]) -> None:
    for operation in operations:
        try:
            await asyncio.to_thread(session_store.apply_persistence_batch, [operation])
        except sqlite3.Error as op_error:
            logger.error("持久化操作被隔离丢弃: %s", op_error)
        except Exception:
            logger.exception("持久化操作隔离重放失败")


def health() -> dict[str, Any]:
    running = _task is not None and not _task.done()
    depth = _queue.qsize() if _queue is not None else 0
    return {
        "running": running,
        "degraded": False,
        "queue_depth": depth,
        "queue_capacity": _QUEUE_SIZE,
        "pending_admissions": 0,
        "inflight_operations": 0,
        "oldest_operation_seconds": 0,
        "lock_retries": 0,
        "total_failures": 0,
        "consecutive_failures": 0,
        "committed_operations": 0,
        "dead_letter_operations": 0,
        "replayed_operations": 0,
        "callback_rejections": 0,
        "coalesced_snapshots": 0,
    }


async def reconcile_mission_states(sessions_dir: str | Path) -> int:
    """Project authoritative per-session Mission JSON into the SQLite index."""
    directory = Path(sessions_dir)
    if not directory.is_dir():
        return 0

    def _read_states() -> dict[str, dict[str, Any]]:
        states: dict[str, dict[str, Any]] = {}
        for path in directory.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                logger.exception("跳过损坏的 Mission JSON: %s", path)
                continue
            if isinstance(data, dict):
                states[path.stem] = data
        return states

    mission_states = await asyncio.to_thread(_read_states)
    sessions = await asyncio.to_thread(
        session_store.get_sessions_by_ids, list(mission_states),
    )
    repairs: list[dict[str, Any]] = []
    for session_id, data in mission_states.items():
        session = sessions.get(session_id)
        if session is None:
            continue
        phase = str(data.get("phase") or session.get("phase") or "planning")
        terminal = phase in {"completed", "failed", "cancelled"}
        fields = {
            "phase": phase,
            "status": phase if terminal else "active",
            "success": data.get("success"),
            "flag": data.get("flag"),
            "summary": data.get("summary") or "",
            "title": data.get("title") or session.get("title"),
            "checkpoint_seq": int(data.get("checkpoint_seq") or 0),
            "resume_status": data.get("resume_status") or session.get("resume_status") or "fresh",
            "approval_status": infer_exploitation_approval_status(
                data,
                pending=bool(session.get("pending_approval")),
                active=not terminal,
            ),
            "approval_decision": data.get("exploitation_approval_decision") or "",
            "approval_requested_at": data.get("exploitation_approval_requested_at") or "",
            "approval_resolved_at": data.get("exploitation_approval_resolved_at") or "",
        }
        changed = {key: value for key, value in fields.items() if session.get(key) != value}
        if changed:
            repairs.append({
                "type": "session_update", "session_id": session_id,
                "fields": changed,
            })
    if repairs:
        await submit(repairs, wait=True)
    return len(repairs)


class PersistenceWriter:
    """兼容适配器：为 integrations 等旧调用方保留对象式 API。"""

    @property
    def running(self) -> bool:
        return _task is not None and not _task.done()

    @property
    def capacity(self) -> int:
        return _QUEUE_SIZE

    @property
    def degraded(self) -> bool:
        return False

    async def start(self) -> None:
        await start_persistence()

    async def stop(self) -> None:
        await stop_persistence()

    async def flush(self) -> None:
        await flush_persistence()

    async def submit(
        self,
        operations: list[dict[str, Any]],
        *,
        wait: bool = False,
    ) -> list[int | None] | None:
        return await submit(operations, wait=wait)

    def submit_from_callback(self, operations: list[dict[str, Any]]) -> None:
        if not queue_persistence_operations(operations):
            fallback_direct_write(operations)

    def health(self) -> dict[str, Any]:
        return health()

    async def reconcile_mission_states(self, sessions_dir: str | Path) -> int:
        return await reconcile_mission_states(sessions_dir)


_writer = PersistenceWriter()


def get_persistence_writer() -> PersistenceWriter:
    return _writer
