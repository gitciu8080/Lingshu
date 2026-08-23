"""Single-writer SQLite projection service for mission/session events."""

from __future__ import annotations

import asyncio
import logging
import os
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from pathlib import Path

import session_store

logger = logging.getLogger(__name__)


@dataclass
class _WriteGroup:
    operations: list[dict[str, Any]]
    receipt: asyncio.Future[list[int | None]] | None = None
    admitted_at: float = field(default_factory=time.monotonic)


class PersistenceWriter:
    """Serialize SQLite projections without blocking the asyncio event loop."""

    def __init__(self) -> None:
        self.capacity = max(1, int(os.getenv("LINGSHU_PERSISTENCE_QUEUE_SIZE", "10000")))
        self.retry_initial = max(
            0.01, float(os.getenv("LINGSHU_SQLITE_RETRY_INITIAL_MS", "50")) / 1000.0,
        )
        self.retry_max = max(
            self.retry_initial,
            float(os.getenv("LINGSHU_SQLITE_RETRY_MAX_MS", "5000")) / 1000.0,
        )
        self._queue: asyncio.Queue[_WriteGroup] | None = None
        self._worker: asyncio.Task[None] | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._admission_tasks: set[asyncio.Task[Any]] = set()
        self._inflight_since: float | None = None
        self._inflight_operations = 0
        self.started_at: str | None = None
        self.last_success_at: str | None = None
        self.last_error_at: str | None = None
        self.last_error: str = ""
        self.lock_retries = 0
        self.total_failures = 0
        self.consecutive_failures = 0
        self.committed_operations = 0
        self.degraded = False

    @property
    def running(self) -> bool:
        return self._worker is not None and not self._worker.done()

    async def start(self) -> None:
        if self.running:
            return
        self._queue = asyncio.Queue(maxsize=self.capacity)
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="lingshu-sqlite-writer",
        )
        self.started_at = _utc_now()
        self._worker = asyncio.create_task(self._run(), name="lingshu-sqlite-persistence")

    async def submit(
        self,
        operations: list[dict[str, Any]],
        *,
        wait: bool = False,
    ) -> list[int | None] | None:
        if not operations:
            return [] if wait else None
        if not self.running or self._queue is None:
            raise RuntimeError("SQLite 持久化服务尚未启动")
        loop = asyncio.get_running_loop()
        receipt = loop.create_future() if wait else None
        # await put 是唯一的满载处理路径：产生背压，不同步回退 SQLite。
        await self._queue.put(_WriteGroup(operations, receipt))
        if receipt is not None:
            return await receipt
        return None

    def submit_from_callback(self, operations: list[dict[str, Any]]) -> None:
        """Bridge a synchronous Agent callback into the bounded async queue."""
        if not operations:
            return
        if not self.running:
            raise RuntimeError("SQLite 持久化服务尚未启动")
        if self._queue is not None and self._queue.full():
            if not self.degraded:
                logger.error("SQLite 持久化队列已满，实时事件开始等待背压")
            self.degraded = True
        task = asyncio.get_running_loop().create_task(self.submit(operations))
        self._admission_tasks.add(task)
        task.add_done_callback(self._admission_done)

    def _admission_done(self, task: asyncio.Task[Any]) -> None:
        self._admission_tasks.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            logger.error(
                "持久化操作入队失败: %s",
                error,
                exc_info=(type(error), error, error.__traceback__),
            )

    async def flush(self) -> None:
        # callback 创建的 put task 可能尚未获得队列槽位，必须先等待它们。
        while self._admission_tasks:
            await asyncio.gather(*tuple(self._admission_tasks), return_exceptions=True)
        if self._queue is not None:
            await self._queue.join()

    async def stop(self) -> None:
        await self.flush()
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.cancel()
            try:
                await worker
            except asyncio.CancelledError:
                pass
        executor = self._executor
        self._executor = None
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=False)
        self._queue = None

    async def _run(self) -> None:
        assert self._queue is not None
        while True:
            first = await self._queue.get()
            groups = [first]
            operation_count = len(first.operations)
            deadline = asyncio.get_running_loop().time() + 0.02
            while operation_count < 128:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    group = await asyncio.wait_for(self._queue.get(), remaining)
                except asyncio.TimeoutError:
                    break
                groups.append(group)
                operation_count += len(group.operations)

            operations = [op for group in groups for op in group.operations]
            self._inflight_since = min(group.admitted_at for group in groups)
            self._inflight_operations = len(operations)
            delay = self.retry_initial
            while True:
                try:
                    loop = asyncio.get_running_loop()
                    assert self._executor is not None
                    results = await loop.run_in_executor(
                        self._executor,
                        session_store.apply_persistence_batch,
                        operations,
                    )
                    self.committed_operations += len(operations)
                    self.consecutive_failures = 0
                    self.degraded = False
                    self.last_error = ""
                    self.last_success_at = _utc_now()
                    offset = 0
                    for group in groups:
                        count = len(group.operations)
                        if group.receipt is not None and not group.receipt.done():
                            group.receipt.set_result(results[offset:offset + count])
                        offset += count
                    for _ in groups:
                        self._queue.task_done()
                    self._inflight_since = None
                    self._inflight_operations = 0
                    break
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # retain the batch until SQLite recovers
                    self.total_failures += 1
                    self.consecutive_failures += 1
                    self.degraded = True
                    self.last_error_at = _utc_now()
                    self.last_error = f"{type(exc).__name__}: {exc}"[:500]
                    if isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc).lower():
                        self.lock_retries += 1
                    logger.error(
                        "SQLite 投影失败，%.2fs 后重试（批次不会丢弃）: %s",
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, self.retry_max)

    def health(self) -> dict[str, Any]:
        queue = self._queue
        oldest_age = 0.0
        if self._inflight_since is not None:
            oldest_age = max(0.0, time.monotonic() - self._inflight_since)
        elif queue is not None and queue.qsize():
            try:
                oldest_age = max(0.0, time.monotonic() - queue._queue[0].admitted_at)
            except (AttributeError, IndexError):
                pass
        return {
            "running": self.running,
            "degraded": self.degraded,
            "queue_depth": queue.qsize() if queue is not None else 0,
            "queue_capacity": self.capacity,
            "pending_admissions": len(self._admission_tasks),
            "inflight_operations": self._inflight_operations,
            "oldest_operation_seconds": round(oldest_age, 3),
            "lock_retries": self.lock_retries,
            "total_failures": self.total_failures,
            "consecutive_failures": self.consecutive_failures,
            "committed_operations": self.committed_operations,
            "started_at": self.started_at,
            "last_success_at": self.last_success_at,
            "last_error_at": self.last_error_at,
            "last_error": self.last_error,
        }

    async def reconcile_mission_states(self, sessions_dir: str | Path) -> int:
        """Project authoritative per-session Mission JSON into the SQLite index."""
        directory = Path(sessions_dir)
        if not directory.is_dir():
            return 0
        repairs: list[dict[str, Any]] = []
        for path in directory.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                logger.exception("跳过损坏的 Mission JSON: %s", path)
                continue
            if not isinstance(data, dict):
                continue
            session_id = path.stem
            session = await asyncio.to_thread(session_store.get_session, session_id)
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
            }
            changed = {key: value for key, value in fields.items() if session.get(key) != value}
            if changed:
                repairs.append({
                    "type": "session_update", "session_id": session_id,
                    "fields": changed,
                })
        if repairs:
            await self.submit(repairs, wait=True)
        return len(repairs)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


_writer = PersistenceWriter()


def get_persistence_writer() -> PersistenceWriter:
    return _writer
