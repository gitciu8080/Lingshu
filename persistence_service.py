"""Single-writer SQLite projection service for mission/session events."""

from __future__ import annotations

import asyncio
from collections import deque
import logging
import os
import json
import sqlite3
import time
import fcntl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from pathlib import Path

import session_store
from TaskState import infer_exploitation_approval_status

logger = logging.getLogger(__name__)


@dataclass
class _WriteGroup:
    operations: list[dict[str, Any]]
    receipt: asyncio.Future[list[int | None]] | None = None
    admitted_at: float = field(default_factory=time.monotonic)
    byte_size: int = 0
    outbox_path: Path | None = None


class PersistenceWriter:
    """Serialize SQLite projections without blocking the asyncio event loop."""

    def __init__(self) -> None:
        self.capacity = max(1, int(os.getenv("LINGSHU_PERSISTENCE_QUEUE_SIZE", "10000")))
        self.capacity_bytes = max(
            1024 * 1024,
            int(os.getenv("LINGSHU_PERSISTENCE_QUEUE_BYTES", str(64 * 1024 * 1024))),
        )
        self.callback_capacity = max(
            1, int(os.getenv("LINGSHU_PERSISTENCE_CALLBACK_QUEUE_SIZE", "2048")),
        )
        self.shutdown_timeout = max(
            1.0, float(os.getenv("LINGSHU_PERSISTENCE_SHUTDOWN_TIMEOUT_SECONDS", "20")),
        )
        configured_outbox = os.getenv("LINGSHU_PERSISTENCE_OUTBOX_DIR", "").strip()
        self.outbox_dir = Path(
            configured_outbox
            or Path(__file__).resolve().parent / ".TaskMemory" / "persistence-outbox"
        ).resolve()
        self.dead_letter_dir = self.outbox_dir / "dead-letter"
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
        self._callback_pending: deque[list[dict[str, Any]]] = deque()
        self._callback_drain: asyncio.Task[None] | None = None
        self._admission_condition: asyncio.Condition | None = None
        self._admitted_operations = 0
        self._admitted_bytes = 0
        self._inflight_since: float | None = None
        self._inflight_operations = 0
        self._process_lock_handle: Any = None
        self.started_at: str | None = None
        self.last_success_at: str | None = None
        self.last_error_at: str | None = None
        self.last_error: str = ""
        self.lock_retries = 0
        self.total_failures = 0
        self.consecutive_failures = 0
        self.committed_operations = 0
        self.dead_letter_operations = 0
        self.replayed_operations = 0
        self.callback_rejections = 0
        self.coalesced_snapshots = 0
        self.degraded = False

    @property
    def running(self) -> bool:
        return self._worker is not None and not self._worker.done()

    async def start(self) -> None:
        if self.running:
            return
        self._queue = asyncio.Queue(maxsize=self.capacity)
        self._admission_condition = asyncio.Condition()
        self.outbox_dir.mkdir(parents=True, exist_ok=True)
        self.dead_letter_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.outbox_dir.parent / "api-single-writer.lock"
        self._process_lock_handle = lock_path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(
                self._process_lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as exc:
            self._process_lock_handle.close()
            self._process_lock_handle = None
            raise RuntimeError(
                "检测到另一个 Lingshu API worker；SQLite 模式仅支持单 Uvicorn worker",
            ) from exc
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="lingshu-sqlite-writer",
        )
        self.started_at = _utc_now()
        self._worker = asyncio.create_task(self._run(), name="lingshu-sqlite-persistence")
        await self._replay_outbox()

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
        # 跨线程、outbox 与重启重放必须看到完全相同的 JSON 形状。
        operations = json.loads(json.dumps(operations, ensure_ascii=False, default=str))
        byte_size = _operation_bytes(operations)
        if len(operations) > self.capacity or byte_size > self.capacity_bytes:
            raise RuntimeError(
                f"单批持久化操作超过容量限制: operations={len(operations)}, bytes={byte_size}",
            )
        loop = asyncio.get_running_loop()
        receipt = loop.create_future() if wait else None
        # 流快照是可重建的展示状态，最终 text_end/thinking_end 才是语义记录；
        # 对每个 200ms 快照 fsync 会制造比 SQLite 本身更大的写放大。
        durable = any(
            operation.get("type") not in {"snapshot_upsert", "snapshot_delete"}
            for operation in operations
        )
        outbox_path = (
            await asyncio.to_thread(self._write_outbox, operations)
            if durable else None
        )
        group = _WriteGroup(
            operations, receipt, byte_size=byte_size, outbox_path=outbox_path,
        )
        await self._admit(group)
        if receipt is not None:
            return await receipt
        return None

    def submit_from_callback(self, operations: list[dict[str, Any]]) -> None:
        """Bridge a synchronous Agent callback into the bounded async queue."""
        if not operations:
            return
        if not self.running:
            raise RuntimeError("SQLite 持久化服务尚未启动")
        if len(self._callback_pending) >= self.callback_capacity:
            if all(
                operation.get("type") in {"snapshot_upsert", "snapshot_delete"}
                for operation in operations
            ):
                self.coalesced_snapshots += len(operations)
                return
            self.callback_rejections += len(operations)
            self.degraded = True
            raise RuntimeError("SQLite 持久化回调入口已满，已对事件生产者施加背压")
        self._callback_pending.append(operations)
        if self._callback_drain is None or self._callback_drain.done():
            self._callback_drain = asyncio.get_running_loop().create_task(
                self._drain_callbacks(), name="lingshu-persistence-admission",
            )

    async def _drain_callbacks(self) -> None:
        while self._callback_pending:
            operations = self._callback_pending[0]
            try:
                await self.submit(operations)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("持久化回调入队失败")
                self._callback_pending.popleft()
                continue
            self._callback_pending.popleft()

    async def flush(self) -> None:
        drain = self._callback_drain
        if drain is not None and not drain.done():
            await drain
        if self._queue is not None:
            await self._queue.join()

    async def stop(self) -> None:
        try:
            await asyncio.wait_for(self.flush(), timeout=self.shutdown_timeout)
        except asyncio.TimeoutError:
            self.degraded = True
            logger.error(
                "SQLite 持久化关闭等待超过 %.1fs，未提交操作保留在 outbox",
                self.shutdown_timeout,
            )
        drain = self._callback_drain
        self._callback_drain = None
        if drain is not None and not drain.done():
            drain.cancel()
            try:
                await drain
            except asyncio.CancelledError:
                pass
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
            executor.shutdown(wait=False, cancel_futures=True)
        self._queue = None
        self._admission_condition = None
        if self._process_lock_handle is not None:
            fcntl.flock(self._process_lock_handle.fileno(), fcntl.LOCK_UN)
            self._process_lock_handle.close()
            self._process_lock_handle = None

    async def _admit(self, group: _WriteGroup) -> None:
        assert self._queue is not None and self._admission_condition is not None
        async with self._admission_condition:
            await self._admission_condition.wait_for(lambda: (
                self._admitted_operations + len(group.operations) <= self.capacity
                and self._admitted_bytes + group.byte_size <= self.capacity_bytes
            ))
            self._admitted_operations += len(group.operations)
            self._admitted_bytes += group.byte_size
        try:
            await self._queue.put(group)
        except BaseException:
            await self._release(group)
            raise

    async def _release(self, group: _WriteGroup) -> None:
        condition = self._admission_condition
        if condition is None:
            return
        async with condition:
            self._admitted_operations = max(
                0, self._admitted_operations - len(group.operations),
            )
            self._admitted_bytes = max(0, self._admitted_bytes - group.byte_size)
            condition.notify_all()

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
                    for group in groups:
                        if group.outbox_path is not None:
                            await asyncio.to_thread(_unlink_quietly, group.outbox_path)
                        self._queue.task_done()
                        await self._release(group)
                    self._inflight_since = None
                    self._inflight_operations = 0
                    break
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # retain transient batches until SQLite recovers
                    self.total_failures += 1
                    self.consecutive_failures += 1
                    self.degraded = True
                    self.last_error_at = _utc_now()
                    self.last_error = f"{type(exc).__name__}: {exc}"[:500]
                    if isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc).lower():
                        self.lock_retries += 1
                    if not _is_transient_sqlite_error(exc):
                        logger.exception("SQLite 投影发生永久错误，批次转入 dead-letter")
                        await self._isolate_failed_groups(groups)
                        self._inflight_since = None
                        self._inflight_operations = 0
                        break
                    logger.error(
                        "SQLite 投影失败，%.2fs 后重试（批次不会丢弃）: %s",
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, self.retry_max)

    async def _isolate_failed_groups(self, groups: list[_WriteGroup]) -> None:
        """Retry groups separately so one malformed event cannot poison neighbors."""
        loop = asyncio.get_running_loop()
        assert self._executor is not None and self._queue is not None
        for group in groups:
            try:
                results = await loop.run_in_executor(
                    self._executor,
                    session_store.apply_persistence_batch,
                    group.operations,
                )
            except Exception as group_error:
                self.dead_letter_operations += len(group.operations)
                if group.outbox_path is not None:
                    await asyncio.to_thread(self._move_dead_letter, group.outbox_path)
                if group.receipt is not None and not group.receipt.done():
                    group.receipt.set_exception(group_error)
                logger.error(
                    "持久化操作组进入 dead-letter: %s", group_error,
                    exc_info=(type(group_error), group_error, group_error.__traceback__),
                )
            else:
                self.committed_operations += len(group.operations)
                self.last_success_at = _utc_now()
                if group.receipt is not None and not group.receipt.done():
                    group.receipt.set_result(results)
                if group.outbox_path is not None:
                    await asyncio.to_thread(_unlink_quietly, group.outbox_path)
            finally:
                self._queue.task_done()
                await self._release(group)

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
            "process_id": os.getpid(),
            "degraded": self.degraded,
            "queue_depth": queue.qsize() if queue is not None else 0,
            "queue_capacity": self.capacity,
            "queue_operations": self._admitted_operations,
            "queue_bytes": self._admitted_bytes,
            "queue_capacity_bytes": self.capacity_bytes,
            "pending_admissions": len(self._callback_pending),
            "inflight_operations": self._inflight_operations,
            "oldest_operation_seconds": round(oldest_age, 3),
            "lock_retries": self.lock_retries,
            "total_failures": self.total_failures,
            "consecutive_failures": self.consecutive_failures,
            "committed_operations": self.committed_operations,
            "dead_letter_operations": self.dead_letter_operations,
            "replayed_operations": self.replayed_operations,
            "callback_rejections": self.callback_rejections,
            "coalesced_snapshots": self.coalesced_snapshots,
            "started_at": self.started_at,
            "last_success_at": self.last_success_at,
            "last_error_at": self.last_error_at,
            "last_error": self.last_error,
        }

    def _write_outbox(self, operations: list[dict[str, Any]]) -> Path:
        self.outbox_dir.mkdir(parents=True, exist_ok=True)
        name = f"{time.time_ns()}-{os.getpid()}-{id(operations):x}.json"
        target = self.outbox_dir / name
        temporary = target.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(
                {"operations": operations}, handle, ensure_ascii=False, default=str,
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        return target

    def _move_dead_letter(self, path: Path) -> None:
        self.dead_letter_dir.mkdir(parents=True, exist_ok=True)
        if path.exists():
            os.replace(path, self.dead_letter_dir / path.name)

    async def _replay_outbox(self) -> None:
        for path in sorted(self.outbox_dir.glob("*.json")):
            try:
                payload = await asyncio.to_thread(
                    lambda candidate=path: json.loads(candidate.read_text(encoding="utf-8")),
                )
                operations = payload.get("operations") if isinstance(payload, dict) else None
                if not isinstance(operations, list) or not operations:
                    raise ValueError("outbox 缺少 operations")
                group = _WriteGroup(
                    operations=operations,
                    byte_size=_operation_bytes(operations),
                    outbox_path=path,
                )
                if (
                    len(operations) > self.capacity
                    or group.byte_size > self.capacity_bytes
                ):
                    raise ValueError("outbox 批次超过当前队列容量")
                await self._admit(group)
                self.replayed_operations += len(operations)
            except Exception:
                logger.exception("持久化 outbox 重放失败，已转入 dead-letter: %s", path)
                await asyncio.to_thread(self._move_dead_letter, path)

    async def reconcile_mission_states(self, sessions_dir: str | Path) -> int:
        """Project authoritative per-session Mission JSON into the SQLite index."""
        directory = Path(sessions_dir)
        if not directory.is_dir():
            return 0
        mission_states = await asyncio.to_thread(_read_mission_states, directory)
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
            await self.submit(repairs, wait=True)
        return len(repairs)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _operation_bytes(operations: list[dict[str, Any]]) -> int:
    return len(json.dumps(
        operations, ensure_ascii=False, separators=(",", ":"), default=str,
    ).encode("utf-8"))


def _is_transient_sqlite_error(exc: Exception) -> bool:
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    message = str(exc).lower()
    return any(token in message for token in (
        "locked", "busy", "temporarily unavailable", "disk i/o error",
    ))


def _unlink_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        logger.exception("清理已提交 outbox 失败: %s", path)


def _read_mission_states(directory: Path) -> dict[str, dict[str, Any]]:
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


_writer = PersistenceWriter()


def get_persistence_writer() -> PersistenceWriter:
    return _writer
