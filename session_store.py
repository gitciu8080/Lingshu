"""
session_store.py — SQLite 会话存储层

管理 sessions 和 session_messages 两张表的 CRUD 操作。
复用 auth.py 的 get_db() 获取数据库连接。
"""

import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime
from functools import wraps

from auth import get_db


_WRITE_LOCK = threading.RLock()
_LOCK_RETRIES = max(1, int(os.getenv("LINGSHU_SQLITE_LOCK_RETRIES", "5")))


def _retry_locked_write(function):
    """串行化进程内写事务，并对跨进程 SQLite 锁竞争进行退避重试。"""
    @wraps(function)
    def wrapped(*args, **kwargs):
        delay = 0.05
        for attempt in range(_LOCK_RETRIES):
            try:
                with _WRITE_LOCK:
                    return function(*args, **kwargs)
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                if "locked" not in message:
                    raise
                if attempt + 1 >= _LOCK_RETRIES:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 1.0)
        raise RuntimeError("SQLite 写入重试状态异常")

    return wrapped


@_retry_locked_write
def init_sessions_db():
    """初始化 sessions 和 session_messages 两张表（幂等操作）。"""
    conn = get_db()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT DEFAULT '新会话',
                target TEXT NOT NULL,
                goal TEXT DEFAULT '',
                provider TEXT DEFAULT 'deepseek',
                model TEXT DEFAULT 'Min',
                phase TEXT DEFAULT 'planning',
                status TEXT DEFAULT 'active',
                success BOOLEAN,
                flag TEXT,
                summary TEXT DEFAULT '',
                target_info TEXT DEFAULT NULL,
                pending_approval TEXT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                event_type TEXT DEFAULT '',
                agent_name TEXT DEFAULT '',
                source_id TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id),
                UNIQUE(session_id, seq)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_stream_snapshots (
                session_id TEXT NOT NULL,
                reply_id TEXT NOT NULL,
                block_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                stream_type TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (session_id, block_id),
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        # blob 引用表：session_id/sha256/original_name/size；删除最后一个
        # 引用后才删除共享 blob（内容寻址存储，多会话可共享同一文件）。
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blob_refs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                original_name TEXT DEFAULT '',
                size INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id),
                UNIQUE(session_id, sha256)
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blob_refs_sha ON blob_refs(sha256)"
        )
        # CREATE TABLE IF NOT EXISTS 不会给旧表补列，显式执行幂等迁移。
        session_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()
        }
        migrations = {
            "target_info": "TEXT DEFAULT NULL",
            "pending_approval": "TEXT DEFAULT NULL",
            # ── v0.3.0 Workspace v2 ──
            "workspace_id": "TEXT DEFAULT ''",
            "workspace_version": "INTEGER DEFAULT 0",
            "resume_status": "TEXT DEFAULT 'fresh'",
            "checkpoint_seq": "INTEGER DEFAULT 0",
        }
        for column, definition in migrations.items():
            if column not in session_columns:
                conn.execute(
                    f"ALTER TABLE sessions ADD COLUMN {column} {definition}"
                )
        message_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(session_messages)").fetchall()
        }
        if "source_id" not in message_columns:
            conn.execute(
                "ALTER TABLE session_messages ADD COLUMN source_id TEXT DEFAULT ''"
            )
        # 会话列表按用户/状态和创建时间分页，显式复合索引避免用户与
        # 历史会话增长后重复扫描、排序整张 sessions 表。
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_created "
            "ON sessions(user_id, created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_status_created "
            "ON sessions(user_id, status, created_at DESC)"
        )
        conn.commit()
    finally:
        conn.close()


@_retry_locked_write
def create_session(
    user_id: int,
    target: str,
    goal: str = '',
    provider: str = 'deepseek',
    model: str = 'Min',
    title: str = '',
    session_id: str = '',
) -> str:
    """创建一条新会话记录，返回 session_id。
    
    如果外部传入 session_id 则使用外部值，否则自动生成。
    """
    if not session_id:
        session_id = uuid.uuid4().hex[:16]
    if not title:
        title = target
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO sessions (id, user_id, title, target, goal, provider, model)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (session_id, user_id, title, target, goal, provider, model),
        )
        conn.commit()
    finally:
        conn.close()
    return session_id


# update_session 允许更新的字段白名单
_UPDATABLE_FIELDS = {
    'phase', 'status', 'success', 'flag', 'summary', 'title', 'target_info',
    'pending_approval', 'updated_at',
    # v0.3.0 Workspace v2
    'workspace_id', 'workspace_version', 'resume_status', 'checkpoint_seq',
}


@_retry_locked_write
def update_session(session_id: str, **fields) -> None:
    """动态更新会话的指定字段（仅允许白名单中的字段）。"""
    # 过滤非法字段
    updates = {k: v for k, v in fields.items() if k in _UPDATABLE_FIELDS}
    if not updates:
        return
    # 自动设置 updated_at
    updates['updated_at'] = datetime.now().isoformat()

    set_clause = ', '.join(f'{k} = ?' for k in updates)
    values = list(updates.values()) + [session_id]

    conn = get_db()
    try:
        conn.execute(f"UPDATE sessions SET {set_clause} WHERE id = ?", values)
        conn.commit()
    finally:
        conn.close()


def list_sessions(
    user_id: int,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """列出用户的会话，按创建时间倒序，可选按状态过滤。"""
    conn = get_db()
    try:
        if status is not None:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE user_id = ? AND status = ? "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (user_id, status, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE user_id = ? "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (user_id, limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_session(session_id: str) -> dict | None:
    """根据 id 获取单条会话，不存在返回 None。"""
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


@_retry_locked_write
def delete_session(session_id: str) -> list[str]:
    """删除会话及其所有关联消息、快照与 blob 引用。

    返回本次删除后成为孤儿的 blob sha256 列表（调用方负责物理删除共享
    blob）；没有孤儿时返回空列表。删除失败时保留 tombstone（调用方可
    依据返回值重试）。
    """
    conn = get_db()
    orphaned: list[str] = []
    try:
        # 1) 收集本会话引用的 blob
        refs = conn.execute(
            "SELECT sha256 FROM blob_refs WHERE session_id = ?",
            (session_id,),
        ).fetchall()
        # 2) 删除引用
        conn.execute("DELETE FROM blob_refs WHERE session_id = ?", (session_id,))
        # 3) 删除消息/快照/会话
        conn.execute("DELETE FROM session_stream_snapshots WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM session_messages WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
        # 4) 判定孤儿：其他会话是否还引用同一 blob
        for (sha256,) in refs:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM blob_refs WHERE sha256 = ?",
                (sha256,),
            ).fetchone()
            if (remaining[0] or 0) == 0:
                orphaned.append(sha256)
    finally:
        conn.close()
    return orphaned


@_retry_locked_write
def add_blob_ref(session_id: str, sha256: str, original_name: str = '', size: int = 0) -> None:
    """为会话登记一条 blob 引用（幂等：同会话同 sha256 只记一次）。"""
    conn = get_db()
    try:
        conn.execute(
            """INSERT OR IGNORE INTO blob_refs
               (session_id, sha256, original_name, size)
               VALUES (?, ?, ?, ?)""",
            (session_id, sha256, original_name, size),
        )
        conn.commit()
    finally:
        conn.close()


def list_blob_refs(session_id: str) -> list[dict]:
    """列出会话登记的 blob 引用。"""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT sha256, original_name, size, created_at FROM blob_refs "
            "WHERE session_id = ? ORDER BY id ASC",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@_retry_locked_write
def add_message(
    session_id: str,
    role: str,
    content: str,
    event_type: str = '',
    agent_name: str = '',
    source_id: str = '',
) -> int:
    """追加一条消息到会话，自动计算 seq，返回 seq 值。

    使用 BEGIN IMMEDIATE 保证 SELECT MAX(seq) + INSERT 的原子性，
    防止并发写入导致 seq 冲突。
    """
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT COALESCE(MAX(seq), 0) FROM session_messages WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        next_seq = (row[0] or 0) + 1
        conn.execute(
            """INSERT INTO session_messages
               (session_id, seq, role, content, event_type, agent_name, source_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (session_id, next_seq, role, content, event_type, agent_name, source_id),
        )
        conn.commit()
        return next_seq
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@_retry_locked_write
def apply_persistence_batch(operations: list[dict]) -> list[int | None]:
    """在单个事务中顺序应用消息和流快照操作。

    返回值与 operations 对齐；只有 message 操作返回分配到的 seq。
    BEGIN IMMEDIATE 保证本批次与用户消息等其他写入者之间不会产生序号
    冲突，同时把多次 fsync 合并为一次事务提交。
    """
    if not operations:
        return []
    conn = get_db()
    results: list[int | None] = []
    next_sequences: dict[str, int] = {}
    try:
        conn.execute("BEGIN IMMEDIATE")
        for operation in operations:
            operation_type = operation.get("type")
            session_id = str(operation.get("session_id") or "")
            if operation_type == "message":
                if session_id not in next_sequences:
                    row = conn.execute(
                        "SELECT COALESCE(MAX(seq), 0) FROM session_messages "
                        "WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()
                    next_sequences[session_id] = int(row[0] or 0)
                next_sequences[session_id] += 1
                seq = next_sequences[session_id]
                conn.execute(
                    """INSERT INTO session_messages
                       (session_id, seq, role, content, event_type, agent_name, source_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session_id,
                        seq,
                        operation.get("role", "agent"),
                        operation.get("content", ""),
                        operation.get("event_type", ""),
                        operation.get("agent_name", ""),
                        operation.get("source_id", ""),
                    ),
                )
                results.append(seq)
            elif operation_type == "snapshot_upsert":
                conn.execute(
                    """INSERT INTO session_stream_snapshots
                       (session_id, reply_id, block_id, agent_name, stream_type, content, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(session_id, block_id) DO UPDATE SET
                         reply_id = excluded.reply_id,
                         agent_name = excluded.agent_name,
                         stream_type = excluded.stream_type,
                         content = excluded.content,
                         updated_at = excluded.updated_at""",
                    (
                        session_id,
                        operation.get("reply_id", ""),
                        operation.get("block_id", ""),
                        operation.get("agent_name", ""),
                        operation.get("stream_type", "text"),
                        operation.get("content", ""),
                        datetime.now().isoformat(),
                    ),
                )
                results.append(None)
            elif operation_type == "snapshot_delete":
                conn.execute(
                    "DELETE FROM session_stream_snapshots "
                    "WHERE session_id = ? AND block_id = ?",
                    (session_id, operation.get("block_id", "")),
                )
                results.append(None)
            else:
                results.append(None)
        conn.commit()
        return results
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_messages(
    session_id: str,
    after_seq: int = 0,
    limit: int = 200,
) -> list[dict]:
    """获取会话消息列表，按 seq 正序，支持分页。"""
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT * FROM session_messages
               WHERE session_id = ? AND seq > ?
               ORDER BY seq ASC
               LIMIT ?""",
            (session_id, after_seq, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_all_messages(session_id: str) -> list[dict]:
    """导出会话的全部已落库消息，不分页、不截断，保持原始顺序。"""
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT * FROM session_messages
               WHERE session_id = ?
               ORDER BY seq ASC""",
            (session_id,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


@_retry_locked_write
def upsert_stream_snapshot(
    session_id: str,
    reply_id: str,
    block_id: str,
    agent_name: str,
    stream_type: str,
    content: str,
) -> None:
    """Persist the latest content of an unfinished text/thinking block."""
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO session_stream_snapshots
               (session_id, reply_id, block_id, agent_name, stream_type, content, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(session_id, block_id) DO UPDATE SET
                 reply_id = excluded.reply_id,
                 agent_name = excluded.agent_name,
                 stream_type = excluded.stream_type,
                 content = excluded.content,
                 updated_at = excluded.updated_at""",
            (
                session_id,
                reply_id,
                block_id,
                agent_name,
                stream_type,
                content,
                datetime.now().isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


@_retry_locked_write
def delete_stream_snapshot(session_id: str, block_id: str) -> None:
    conn = get_db()
    try:
        conn.execute(
            "DELETE FROM session_stream_snapshots WHERE session_id = ? AND block_id = ?",
            (session_id, block_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_stream_snapshots(session_id: str) -> list[dict]:
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT * FROM session_stream_snapshots
               WHERE session_id = ? ORDER BY updated_at ASC""",
            (session_id,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_history_snapshot(
    session_id: str,
    after_seq: int = 0,
    limit: int = 200,
) -> tuple[list[dict], list[dict]]:
    """Read completed messages and unfinished blocks from one DB snapshot."""
    conn = get_db()
    try:
        conn.execute("BEGIN")
        messages = conn.execute(
            """SELECT * FROM session_messages
               WHERE session_id = ? AND seq > ?
               ORDER BY seq ASC LIMIT ?""",
            (session_id, after_seq, limit),
        ).fetchall()
        snapshots = conn.execute(
            """SELECT * FROM session_stream_snapshots
               WHERE session_id = ? ORDER BY updated_at ASC""",
            (session_id,),
        ).fetchall()
        conn.commit()
        return [dict(row) for row in messages], [dict(row) for row in snapshots]
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_history_page(
    session_id: str,
    *,
    before_seq: int | None = None,
    after_seq: int = 0,
    limit: int = 200,
    include_snapshots: bool = True,
) -> tuple[list[dict], list[dict], bool]:
    """读取一页历史消息及未完成流快照。

    默认返回最新一页；``before_seq`` 用于向更早历史翻页；保留
    ``after_seq`` 供 SSE/旧客户端正向补偿。额外读取一条判断 has_more。
    """
    page_size = max(1, limit)
    conn = get_db()
    try:
        conn.execute("BEGIN")
        if before_seq is not None:
            rows = conn.execute(
                """SELECT * FROM session_messages
                   WHERE session_id = ? AND seq < ?
                   ORDER BY seq DESC LIMIT ?""",
                (session_id, before_seq, page_size + 1),
            ).fetchall()
            has_more = len(rows) > page_size
            messages = list(reversed(rows[:page_size]))
        elif after_seq > 0:
            rows = conn.execute(
                """SELECT * FROM session_messages
                   WHERE session_id = ? AND seq > ?
                   ORDER BY seq ASC LIMIT ?""",
                (session_id, after_seq, page_size + 1),
            ).fetchall()
            has_more = len(rows) > page_size
            messages = rows[:page_size]
        else:
            rows = conn.execute(
                """SELECT * FROM session_messages
                   WHERE session_id = ?
                   ORDER BY seq DESC LIMIT ?""",
                (session_id, page_size + 1),
            ).fetchall()
            has_more = len(rows) > page_size
            messages = list(reversed(rows[:page_size]))

        snapshots = []
        if include_snapshots:
            snapshots = conn.execute(
                """SELECT * FROM session_stream_snapshots
                   WHERE session_id = ? ORDER BY updated_at ASC""",
                (session_id,),
            ).fetchall()
        conn.commit()
        return (
            [dict(row) for row in messages],
            [dict(row) for row in snapshots],
            has_more,
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
