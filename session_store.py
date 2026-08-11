"""
session_store.py — SQLite 会话存储层

管理 sessions 和 session_messages 两张表的 CRUD 操作。
复用 auth.py 的 get_db() 获取数据库连接。
"""

import uuid
from datetime import datetime

from auth import get_db


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
        # CREATE TABLE IF NOT EXISTS 不会给旧表补列，显式执行幂等迁移。
        session_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()
        }
        migrations = {
            "target_info": "TEXT DEFAULT NULL",
            "pending_approval": "TEXT DEFAULT NULL",
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
        conn.commit()
    finally:
        conn.close()


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
_UPDATABLE_FIELDS = {'phase', 'status', 'success', 'flag', 'summary', 'title', 'target_info', 'pending_approval', 'updated_at'}


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


def delete_session(session_id: str) -> None:
    """删除会话及其所有关联消息。"""
    conn = get_db()
    try:
        conn.execute("DELETE FROM session_stream_snapshots WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM session_messages WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
    finally:
        conn.close()


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
