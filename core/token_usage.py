"""模型 Token 用量统计（LLM 推理调用级明细，存 users.db）。

- 每次模型调用完成由 LLM/model.py 的实例级 usage 钩子写入一行明细
  （provider 为注册表配置显示名；user_id 为 NULL 表示 CLI/无用户上下文）；
- 用户端 /settings「用量统计」与超管端「Token 用量」页消费聚合查询；
- 只统计 LLM 推理 token；RAG embedding 走独立 SDK 路径不计入；
- 明细全量保留（SQLite 量级无压力），查询按 days 过滤，不做自动清理。
"""
from __future__ import annotations

import sqlite3
from typing import Any

from core.auth import get_db


def _init_table() -> None:
    conn: sqlite3.Connection = get_db()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS model_token_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_id TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                model_name TEXT NOT NULL DEFAULT '',
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_token_usage_user_time "
            "ON model_token_usage(user_id, created_at)",
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_token_usage_time "
            "ON model_token_usage(created_at)",
        )
        conn.commit()
    finally:
        conn.close()


_init_table()


def record_token_usage(
    *,
    user_id: int | None,
    session_id: str,
    role: str,
    provider: str,
    model_name: str,
    input_tokens: int,
    output_tokens: int,
) -> None:
    """写入一次模型调用的 token 明细（input/output 任一为正才记录）。"""
    input_tokens = max(0, int(input_tokens or 0))
    output_tokens = max(0, int(output_tokens or 0))
    if input_tokens <= 0 and output_tokens <= 0:
        return
    conn: sqlite3.Connection = get_db()
    try:
        conn.execute(
            "INSERT INTO model_token_usage "
            "(user_id, session_id, role, provider, model_name, input_tokens, output_tokens) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                int(user_id) if user_id is not None else None,
                str(session_id or "")[:64], str(role or "")[:32],
                str(provider or "")[:80], str(model_name or "")[:300],
                input_tokens, output_tokens,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _days_clause(days: int) -> tuple[str, tuple]:
    """days<=0 表示全量；否则限定最近 N 天（created_at 为 UTC）。"""
    if days and days > 0:
        return (
            " WHERE created_at >= datetime('now', ?) ",
            (f"-{int(days)} days",),
        )
    return "", ()


def _total_row(rows: list[sqlite3.Row]) -> dict[str, int]:
    return {
        "calls": len(rows),
        "input_tokens": sum(int(r["input_tokens"]) for r in rows),
        "output_tokens": sum(int(r["output_tokens"]) for r in rows),
    }


def _group_rows(
    conn: sqlite3.Connection, group_by: str, where: str, params: tuple,
    limit: int = 0,
) -> list[dict[str, Any]]:
    sql = (
        f"SELECT {group_by} AS key, COUNT(*) AS calls, "
        f"SUM(input_tokens) AS input_tokens, SUM(output_tokens) AS output_tokens "
        f"FROM model_token_usage{where} GROUP BY {group_by} "
        f"ORDER BY (SUM(input_tokens) + SUM(output_tokens)) DESC"
    )
    if limit and limit > 0:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql, params).fetchall()
    return [
        {
            "key": r["key"] if r["key"] not in (None, "") else "未知",
            "calls": int(r["calls"]),
            "input_tokens": int(r["input_tokens"] or 0),
            "output_tokens": int(r["output_tokens"] or 0),
        }
        for r in rows
    ]


def user_usage_summary(user_id: int, days: int = 30) -> dict[str, Any]:
    """单个用户的用量汇总：总计 + 按配置/模型/会话分解。"""
    where, base_params = _days_clause(days)
    conn: sqlite3.Connection = get_db()
    try:
        user_where = f" WHERE user_id = ?{where.replace(' WHERE', ' AND') if where else ''}"
        params = (int(user_id), *base_params)
        rows = conn.execute(
            f"SELECT input_tokens, output_tokens FROM model_token_usage{user_where}",
            params,
        ).fetchall()
        return {
            "user_id": int(user_id),
            "days": days,
            **_total_row(rows),
            "by_provider": _group_rows(conn, "provider", user_where, params),
            "by_model": _group_rows(conn, "model_name", user_where, params),
            "by_session": _group_rows(conn, "session_id", user_where, params, limit=10),
        }
    finally:
        conn.close()


def platform_usage_summary(days: int = 30) -> dict[str, Any]:
    """平台级用量汇总：总计 + 按用户（含 CLI 桶）/配置/模型分解。"""
    where, params = _days_clause(days)
    conn: sqlite3.Connection = get_db()
    try:
        rows = conn.execute(
            f"SELECT input_tokens, output_tokens FROM model_token_usage{where}",
            params,
        ).fetchall()
        where_t = where.replace("created_at", "t.created_at") if where else ""
        by_user_sql = (
            "SELECT COALESCE(u.username, '本地 CLI') AS key, "
            "COALESCE(t.user_id, 0) AS uid, COUNT(*) AS calls, "
            "SUM(t.input_tokens) AS input_tokens, SUM(t.output_tokens) AS output_tokens "
            f"FROM model_token_usage t LEFT JOIN users u ON u.id = t.user_id"
            f"{where_t} "
            "GROUP BY t.user_id "
            "ORDER BY (SUM(t.input_tokens) + SUM(t.output_tokens)) DESC"
        )
        by_user = [
            {
                "key": r["key"],
                "user_id": int(r["uid"]),
                "calls": int(r["calls"]),
                "input_tokens": int(r["input_tokens"] or 0),
                "output_tokens": int(r["output_tokens"] or 0),
            }
            for r in conn.execute(by_user_sql, params).fetchall()
        ]
        return {
            "days": days,
            **_total_row(rows),
            "by_user": by_user,
            "by_provider": _group_rows(conn, "provider", where, params),
            "by_model": _group_rows(conn, "model_name", where, params),
        }
    finally:
        conn.close()
