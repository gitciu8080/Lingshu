"""PostgreSQL 业务数据库连接。"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None


_ROOT = Path(__file__).resolve().parent.parent


def _load_database_url_from_dotenv() -> None:
    """保证 CLI 与独立模块也能读取项目根目录的数据库配置。"""
    if os.getenv("LINGSHU_DATABASE_URL", "").strip():
        return
    dotenv = _ROOT / ".env"
    if not dotenv.is_file():
        return
    for raw_line in dotenv.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() == "LINGSHU_DATABASE_URL":
            os.environ.setdefault("LINGSHU_DATABASE_URL", value.strip().strip("\"'"))
            return


def database_url() -> str:
    """返回必填的 PostgreSQL 业务库 URL。"""
    _load_database_url_from_dotenv()
    url = os.getenv("LINGSHU_DATABASE_URL", "").strip()
    if not url.startswith(("postgresql://", "postgres://")):
        raise RuntimeError("必须配置 LINGSHU_DATABASE_URL 为 PostgreSQL URL")
    return url


def _postgres_url(url: str) -> str:
    return "postgresql://" + url.split("://", 1)[1] if url.startswith("postgres://") else url


class _PostgresConnection:
    """将既有 qmark SQL 调用适配为 psycopg 参数风格。"""

    def __init__(self, connection) -> None:
        self._connection = connection

    def execute(self, query: str, params=None):
        return self._connection.execute(query.replace("?", "%s"), params)

    def cursor(self):
        """兼容统计脚本的 DB-API 游标用法。"""
        return self

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()


def get_db():
    """获取同步 PostgreSQL 连接，查询行以映射形式返回。"""
    if psycopg is None:
        raise RuntimeError("未安装 psycopg；请执行 pip install -r requirements.txt")
    return _PostgresConnection(
        psycopg.connect(_postgres_url(database_url()), row_factory=dict_row),
    )


def integrity_errors():
    """返回 PostgreSQL 完整性异常类型，供认证模块处理唯一键冲突。"""
    if psycopg is None:
        return RuntimeError
    return psycopg.IntegrityError


def table_columns(conn, table: str) -> set[str]:
    rows = conn.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = ?",
        (table,),
    ).fetchall()
    return {str(row["column_name"]) for row in rows}


def agentscope_database_url() -> str:
    """返回 AgentScope 专用 PostgreSQL 数据库 URL。"""
    parsed = urlsplit(_postgres_url(database_url()))
    database = parsed.path.rsplit("/", 1)[-1]
    if not database:
        raise RuntimeError("LINGSHU_DATABASE_URL 必须包含数据库名")
    return urlunsplit((
        "postgresql+asyncpg", parsed.netloc, f"/{database}_agentscope", parsed.query, parsed.fragment,
    ))
