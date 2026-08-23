""" JWT + SQLite 认证模块 """
from __future__ import annotations

import sqlite3
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext


def _load_dotenv_for_auth() -> None:
    """认证在配置模块之前导入，因此在此尽早读取项目 .env。"""
    dotenv_path = Path(__file__).with_name(".env")
    if not dotenv_path.is_file():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip("\"'")


_load_dotenv_for_auth()

JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "10080"))

DB_DIR = Path(__file__).parent / "data"
DB_DIR.mkdir(exist_ok=True)
DB_PATH = DB_DIR / "users.db"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


class UserCreate(BaseModel):
    username: str
    password: str
    email: str = ""
    invite_code: str = ""


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    expires_in: int


class PasswordReset(BaseModel):
    password: str


def validate_password_strength(password: str) -> str:
    """校验注册和密码重置使用的强密码策略。"""
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="密码至少需要 8 位")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="密码必须包含大写字母")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="密码必须包含小写字母")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=400, detail="密码必须包含数字")
    return password


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    # journal_mode 是数据库级设置，只在 init_db 中初始化一次。每次新建
    # 连接重复切换 WAL 会引入额外锁竞争，实时消息高频写入时尤其明显。
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT DEFAULT '',
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        # 旧数据库的兼容迁移。auth_epoch 变更后，旧 Token 将立即失效，
        # 用于在管理员重置密码时撤销该用户现有的所有登录态。
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        if "auth_epoch" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN auth_epoch INTEGER NOT NULL DEFAULT 0")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_valid BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        _create_default_admin(conn)
        _create_configured_superadmin(conn)
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id),
                UNIQUE(session_id, seq)
            )
        """)
        conn.commit()
    finally:
        conn.close()


def _create_default_admin(conn: sqlite3.Connection):
    try:
        admin_hash = pwd_context.hash("admin123")
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", admin_hash, "admin"),
        )
    except sqlite3.IntegrityError:
        pass


def _create_configured_superadmin(conn: sqlite3.Connection):
    """首次启动时按环境变量创建独立的最高管理员账户。

    不提供内置密码，避免把可公开猜到的最高权限账号带到部署环境。
    账户一旦创建，后续修改环境变量不会覆盖其密码；请通过管理页重置。
    """
    username = os.getenv("LINGSHU_SUPERADMIN_USERNAME", "superadmin").strip()
    password = os.getenv("LINGSHU_SUPERADMIN_PASSWORD", "")
    if not username or not password:
        return
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if row:
        conn.execute("UPDATE users SET role = 'superadmin' WHERE id = ?", (row["id"],))
        return
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'superadmin')",
        (username, pwd_context.hash(password)),
    )


def get_user_by_username(username: str) -> Optional[dict]:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_user(username: str, password: str, email: str = "") -> dict:
    validate_password_strength(password)
    password_hash = pwd_context.hash(password)
    conn = get_db()
    try:
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email),
        )
        conn.commit()
        return {
            "id": cursor.lastrowid,
            "username": username,
            "email": email,
            "role": "user",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="注册失败，请检查邀请码、用户名或密码",
        )
    finally:
        conn.close()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def list_users() -> list[dict]:
    """用于超级管理员页面的最小化用户信息，不泄露密码散列。"""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, username, email, role, created_at, last_login FROM users ORDER BY id ASC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def reset_user_password(user_id: int, password: str) -> None:
    if len(password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="新密码长度不能少于 8 位")
    conn = get_db()
    try:
        cursor = conn.execute(
            "UPDATE users SET password_hash = ?, auth_epoch = auth_epoch + 1 WHERE id = ?",
            (pwd_context.hash(password), user_id),
        )
        if cursor.rowcount != 1:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
        conn.commit()
    finally:
        conn.close()


def delete_user(user_id: int) -> None:
    conn = get_db()
    try:
        cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        if cursor.rowcount != 1:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
        conn.commit()
    finally:
        conn.close()


def create_access_token(user_id: int, username: str, role: str, auth_epoch: int = 0):
    expires = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "auth_epoch": auth_epoch,
        "exp": expires,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_hex(16),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, JWT_EXPIRE_MINUTES


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """获取当前用户，优先使用中间件预加载的结果以避免重复 DB 查询。"""
    # 优先使用中间件已验证并缓存的用户对象
    pre_loaded = getattr(request.state, "current_user", None)
    if pre_loaded and isinstance(pre_loaded, dict) and "id" in pre_loaded:
        return pre_loaded

    # Fallback：手动解码令牌并查找用户
    token = credentials.credentials
    payload = decode_access_token(token)
    user = get_user_by_username(payload["username"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户不存在",
        )
    if int(payload.get("auth_epoch", -1)) != int(user.get("auth_epoch", 0)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="登录状态已失效，请重新登录")
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user.get("email", ""),
        "role": user["role"],
    }


init_db()
