""" Web API FastAPI SSE """
from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from auth import (
    get_current_user,
    create_user,
    verify_password,
    create_access_token,
    decode_access_token,
    security,
    UserCreate,
    UserLogin,
    TokenResponse,
)

from main import run_mission

# ── SSE 事件总线和任务管理 ──
_event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=5000)
_mission_lock = asyncio.Lock()
_current_task: asyncio.Task[Any] | None = None
_mission_store_path = _PROJECT_ROOT / ".TaskMemory" / "current_mission.json"
_long_memory_path = _PROJECT_ROOT / ".LongMemory" / "agentic_memory.json"
_upload_dir = _PROJECT_ROOT / "WorkDir" / "uploads"
_upload_dir.mkdir(parents=True, exist_ok=True)


def _push_event(event_type: str, **payload: Any) -> None:
    data = {"type": event_type, **payload}
    try:
        _event_queue.put_nowait(data)
    except asyncio.QueueFull:
        pass


async def _event_generator():
    while True:
        try:
            event = await asyncio.wait_for(_event_queue.get(), timeout=15.0)
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        except asyncio.TimeoutError:
            yield ": heartbeat\n\n"


app = FastAPI(
    title="灵枢 Lingshu — Web 控制台",
    description="多智能体授权安全测试系统前端 API",
    version="0.4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── JWT 认证中间件 ──
# 免认证路径：登录/注册接口、静态页面与文档。登录页本身无需 Token，
# 页面加载后由前端 JS 携带 Token 调用受保护的 /api/* 接口。
_AUTH_SKIP_PATHS = (
    "/",
    "/index.html",
    "/uploads",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/favicon.ico",
    "/auth/login",
    "/auth/register",
)


class JWTAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/") or "/"
        if any(path == p or path.startswith(p + "/") for p in _AUTH_SKIP_PATHS):
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return Response(
                status_code=401,
                content=json.dumps({"detail": "需要 Bearer Token 认证"}),
                media_type="application/json",
            )
        token = auth[7:]
        try:
            payload = decode_access_token(token)
            request.state.current_user = payload
        except HTTPException:
            return Response(
                status_code=401,
                content=json.dumps({"detail": "无效的认证令牌"}),
                media_type="application/json",
            )
        return await call_next(request)


app.add_middleware(JWTAuthMiddleware)
app.mount("/uploads", StaticFiles(directory=str(_upload_dir)), name="uploads")

# ── 请求模型 ──
class MissionStartRequest(BaseModel):
    target: str = Field(..., description="授权目标 IP / IP:端口 / 主机名 / 文件路径")
    goal: str = Field(default="获取 Flag", description="任务目标描述")
    provider: str = Field(default="deepseek", description="模型提供商: deepseek | qwen")
    model: str = Field(default="Min", description="思考级别: Low | Min | Max")


class MissionCancelRequest(BaseModel):
    task_id: str


# ── 认证路由 ──
@app.post("/auth/register", response_model=TokenResponse)
async def register(data: UserCreate):
    try:
        user = create_user(data.username, data.password, data.email)
        token, expires_in = create_access_token(user["id"], user["username"], user["role"])
        return TokenResponse(access_token=token, username=user["username"], expires_in=expires_in)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auth/login", response_model=TokenResponse)
async def login(data: UserLogin):
    from auth import get_user_by_username
    user = get_user_by_username(data.username)
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    token, expires_in = create_access_token(user["id"], user["username"], user["role"])
    return TokenResponse(access_token=token, username=user["username"], expires_in=expires_in)


@app.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user


@app.post("/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    return {"message": "登出成功"}


# ── 路由 ──
@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
async def index():
    html_path = _PROJECT_ROOT / "frontend" / "index.html"
    if html_path.is_file():
        return html_path.read_text(encoding="utf-8")
    return HTMLResponse("<h1>前端页面未找到</h1>", status_code=404)


@app.post("/api/mission/start")
async def start_mission(req: MissionStartRequest, current_user: dict = Depends(get_current_user)):
    global _current_task
    if _mission_lock.locked():
        raise HTTPException(status_code=409, detail="当前有任务正在运行")

    async def _run_and_cleanup():
        try:
            await run_mission(
                target=req.target, goal=req.goal, model_ver=req.model,
                provider=req.provider, event_callback=_push_event,
            )
        except Exception as exc:
            _push_event("error", message=f"任务异常：{exc}", agent="system")
        finally:
            _push_event("mission_end", message="任务已结束")
            if _mission_lock.locked():
                _mission_lock.release()

    await _mission_lock.acquire()
    # 清空队列中残留的上一任务/历史事件，避免推送给本次任务的订阅者
    while not _event_queue.empty():
        try:
            _event_queue.get_nowait()
        except asyncio.QueueEmpty:
            break
    _push_event("mission_start", target=req.target, goal=req.goal, provider=req.provider, model=req.model)
    _current_task = asyncio.create_task(_run_and_cleanup())
    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.get("/api/mission/stream")
async def stream_events():
    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.post("/api/mission/cancel")
async def cancel_mission(current_user: dict = Depends(get_current_user)):
    global _current_task
    if _current_task is None or _current_task.done():
        _push_event("error", message="没有正在运行的任务可以取消", agent="system")
        return {"status": "no_task"}
    _current_task.cancel()
    _push_event("mission_cancelled", message="任务已被用户取消")
    return {"status": "cancelled"}


@app.get("/api/mission/state")
async def mission_state(current_user: dict = Depends(get_current_user)):
    if _mission_store_path.is_file():
        try:
            return json.loads(_mission_store_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"phase": "idle", "message": "无运行中的任务"}


@app.get("/api/mission/history")
async def mission_history(limit: int = 20, current_user: dict = Depends(get_current_user)):
    if _long_memory_path.is_file():
        try:
            data = json.loads(_long_memory_path.read_text(encoding="utf-8"))
            missions = data.get("missions", [])
            return {"missions": missions[-limit:], "total": len(missions)}
        except (json.JSONDecodeError, OSError):
            pass
    return {"missions": [], "total": 0}


@app.post("/api/mission/upload")
async def upload_target(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    MAX_SIZE = 100 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="文件过大，上限 100MB")
    safe_name = Path(file.filename or "upload").name
    dest = _upload_dir / f"{uuid.uuid4().hex[:8]}_{safe_name}"
    dest.write_bytes(content)
    return {"filename": safe_name, "path": str(dest), "size": len(content), "message": f"文件已上传：{dest}"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8080, reload=False, log_level="info")
