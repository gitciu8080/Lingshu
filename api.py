"""灵枢 Web API — FastAPI 后端，提供任务管理、SSE 流式日志、文件上传。"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

# 确保项目根在 sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

# ── SSE 事件总线和任务管理 ──

_event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=5000)
_mission_lock = asyncio.Lock()
_current_task: asyncio.Task[Any] | None = None
_mission_store_path = _PROJECT_ROOT / ".TaskMemory" / "current_mission.json"
_long_memory_path = _PROJECT_ROOT / ".LongMemory" / "agentic_memory.json"
_upload_dir = _PROJECT_ROOT / "WorkDir" / "uploads"

# 确保上传目录存在
_upload_dir.mkdir(parents=True, exist_ok=True)


def _push_event(event_type: str, **payload: Any) -> None:
    """将事件推入 SSE 队列（非阻塞尽力而为）。"""
    data = {"type": event_type, **payload}
    try:
        _event_queue.put_nowait(data)
    except asyncio.QueueFull:
        pass  # 丢弃最旧事件以容纳新事件


async def _event_generator():
    """SSE 事件生成器，持续从队列读取并 yield。"""
    while True:
        try:
            event = await asyncio.wait_for(_event_queue.get(), timeout=15.0)
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        except asyncio.TimeoutError:
            yield ": heartbeat\n\n"


# ── 从 main 延迟导入（避免循环）──

from main import run_mission  # noqa: E402


# ── FastAPI 应用 ──

app = FastAPI(
    title="灵枢 Lingshu — Web 控制台",
    description="多智能体授权安全测试系统前端 API",
    version="0.3.0",
)

# ── HTTP Basic 认证 ──

# 加载 .env 文件
from config import _load_dotenv  # noqa: E402
_load_dotenv()

_LINGSHU_USER = os.getenv("LINGSHU_USER", "admin")
_LINGSHU_PASS = os.getenv("LINGSHU_PASS", "lingshu2024")
_AUTH_SKIP_PREFIXES = ("/uploads", "/docs", "/openapi.json", "/redoc", "/favicon.ico")


class BasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in _AUTH_SKIP_PREFIXES):
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Lingshu"'},
            )

        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            username, _, password = decoded.partition(":")
        except Exception:
            return Response(status_code=401)

        # 时间恒定比较防时序攻击
        if not (
            len(username) == len(_LINGSHU_USER)
            and len(password) == len(_LINGSHU_PASS)
            and all(a == b for a, b in zip(username, _LINGSHU_USER))
            and all(a == b for a, b in zip(password, _LINGSHU_PASS))
        ):
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Lingshu"'},
            )

        return await call_next(request)


app.add_middleware(BasicAuthMiddleware)

# 挂载上传目录为静态文件
app.mount("/uploads", StaticFiles(directory=str(_upload_dir)), name="uploads")


# ── 请求模型 ──

class MissionStartRequest(BaseModel):
    target: str = Field(..., description="授权目标 IP / IP:端口 / 主机名 / 文件路径")
    goal: str = Field(default="获取 Flag", description="任务目标描述")
    provider: str = Field(default="deepseek", description="模型提供商: deepseek | qwen")
    model: str = Field(default="Min", description="思考级别: Low | Min | Max")


class MissionCancelRequest(BaseModel):
    task_id: str


# ── 路由 ──


@app.get("/", response_class=HTMLResponse)
async def index():
    """返回前端页面。"""
    html_path = _PROJECT_ROOT / "frontend" / "index.html"
    if html_path.is_file():
        return html_path.read_text(encoding="utf-8")
    return HTMLResponse("<h1>前端页面未找到，请将 index.html 放入 frontend/ 目录</h1>", status_code=404)


@app.post("/api/mission/start")
async def start_mission(req: MissionStartRequest):
    """启动一个新的安全测试任务并以 SSE 流式返回日志。"""
    global _current_task

    if _mission_lock.locked():
        raise HTTPException(status_code=409, detail="当前有任务正在运行，请等待完成或取消")

    async def _run_and_cleanup():
        """后台运行任务并在完成后释放锁。"""
        try:
            await run_mission(
                target=req.target,
                goal=req.goal,
                model_ver=req.model,
                provider=req.provider,
                event_callback=_push_event,
            )
        except Exception as exc:
            _push_event("error", message=f"任务异常: {exc}", agent="system")
        finally:
            _push_event("mission_end", message="任务已结束")
            if _mission_lock.locked():
                _mission_lock.release()

    await _mission_lock.acquire()
    _push_event("mission_start", target=req.target, goal=req.goal, provider=req.provider, model=req.model)
    _current_task = asyncio.create_task(_run_and_cleanup())

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/mission/stream")
async def stream_events():
    """独立 SSE 端点，用于连接已有任务的实时日志。"""
    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/mission/cancel")
async def cancel_mission():
    """取消当前正在运行的任务。"""
    global _current_task
    if _current_task is None or _current_task.done():
        _push_event("error", message="没有正在运行的任务可以取消", agent="system")
        return {"status": "no_task"}
    _current_task.cancel()
    _push_event("mission_cancelled", message="任务已被用户取消")
    return {"status": "cancelled"}


@app.get("/api/mission/state")
async def mission_state():
    """返回当前任务的结构化状态。"""
    if _mission_store_path.is_file():
        try:
            return json.loads(_mission_store_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"phase": "idle", "message": "无运行中的任务"}


@app.get("/api/mission/history")
async def mission_history(limit: int = 20):
    """返回历史任务记录。"""
    if _long_memory_path.is_file():
        try:
            data = json.loads(_long_memory_path.read_text(encoding="utf-8"))
            missions = data.get("missions", [])
            return {"missions": missions[-limit:], "total": len(missions)}
        except (json.JSONDecodeError, OSError):
            pass
    return {"missions": [], "total": 0}


@app.post("/api/mission/upload")
async def upload_target(file: UploadFile = File(...)):
    """上传目标文件（.zip / .tar.gz / .pcapng 等）。"""
    # 安全检查：拒绝过大文件（100MB）
    MAX_SIZE = 100 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="文件过大，上限 100MB")

    # 保存文件
    safe_name = Path(file.filename or "upload").name
    dest = _upload_dir / f"{uuid.uuid4().hex[:8]}_{safe_name}"
    dest.write_bytes(content)

    return {
        "filename": safe_name,
        "path": str(dest),
        "size": len(content),
        "message": f"文件已上传: {dest}",
    }


# ── 启动入口 ──

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_level="info",
    )
