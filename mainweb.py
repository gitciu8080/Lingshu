#!/usr/bin/env python3
"""灵枢：基于 AgentScope 2.x 的多智能体授权安全测试 Web 服务入口。

与 main.py（CLI 入口）等价：核心工作流均为 main.run_mission 驱动的
Brain→Orchestrator→Recon→Attack 授权测试链。本入口通过 AgentScope 2.x
的 Agent Service（create_app）对外提供 Web 控制台 API（服务本身不附带
前端，控制台是独立的 React 应用 —— 见 docs.agentscope.io 的 agent-service
章节，前端即 agentscope 仓库 examples/web_ui）：

  mainweb.py 启动 → AgentScope Agent Service（根路径，兼容 web_ui 直连）
    ├── GET /health                      # web_ui 连接探测端点
    ├── AgentScope 资源 API（/agent /sessions /chat /credential …）
    ├── 控制路由 /api/agent-service/*（审批 / steering / interrupt / mirror）
    └── LingshuMissionAgent（单个 reply 驱动一次完整任务）
          ├── main.run_mission()        # 复用 CLI 的完整多智能体流水线
          └── 审批由 _ApprovalBroker._ask_api 挂起，经输入端点 feed 答复

CLI 模式（main.py）的 --target/--goal/--provider/--model 参数在 Web 模式下
由控制台聊天消息携带：灵枢自家前端经 UserMsg.metadata.lingshu 注入；
web_ui 等纯文本通道则用「目标: IP / target: IP」前缀解析（见 facade）。
"""
from __future__ import annotations

import argparse  # 命令行参数解析（--host / --port / --reload）
import asyncio  # 异步取消与运行控制
import json  # 任务状态 JSON 读写
import os  # 路径与环境变量
import sys  # 修改模块搜索路径
from pathlib import Path
from typing import Any

# 将本文件所在目录加入模块搜索路径，
# 确保无论从哪里启动 mainweb.py 都能导入 main / config / integrations 等兄弟模块。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.middleware import Middleware
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agentscope.app import create_app
from agentscope.app.deps import get_current_user_id  # AgentScope 默认用户标识（X-User-ID 头）
from agentscope.app.message_bus import InMemoryMessageBus
from agentscope.app.storage import AsyncSQLAlchemyStorage
from agentscope.app.workspace_manager import IsolationPolicy, LocalWorkspaceManager

import session_store  # 会话持久化（与 api.py 集成共享）
from Tools.tooling import cancel_agent_tasks  # 取消所有 Agent reply task（steering/interrupt）
from integrations.agentscope_service.facade import LingshuMissionAgent  # 包装 main.run_mission 的服务 facade
from integrations.agentscope_service.runtime import get_runtime  # 运行中任务的审批/steering 状态

# ── 目录规划（与 api.py 的 AgentScope 集成保持一致）──
_PROJECT_ROOT = Path(__file__).resolve().parent
_DATA_DIR = _PROJECT_ROOT / "data"
_WORKSPACE_DIR = _PROJECT_ROOT / "WorkDir" / "agent-service"
_MISSION_DIR = _PROJECT_ROOT / ".TaskMemory" / "sessions"

# 初始化目录与会话数据库（模块加载时执行，等价于 api.py 的行为）
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
_MISSION_DIR.mkdir(parents=True, exist_ok=True)
session_store.init_sessions_db()

# ── 共享存储与工作区 ──
# SQLite 存储（免外部服务，与 api.py 集成同一数据库文件）；
# 工作区按会话隔离，每个会话拥有独立沙箱。
storage = AsyncSQLAlchemyStorage(
    f"sqlite+aiosqlite:///{_DATA_DIR / 'agentscope.db'}",
)
message_bus = InMemoryMessageBus()
workspace_manager = LocalWorkspaceManager(
    basedir=str(_WORKSPACE_DIR),
    isolation=IsolationPolicy.PER_SESSION,
)

# ── AgentScope Agent Service（根路径对外）──
# 注册 LingshuMissionAgent 为自定义 agent；控制台发送聊天消息即可驱动一次任务。
# 该 app 由 create_app 自带 lifespan 管理存储/总线/工作区等资源生命周期。
app = create_app(
    storage=storage,
    message_bus=message_bus,
    workspace_manager=workspace_manager,
    custom_agent_cls=LingshuMissionAgent,
    # web_ui 在独立端口（Vite 5173）运行，跨域访问后端需要 CORS
    extra_middlewares=[
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        ),
    ],
    title="灵枢 Lingshu — Agent Service",
    version="2.0.6-lingshu",
)


# ── 运行中任务控制路由（审批 / steering / interrupt / mirror）──
# 与 api.py 中挂载的集成路由等价，但鉴权采用 AgentScope 默认的
# X-User-ID 头（不依赖 api.py 的 JWT 中间件），适合独立部署。

control_router = APIRouter(
    prefix="/api/agent-service",
    tags=["agent-service-control"],
)


class RuntimeInput(BaseModel):
    content: str = Field(min_length=1, max_length=10000)


class MirrorSessionRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4096)
    goal: str = Field(default="获取 Flag", max_length=10000)
    provider: str = Field(default="deepseek", pattern="^(deepseek|qwen)$")
    model: str = Field(default="Min", pattern="^(Low|Min|Max)$")
    qwen_tool_call_mode: str | None = Field(default=None, pattern="^(simple|standard)$")


def _agent_id(user_id: str) -> str:
    return f"lingshu-orchestrator-u{user_id}"


def _owned_session(session_id: str, user_id: str) -> dict:
    """校验会话归属权：通过 session_store（Lingshu 侧镜像）判断。"""
    session = session_store.get_session(session_id)
    if session is None or str(session.get("user_id")) != str(user_id):
        raise HTTPException(status_code=404, detail="会话不存在")
    return session


@control_router.post("/sessions/{session_id}/mirror", status_code=status.HTTP_201_CREATED)
async def mirror_session(
    session_id: str,
    body: MirrorSessionRequest,
    user_id: str = Depends(get_current_user_id),
):
    """在 Lingshu 侧创建会话镜像，供 LingshuMissionAgent 的 RoleHistoryRecorder 使用。

    AgentScope 会话创建成功后调用本端点，目标/目标描述/模型参数随之落库。
    """
    existing = session_store.get_session(session_id)
    if existing is not None:
        if str(existing.get("user_id")) != str(user_id):
            raise HTTPException(status_code=409, detail="会话 ID 冲突")
        return {"status": "exists", "session_id": session_id}
    session_store.create_session(
        user_id=user_id,
        target=body.target,
        goal=body.goal,
        provider=body.provider,
        model=body.model,
        title=f"[{session_id[:8]}] 安全测试任务",
        session_id=session_id,
    )
    session_store.add_message(
        session_id, "user", body.goal, "user_message", "user",
    )
    return {"status": "created", "session_id": session_id}


@control_router.post("/sessions/{session_id}/input", status_code=status.HTTP_202_ACCEPTED)
async def send_runtime_input(
    session_id: str,
    body: RuntimeInput,
    user_id: str = Depends(get_current_user_id),
):
    """向运行中的任务发送用户输入——支持审批决策与运行时追加指令（steering）。"""
    _owned_session(session_id, user_id)
    runtime = await get_runtime(session_id)
    if runtime is None:
        raise HTTPException(status_code=409, detail="该会话当前没有运行中的任务")
    content = body.content.strip()
    try:
        if session_store.get_session(session_id) is not None:
            session_store.add_message(
                session_id, "user", content, "user_message", "user",
            )
    except Exception:
        pass
    # 挂起人工审批：输入是审批答复（批准/补充侦察/拒绝），非肯定答复视为拒绝
    if runtime.pending_approval is not None:
        if runtime.approval_decision_submitted:
            return {"status": "duplicate", "session_id": session_id}
        runtime.approval_decision_submitted = True
        runtime.approval_decision = content
        await runtime.input_queue.put(content)
        return {"status": "accepted", "session_id": session_id}
    if runtime.approval_decision_submitted and content == runtime.approval_decision:
        return {"status": "approval_already_resolved", "session_id": session_id}
    # 普通指令：写入 steering_state 并中断 Agent，主循环注入后恢复执行
    runtime.steering_state["pending"] = content
    runtime.steering_state["processed"] = False
    await cancel_agent_tasks(runtime.agent_tasks)
    return {"status": "steering", "session_id": session_id}


@control_router.post("/sessions/{session_id}/interrupt", status_code=status.HTTP_202_ACCEPTED)
async def interrupt_runtime(
    session_id: str,
    user_id: str = Depends(get_current_user_id),
):
    """取消运行中的任务（立即生效，进程清理由 facade 的 finally 完成）。"""
    _owned_session(session_id, user_id)
    task = app.state.chat_run_registry.get(session_id)
    cancellation_requested = False
    if task is not None and not task.done():
        cancellation_requested = task.cancel()
        if cancellation_requested:
            marker = _MISSION_DIR / f"{session_id}.cancelled"
            marker.write_text("cancelled\n", encoding="utf-8")
        try:
            await task
        except asyncio.CancelledError:
            pass
    return {
        "status": "interrupted" if cancellation_requested else "idle",
        "session_id": session_id,
    }


@control_router.get("/sessions/{session_id}/pending-approval")
async def get_pending_approval(
    session_id: str,
    user_id: str = Depends(get_current_user_id),
):
    """查询会话是否有待处理的人工审批请求（断线重连恢复审批弹窗用）。"""
    _owned_session(session_id, user_id)
    runtime = await get_runtime(session_id)
    if runtime is None or runtime.pending_approval is None:
        return {"pending": False}
    return {
        "pending": True,
        "event": {
            "type": "approval_required",
            "session_id": session_id,
            **runtime.pending_approval,
        },
    }


@control_router.get("/sessions/{session_id}/mission")
async def get_mission_state(
    session_id: str,
    user_id: str = Depends(get_current_user_id),
):
    """返回任务的持久化 MissionState 快照与精简视图。"""
    session = _owned_session(session_id, user_id)
    mission_path = _MISSION_DIR / f"{session_id}.json"
    mission_state = None
    if mission_path.is_file():
        try:
            mission_state = json.loads(mission_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            mission_state = None
    phase = (mission_state or {}).get("phase", "planning")
    if (_MISSION_DIR / f"{session_id}.cancelled").is_file():
        phase = "cancelled"
    provider = "deepseek"
    model_ver = "Min"
    for event in (mission_state or {}).get("events", []):
        if event.get("action") != "mission_created":
            continue
        model_ref = str((event.get("details") or {}).get("model") or "")
        if "/" in model_ref:
            provider, model_ver = model_ref.split("/", 1)
        break
    return {
        "id": session_id,
        "title": (mission_state or {}).get("title")
        or session.get("title") or "安全测试任务",
        "target": (mission_state or {}).get("target") or session.get("target", ""),
        "goal": (mission_state or {}).get("goal") or session.get("goal", ""),
        "provider": provider,
        "model": model_ver,
        "phase": phase,
        "mission_state": mission_state,
        "target_info": {
            "target": (mission_state or {}).get("target") or session.get("target", ""),
            "goal": (mission_state or {}).get("goal", ""),
            "phase": phase,
            "flag": (mission_state or {}).get("flag"),
        },
    }


# ── 聚合：AgentScope 服务 + 控制路由 + 健康探测 ──
# app 即 create_app 返回的 FastAPI（根路径对外，兼容 web_ui 直连）。
app.include_router(control_router)


@app.get("/health")
async def health() -> dict[str, Any]:
    """健康探测端点：web_ui 连接前会 GET {server_url}/health 校验。"""
    return {
        "status": "ok",
        "version": "2.0.6-lingshu",
        "components": {
            "storage": "ok",
            "message_bus": "ok",
            "workspace_manager": "ok",
        },
    }


@app.get("/")
async def root() -> dict[str, Any]:
    """服务信息：控制台 API 根路径与控制路由前缀。"""
    return {
        "service": "灵枢 Lingshu — Agent Service",
        "console": "请运行 agentscope 仓库 examples/web_ui 前端连接本服务",
        "control_api": "/api/agent-service/",
        "docs": "/docs",
    }


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器（仿照 main.py 的 build_parser 风格）。

    支持参数:
      --host    服务监听地址，默认 0.0.0.0
      --port / -p  服务监听端口，默认 8000
      --reload  开发模式热重载（检测代码变更自动重启）
      --qwen-tool-mode Qwen 默认工具调用模式：simple 或 standard
    """
    parser = argparse.ArgumentParser(
        description="灵枢 — AgentScope 2.x 多智能体授权安全测试系统（Web 服务入口）",
    )
    parser.add_argument("--host", default="0.0.0.0", help="服务监听地址（默认 0.0.0.0）")
    parser.add_argument(
        "--port", "-p", type=int, default=8000,
        help="服务监听端口（默认 8000）",
    )
    parser.add_argument(
        "--reload", action="store_true",
        help="开发模式热重载（自动检测代码变更并重启）",
    )
    parser.add_argument(
        "--qwen-tool-mode",
        choices=["simple", "standard"],
        default=None,
        help="Qwen 默认工具调用模式：simple=扁平兼容，standard=批量嵌套；默认读 QWEN_TOOL_CALL_MODE",
    )
    return parser


def main() -> None:
    """Web 服务入口：解析参数 → 启动 uvicorn。

    等价于 main.py 的 main()：main.py 用 asyncio.run 驱动单次 CLI 任务，
    本入口用 uvicorn 启动 AgentScope Agent Service 对外提供 Web 控制台。
    """
    args = build_parser().parse_args()
    # run_mission 在每个新会话读取 RuntimeConfig；在此设置进程环境可同时
    # 覆盖普通启动与 uvicorn --reload 派生的子进程。
    if args.qwen_tool_mode is not None:
        os.environ["QWEN_TOOL_CALL_MODE"] = args.qwen_tool_mode
    # reload 模式下 uvicorn 需要按模块路径导入，因此传字符串 "mainweb:app"
    uvicorn.run(
        "mainweb:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
