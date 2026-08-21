"""Build and expose the mounted AgentScope Agent Service application."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from agentscope.app import create_app
from agentscope.app.deps import get_current_user_id as default_user_id
from agentscope.app.message_bus import InMemoryMessageBus
from agentscope.agent import ContextConfig, ReActConfig
from agentscope.app.storage import (
    AgentData,
    AgentRecord,
    AsyncSQLAlchemyStorage,
    ChatModelConfig,
)
from agentscope.app.workspace_manager import IsolationPolicy, LocalWorkspaceManager
from agentscope.credential import DeepSeekCredential, OpenAICredential
from pydantic import SecretStr

from core.auth import get_current_user
from core.config import RuntimeConfig
import core.session_store as session_store
from Tools.tooling import cancel_agent_tasks

from .facade import LingshuMissionAgent
from .account_events import subscribe_account, unsubscribe_account
from .runtime import get_runtime

logger = logging.getLogger(__name__)


_ROOT = Path(__file__).resolve().parents[2]
_DATA_DIR = _ROOT / "data"
_WORKSPACE_DIR = _ROOT / "WorkDir" / "agent-service"


def _cancel_marker(session_id: str) -> Path:
    return _ROOT / ".TaskMemory" / "sessions" / f"{session_id}.cancelled"


def _owner_marker(session_id: str) -> Path:
    return _ROOT / ".TaskMemory" / "sessions" / f"{session_id}.owner"

storage = AsyncSQLAlchemyStorage(
    f"sqlite+aiosqlite:///{_DATA_DIR / 'agentscope.db'}",
)
message_bus = InMemoryMessageBus()
workspace_manager = LocalWorkspaceManager(
    basedir=str(_WORKSPACE_DIR),
    isolation=IsolationPolicy.PER_SESSION,
)

agentscope_app = create_app(
    storage=storage,
    message_bus=message_bus,
    workspace_manager=workspace_manager,
    custom_agent_cls=LingshuMissionAgent,
    title="Lingshu Agent Service",
    version="2.0.6-lingshu",
)


async def _jwt_user_id(request: Request) -> str:
    user = getattr(request.state, "current_user", None)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="需要认证")
    return str(user["id"])


agentscope_app.dependency_overrides[default_user_id] = _jwt_user_id


@asynccontextmanager
async def agentscope_lifespan():
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    async with agentscope_app.router.lifespan_context(agentscope_app):
        yield


class RuntimeInput(BaseModel):
    content: str = Field(min_length=1, max_length=10000)


class MirrorSessionRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4096)
    goal: str = Field(default="获取 Flag", max_length=10000)
    provider: str = Field(default="deepseek", pattern="^(deepseek|qwen)$")
    model: str = Field(default="Min", pattern="^(Low|Min|Max)$")
    qwen_tool_call_mode: str | None = Field(default=None, pattern="^(simple|standard)$")


control_router = APIRouter(prefix="/api/agent-service", tags=["agent-service-control"])


@control_router.get("/account/stream")
async def stream_account_events(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Stream phase changes from every mission owned by the current account."""
    user_id = str(current_user["id"])
    queue = subscribe_account(user_id)

    async def generate():
        try:
            while not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                data = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                yield f"id: {event['id']}\nevent: {event['type']}\ndata: {data}\n\n"
        finally:
            unsubscribe_account(user_id, queue)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

def _agent_id(user_id: str) -> str:
    return f"lingshu-orchestrator-u{user_id}"


async def _ensure_agent(user_id: str) -> str:
    agent_id = _agent_id(user_id)
    if await storage.get_agent(user_id, agent_id) is None:
        await storage.upsert_agent(
            user_id,
            AgentRecord(
                id=agent_id,
                user_id=user_id,
                data=AgentData(
                    id=agent_id,
                    name="Lingshu",
                    system_prompt=(
                        "你是灵枢授权安全测试任务的服务入口。"
                        "实际多智能体工作流由 LingshuMissionAgent 驱动。"
                    ),
                    context_config=ContextConfig(),
                    react_config=ReActConfig(),
                ),
            ),
        )
    return agent_id


async def _ensure_credential(user_id: str, provider: str) -> tuple[str, str]:
    runtime = RuntimeConfig.from_env()
    credential_id = f"lingshu-{provider}-u{user_id}"
    if await storage.get_credential(user_id, credential_id) is None:
        api_key = runtime.get_api_key(provider)
        if provider == "qwen":
            credential = OpenAICredential(
                id=credential_id,
                name="Lingshu Qwen",
                api_key=SecretStr(api_key),
                base_url=runtime.get_base_url(provider),
            )
        else:
            credential = DeepSeekCredential(
                id=credential_id,
                name="Lingshu DeepSeek",
                api_key=SecretStr(api_key),
                base_url=runtime.get_base_url(provider),
            )
        await storage.upsert_credential(user_id, credential)
    return credential_id, runtime.model_name("Min", provider=provider)


class PrepareRequest(BaseModel):
    provider: str = Field(default="deepseek", pattern="^(deepseek|qwen)$")
    model: str = Field(default="Min", pattern="^(Low|Min|Max)$")
    source_session_id: str | None = None


@control_router.get("/config")
async def get_service_config(current_user: dict = Depends(get_current_user)):
    agent_id = await _ensure_agent(str(current_user["id"]))
    return {"enabled": True, "agent_id": agent_id, "api_prefix": "/agentscope"}


@control_router.post("/prepare")
async def prepare_service_session(
    body: PrepareRequest,
    current_user: dict = Depends(get_current_user),
):
    user_id = str(current_user["id"])
    agent_id = await _ensure_agent(user_id)
    credential_id, _ = await _ensure_credential(user_id, body.provider)
    runtime = RuntimeConfig.from_env()
    model_name = runtime.model_name(body.model, provider=body.provider)
    parameters: dict[str, object] = {"temperature": 0.7}
    if body.provider == "deepseek":
        parameters["thinking_enable"] = True
        parameters["reasoning_effort"] = "max" if body.model == "Max" else "high"
    initial_context = None
    if body.source_session_id:
        source = await storage.get_session(user_id, _agent_id(user_id), body.source_session_id)
        if source is None:
            import core.session_store as session_store

            legacy = session_store.get_session(body.source_session_id)
            if legacy is None or str(legacy.get("user_id")) != user_id:
                raise HTTPException(status_code=404, detail="来源会话不存在")
        initial_context = _build_mission_context(body.source_session_id)
    return {
        "agent_id": agent_id,
        "chat_model_config": ChatModelConfig(
            type=f"{body.provider}_credential",
            credential_id=credential_id,
            model=model_name,
            parameters=parameters,
        ).model_dump(mode="json"),
        "initial_context": initial_context,
    }


async def _owned_session(user_id: str, session_id: str):
    session = await storage.get_session(user_id, _agent_id(user_id), session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="会话不存在")
    return session


def _build_mission_context(session_id: str) -> str | None:
    import json

    mission_path = _ROOT / ".TaskMemory" / "sessions" / f"{session_id}.json"
    try:
        mission = json.loads(mission_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    lines = [
        f"前次目标：{mission.get('target', '未知')}",
        f"前次任务：{mission.get('goal', '未知')}",
        f"前次阶段：{mission.get('phase', '未知')}",
    ]
    if mission.get("summary"):
        lines.append(f"前次总结：{str(mission['summary'])[:1000]}")
    findings = mission.get("findings") or []
    if findings:
        lines.append("前次发现：")
        for finding in findings[-5:]:
            lines.append(f"- {str(finding.get('report') or finding)[:500]}")
    attack_chain = mission.get("attack_chain") or []
    if attack_chain:
        lines.append("前次攻击链：")
        for step in attack_chain[-5:]:
            lines.append(f"- {str(step.get('report') or step)[:300]}")
    return "\n".join(lines)[:4000]


@control_router.post("/sessions/{session_id}/input", status_code=status.HTTP_202_ACCEPTED)
async def send_runtime_input(
    session_id: str,
    body: RuntimeInput,
    current_user: dict = Depends(get_current_user),
):
    await _owned_session(str(current_user["id"]), session_id)
    runtime = await get_runtime(session_id)
    if runtime is None:
        raise HTTPException(status_code=409, detail="该会话当前没有运行中的任务")
    content = body.content.strip()
    try:
        if session_store.get_session(session_id) is not None:
            session_store.add_message(
                session_id,
                "user",
                content,
                "user_message",
                "user",
            )
    except Exception:
        logger.exception("Failed to persist user input for %s", session_id)
    if runtime.pending_approval is not None:
        if runtime.approval_decision_submitted:
            return {"status": "duplicate", "session_id": session_id}
        runtime.approval_decision_submitted = True
        runtime.approval_decision = content
        await runtime.input_queue.put(content)
        return {"status": "accepted", "session_id": session_id}
    if runtime.approval_decision_submitted and content == runtime.approval_decision:
        return {"status": "approval_already_resolved", "session_id": session_id}
    runtime.steering_state["pending"] = content
    runtime.steering_state["processed"] = False
    await cancel_agent_tasks(runtime.agent_tasks)
    return {"status": "steering", "session_id": session_id}


@control_router.post("/sessions/{session_id}/mirror", status_code=status.HTTP_201_CREATED)
async def mirror_session(
    session_id: str,
    body: MirrorSessionRequest,
    current_user: dict = Depends(get_current_user),
):
    await _owned_session(str(current_user["id"]), session_id)
    existing = session_store.get_session(session_id)
    if existing is not None:
        if str(existing.get("user_id")) != str(current_user["id"]):
            raise HTTPException(status_code=409, detail="会话 ID 冲突")
        return {"status": "exists", "session_id": session_id}
    session_store.create_session(
        user_id=current_user["id"],
        target=body.target,
        goal=body.goal,
        provider=body.provider,
        model=body.model,
        title=f"[{session_id[:8]}] 安全测试任务",
        session_id=session_id,
    )
    session_store.add_message(
        session_id,
        "user",
        body.goal,
        "user_message",
        "user",
    )
    return {"status": "created", "session_id": session_id}


@control_router.post(
    "/sessions/{session_id}/interrupt",
    status_code=status.HTTP_202_ACCEPTED,
)
async def interrupt_runtime(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    await _owned_session(str(current_user["id"]), session_id)
    registry = agentscope_app.state.chat_run_registry
    task = registry.get(session_id)
    cancellation_requested = False
    if task is not None and not task.done():
        cancellation_requested = task.cancel()
        if cancellation_requested:
            marker = _cancel_marker(session_id)
            marker.parent.mkdir(parents=True, exist_ok=True)
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
    current_user: dict = Depends(get_current_user),
):
    await _owned_session(str(current_user["id"]), session_id)
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
    current_user: dict = Depends(get_current_user),
):
    session = await _owned_session(str(current_user["id"]), session_id)
    mission_path = _ROOT / ".TaskMemory" / "sessions" / f"{session_id}.json"
    mission_state = None
    if mission_path.is_file():
        import json

        try:
            mission_state = json.loads(mission_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            mission_state = None
    phase = (mission_state or {}).get("phase", "planning")
    if _cancel_marker(session_id).is_file():
        phase = "cancelled"
    messages, _ = await storage.list_messages(
        str(current_user["id"]),
        session_id,
        limit=1,
    )
    if messages:
        finished_reason = getattr(messages[-1], "finished_reason", None)
        if finished_reason == "interrupted":
            phase = "cancelled"
        elif finished_reason == "error":
            phase = "failed"
        elif (
            finished_reason == "completed"
            and phase not in {"completed", "failed"}
            and (mission_state or {}).get("success") is not True
        ):
            phase = "failed"
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
        "id": session.id,
        "title": (mission_state or {}).get("title") or session.config.name,
        "target": (mission_state or {}).get("target", session.config.name),
        "goal": (mission_state or {}).get("goal", ""),
        "provider": provider,
        "model": model_ver,
        "phase": phase,
        "mission_state": mission_state,
        "target_info": {
            "target": (mission_state or {}).get("target", session.config.name),
            "goal": (mission_state or {}).get("goal", ""),
            "phase": phase,
            "flag": (mission_state or {}).get("flag"),
        },
    }


@control_router.delete(
    "/sessions/{session_id}/mission",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_mission_state(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    try:
        await _owned_session(str(current_user["id"]), session_id)
    except HTTPException as exc:
        legacy = session_store.get_session(session_id)
        if (
            exc.status_code != 404
            or legacy is None
            or str(legacy.get("user_id")) != str(current_user["id"])
        ):
            raise
    mission_path = _ROOT / ".TaskMemory" / "sessions" / f"{session_id}.json"
    try:
        mission_path.unlink(missing_ok=True)
        _cancel_marker(session_id).unlink(missing_ok=True)
        _owner_marker(session_id).unlink(missing_ok=True)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"删除任务状态失败: {exc}") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@control_router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_service_session(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    user_id = str(current_user["id"])
    agent_id = _agent_id(user_id)
    native = await storage.get_session(user_id, agent_id, session_id)
    legacy = session_store.get_session(session_id)
    legacy_owned = (
        legacy is not None
        and str(legacy.get("user_id")) == user_id
    )
    owner_marker = _owner_marker(session_id)
    try:
        marker_owned = owner_marker.read_text(encoding="utf-8").strip() == user_id
    except OSError:
        marker_owned = False
    if native is None and not legacy_owned and not marker_owned:
        raise HTTPException(status_code=404, detail="会话不存在")

    if native is not None:
        owner_marker.parent.mkdir(parents=True, exist_ok=True)
        owner_marker.write_text(user_id, encoding="utf-8")
        deleted = await agentscope_app.state.session_service.delete_session(
            user_id,
            agent_id,
            session_id,
        )
        if not deleted:
            raise HTTPException(status_code=409, detail="AgentScope 会话删除失败")

    mission_path = _ROOT / ".TaskMemory" / "sessions" / f"{session_id}.json"
    try:
        mission_path.unlink(missing_ok=True)
        _cancel_marker(session_id).unlink(missing_ok=True)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"删除任务状态失败: {exc}") from exc

    if legacy_owned:
        session_store.delete_session(session_id)
    try:
        owner_marker.unlink(missing_ok=True)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"删除所有权标记失败: {exc}") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
