"""AgentScope 2.0 工具适配与目标范围约束。"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import itertools
import json
import os
import re
import signal
import shlex
from collections.abc import Callable
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from jsonschema import Draft202012Validator

from agentscope.agent import Agent

if TYPE_CHECKING:
    from Tools.ScopeRegistry import ScopeRegistry
from agentscope.event import (
    TextBlockDeltaEvent,
    TextBlockEndEvent,
    TextBlockStartEvent,
    ThinkingBlockDeltaEvent,
    ThinkingBlockEndEvent,
    ThinkingBlockStartEvent,
    ToolCallStartEvent,
    ToolCallDeltaEvent,
    ToolCallEndEvent,
)
from agentscope.message import Msg, TextBlock, ToolCallBlock, ToolResultState
from agentscope.permission import PermissionBehavior, PermissionDecision
from agentscope.types import ReplyFinishedReason
from agentscope.tool import FunctionTool, Toolkit, ToolChunk, ToolResponse
from agentscope.state import AgentState


class AgentMaxIterationsError(RuntimeError):
    """Agent 触发 ReAct 超迭代（ReplyFinishedReason.EXCEED_MAX_ITERS）异常。

    由 stream_agent_reply 在检测到最终消息 finished_reason 为
    EXCEED_MAX_ITERS 时抛出，供调用方将"超迭代"收敛为可恢复事件，
    而不是把 AgentScope 的固定文本当正常结果。
    """


class LazyAgent:
    """首次收到 reply 时才构造真实 Agent 的异步惰性句柄。

    Orchestrator 仍只看到原来的 Agent 协议（name/reply_stream），因此无需改变
    调度工具或状态机。初始化使用锁保证并发工具路径最多创建一次实例。
    """

    def __init__(self, name: str, factory: Callable[[], Any]) -> None:
        self.name = name
        self._factory = factory
        self._agent: Agent | None = None
        self._lock = asyncio.Lock()

    @property
    def loaded(self) -> bool:
        return self._agent is not None

    def get_if_loaded(self) -> Agent | None:
        return self._agent

    async def get(self) -> Agent:
        if self._agent is not None:
            return self._agent
        async with self._lock:
            if self._agent is None:
                created = self._factory()
                if hasattr(created, "__await__"):
                    created = await created
                if not isinstance(created, Agent):
                    raise TypeError(f"LazyAgent factory 未返回 Agent: {type(created)!r}")
                self._agent = created
        return self._agent

    async def reply_stream(self, *args: Any, **kwargs: Any):
        agent = await self.get()
        async for item in agent.reply_stream(*args, **kwargs):
            yield item


class ToolJSONValidationError(RuntimeError):
    """模型连续两次返回损坏或不符合 schema 的工具参数。"""


_TOOL_JSON_FAILURE_HANDLER: ContextVar[
    Callable[[dict[str, Any]], None] | None
] = ContextVar("lingshu_tool_json_failure_handler", default=None)

_ACTION_LIFECYCLE_HANDLER: ContextVar[
    Callable[[str, dict[str, Any]], dict[str, Any]] | None
] = ContextVar("lingshu_action_lifecycle_handler", default=None)


def bind_tool_json_failure_handler(
    handler: Callable[[dict[str, Any]], None],
) -> Token:
    """绑定当前任务的工具 JSON 失败审计处理器。"""
    return _TOOL_JSON_FAILURE_HANDLER.set(handler)


def reset_tool_json_failure_handler(token: Token) -> None:
    _TOOL_JSON_FAILURE_HANDLER.reset(token)


def bind_action_lifecycle_handler(
    handler: Callable[[str, dict[str, Any]], dict[str, Any]],
) -> Token:
    """绑定统一工具/MCP 的 action 去重与结果闭环处理器。"""
    return _ACTION_LIFECYCLE_HANDLER.set(handler)


def reset_action_lifecycle_handler(token: Token) -> None:
    _ACTION_LIFECYCLE_HANDLER.reset(token)


class StrictJSONToolkit(Toolkit):
    """在 AgentScope 的宽松 JSON 修复器之前执行严格工具参数闸门。

    第一次格式/schema 失败仅向模型返回一条短纠错提示；连续第二次失败
    记录审计证据并抛出异常，使任务进入安全收尾。损坏参数永远不会传给工具。
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._consecutive_json_failures = 0

    async def call_tool(
        self,
        tool_call: ToolCallBlock,
        state: AgentState,
    ):
        validation_error: Exception | None = None
        parsed: dict[str, Any] = {}
        try:
            def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError(f"JSON 包含重复字段: {key}")
                    result[key] = value
                return result

            def _reject_non_finite(value: str) -> None:
                raise ValueError(f"JSON 包含非标准数值: {value}")

            parsed = json.loads(
                tool_call.input,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_non_finite,
            )
            if not isinstance(parsed, dict):
                raise ValueError("工具参数顶层必须是 JSON object")
            available = await self._get_available_tools(
                state.tool_context.activated_groups,
            )
            registered = available.get(tool_call.name)
            if registered is not None and registered.tool.input_schema is not None:
                Draft202012Validator(
                    registered.tool.input_schema,
                ).validate(parsed)
        except Exception as exc:  # JSONDecodeError + schema ValidationError
            validation_error = exc

        if validation_error is None:
            self._consecutive_json_failures = 0
            lifecycle_handler = _ACTION_LIFECYCLE_HANDLER.get()
            lifecycle: dict[str, Any] = {}
            if lifecycle_handler is not None:
                lifecycle = lifecycle_handler(
                    "before", {"tool_name": tool_call.name, "parameters": parsed},
                ) or {}
                decision = lifecycle.get("decision", "execute")
                if decision in {"cached", "blocked"}:
                    message = str(lifecycle.get("message") or "工具调用已被执行闭环拦截")
                    response = ToolResponse(id=tool_call.id)
                    chunk = ToolChunk(
                        content=[TextBlock(text=message)],
                        state=(
                            ToolResultState.SUCCESS
                            if decision == "cached" else ToolResultState.ERROR
                        ),
                    )
                    yield chunk
                    yield response.append_chunk(chunk)
                    return

            result_parts: list[str] = []
            tool_error = False
            try:
                async for chunk in super().call_tool(tool_call, state):
                    chunk_state = getattr(chunk, "state", None)
                    if chunk_state == ToolResultState.ERROR:
                        tool_error = True
                    # AgentScope 随后还会产出包含累计内容的 ToolResponse；只从
                    # 增量 ToolChunk 收集，避免结果在 Action/缓存中重复一遍。
                    if isinstance(chunk, ToolChunk):
                        for block in getattr(chunk, "content", None) or []:
                            text_value = getattr(block, "text", None)
                            if text_value and sum(map(len, result_parts)) < 8000:
                                result_parts.append(str(text_value))
                    yield chunk
            except asyncio.CancelledError:
                if lifecycle_handler is not None and lifecycle.get("action_id"):
                    lifecycle_handler("after", {
                        "action_id": lifecycle["action_id"],
                        "result": "工具调用被用户指令或停止请求中断",
                        "cancelled": True,
                    })
                raise
            except BaseException as exc:
                if lifecycle_handler is not None and lifecycle.get("action_id"):
                    lifecycle_handler("after", {
                        "action_id": lifecycle["action_id"],
                        "result": f"{type(exc).__name__}: {exc}",
                        "raised": True, "tool_error": True,
                    })
                raise
            else:
                if lifecycle_handler is not None and lifecycle.get("action_id"):
                    lifecycle_handler("after", {
                        "action_id": lifecycle["action_id"],
                        "result": "".join(result_parts)[:8000],
                        "raised": False, "tool_error": tool_error,
                    })
            return

        self._consecutive_json_failures += 1
        raw = tool_call.input or ""
        evidence = {
            "tool_name": tool_call.name,
            "tool_call_id": tool_call.id,
            "attempt": self._consecutive_json_failures,
            "error": str(validation_error),
            "arguments_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "arguments_preview": raw[:500],
        }
        if self._consecutive_json_failures >= 2:
            handler = _TOOL_JSON_FAILURE_HANDLER.get()
            if handler is not None:
                handler(evidence)
            raise ToolJSONValidationError(
                f"工具 {tool_call.name} 的 JSON 参数连续两次校验失败，已阻止执行并安全终止",
            ) from validation_error

        prompt = (
            "ToolJSONValidationError: 参数必须是严格 JSON 对象并符合工具 schema；"
            "只允许再重试一次，请仅重新调用工具。"
        )
        response = ToolResponse(id=tool_call.id)
        chunk = ToolChunk(
            content=[TextBlock(text=prompt)],
            state=ToolResultState.ERROR,
        )
        yield chunk
        yield response.append_chunk(chunk)


class ProcessTracker:
    """跟踪单次任务启动的进程组，并在任务结束时统一清理。"""

    def __init__(self) -> None:
        self._pgids: set[int] = set()

    def register(self, pgid: int) -> None:
        self._pgids.add(pgid)

    @staticmethod
    def _signal_group(pgid: int, sig: signal.Signals) -> None:
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            pass

    async def terminate_group(self, pgid: int) -> None:
        self._signal_group(pgid, signal.SIGTERM)
        await asyncio.sleep(0.1)
        self._signal_group(pgid, signal.SIGKILL)
        self._pgids.discard(pgid)

    async def terminate_all(self) -> None:
        pgids = tuple(self._pgids)
        for pgid in pgids:
            self._signal_group(pgid, signal.SIGTERM)
        if pgids:
            await asyncio.sleep(0.2)
        for pgid in pgids:
            self._signal_group(pgid, signal.SIGKILL)
        self._pgids.clear()


_PROCESS_TRACKER: ContextVar[ProcessTracker | None] = ContextVar(
    "lingshu_process_tracker",
    default=None,
)


def bind_process_tracker() -> tuple[ProcessTracker, Token]:
    """为当前异步任务绑定一个进程跟踪器。"""
    tracker = ProcessTracker()
    return tracker, _PROCESS_TRACKER.set(tracker)


def reset_process_tracker(token: Token) -> None:
    _PROCESS_TRACKER.reset(token)


_AGENT_TASKS: ContextVar[set[asyncio.Task[Any]] | None] = ContextVar(
    "lingshu_agent_tasks",
    default=None,
)


def bind_agent_tasks(tasks: set[asyncio.Task[Any]]) -> Token:
    """绑定当前会话的 Agent reply task 注册表。"""
    return _AGENT_TASKS.set(tasks)


def reset_agent_tasks(token: Token) -> None:
    _AGENT_TASKS.reset(token)


_EXPERT_ROSTER: ContextVar[set[str] | None] = ContextVar(
    "lingshu_expert_roster",
    default=None,
)


def bind_expert_roster() -> Token:
    """Bind an empty expert roster to the current mission."""
    return _EXPERT_ROSTER.set(set())


def reset_expert_roster(token: Token) -> None:
    _EXPERT_ROSTER.reset(token)


def interrupt_agent_tasks(tasks: set[asyncio.Task[Any]]) -> int:
    """向最外层 AgentScope 调用发出中断信号，绝不等待清理完成。

    对正在运行的 ``Agent.reply_stream``，官方方式是取消承载它的
    ``asyncio.Task``。嵌套 Agent 调用形成父子任务链时，只取消最外层任务，
    让取消信号沿 await 链自然传播；同时取消父、子 reply 会二次打断
    AgentScope 的未完成工具清理，使下一轮回复错误地变成空消息。

    HTTP 插话请求仍会在发出信号后立即返回。旧任务若没有父链元数据，则采用
    原有的全部取消策略，保证热更新/兼容调用不会失去中断能力。
    """
    active = tuple(task for task in tasks if not task.done())
    active_set = set(active)
    roots = tuple(
        task
        for task in active
        if getattr(task, "_lingshu_parent_agent_task", None) not in active_set
    )
    targets = roots or active
    for task in targets:
        task.cancel()
    return len(targets)


async def cancel_agent_tasks(tasks: set[asyncio.Task[Any]]) -> None:
    """中断并等待 Agent reply task 清理；仅用于任务终止/资源回收。"""
    active = tuple(task for task in tasks if not task.done())
    # 任务终止与运行时插话不同：此处不会再恢复 Agent，可以取消全部层级，
    # 确保失去父 await 链的孤立工具任务也被回收。
    for task in active:
        task.cancel()
    if active:
        try:
            await asyncio.wait_for(
                asyncio.gather(*active, return_exceptions=True),
                timeout=10,
            )
        except asyncio.TimeoutError:
            pass  # 强制推进，task 的 finally 会自行完成清理


async def run_interruptible_agent_reply(
    agent: Agent,
    inputs: Msg | list[Msg] | None = None,
    prefix: str = "",
    on_event: Callable[..., None] | None = None,
) -> Msg:
    """在独立任务中运行 Agent 回复，确保嵌套 Agent 可以被会话中断。

    Orchestrator 的 ``dispatch_attack`` 等函数会作为 AgentScope 的工具协程
    执行。仅取消其内部的 ``reply_stream`` task 时，部分 AgentScope 版本会
    继续等待尚未退出的工具协程，导致用户新情报无法及时生效。这里额外登记
    包住整个子 Agent 调用的 task；取消时可直接打断工具协程，并让
    ``CancelledError`` 回传到 Orchestrator 主循环。
    """
    agent_tasks = _AGENT_TASKS.get()
    parent_task = asyncio.current_task()
    task = asyncio.create_task(
        stream_agent_reply(agent, inputs, prefix, on_event),
        name=f"agent-call:{getattr(agent, 'name', 'unknown')}",
    )
    # 记录嵌套关系，供 interrupt_agent_tasks 只中断最外层调用。父任务只有
    # 同属本会话注册表时才参与层级判断，run_mission/API 自身不纳入其中。
    task._lingshu_parent_agent_task = (
        parent_task if agent_tasks is not None and parent_task in agent_tasks else None
    )
    if agent_tasks is not None:
        agent_tasks.add(task)
    try:
        return await task
    finally:
        if agent_tasks is not None:
            agent_tasks.discard(task)


async def stream_agent_reply(
    agent: Agent,
    inputs: Msg | list[Msg] | None = None,
    prefix: str = "",
    on_event: Callable[..., None] | None = None,
) -> Msg:
    """调用 agent 并流式输出到控制台，返回最终 Msg。

    Args:
        agent: 要调用的 Agent。
        inputs: 输入消息。
        prefix: 每个文本块起始行的前缀标签，如 "[Brain] "（仅打印一次）。
        on_event: 可选回调 (event_type, payload) → None，用于 Web SSE 推送。

    Returns:
        agent.reply() 返回的最终 Msg。
    """
    final_msg: Msg | None = None
    interrupted_reply_seen = False
    agent_name = agent.name if hasattr(agent, "name") else prefix.strip("[] ")

    def _emit(event_type: str, **payload: Any) -> None:
        if on_event is not None:
            payload.setdefault("agent", agent_name)
            on_event(event_type, **payload)

    roster = _EXPERT_ROSTER.get()
    if roster is not None and agent_name not in roster:
        roster.add(agent_name)
        _, separator, specialty = agent_name.partition(" - ")
        _emit(
            "expert_joined",
            expert_name=agent_name,
            specialty=specialty if separator else agent_name,
        )

    async def _consume_reply_stream() -> None:
        nonlocal final_msg, interrupted_reply_seen
        # 惰性发送：文本/思考块直到出现首个非空 delta 才发 _start。
        # 空块（模型无实际内容）不发 start/end，避免 web 端出现空气泡。
        text_started = False
        thinking_started = False

        def _finish_open_blocks(*, interrupted: bool = False) -> None:
            """终结已经展示的流式块，确保中断不会留下可被覆盖的临时消息。"""
            nonlocal text_started, thinking_started
            if text_started:
                print(flush=True)
                _emit("text_end", agent=agent_name, interrupted=interrupted)
                text_started = False
            if thinking_started:
                print(flush=True)
                _emit("thinking_end", agent=agent_name, interrupted=interrupted)
                thinking_started = False

        try:
            async for evt_or_msg in agent.reply_stream(
                inputs=inputs,
                yield_final_msg=True,
            ):
                if isinstance(evt_or_msg, Msg):
                    # 某些模型适配器不会在最终 Msg 前发送 BlockEnd。先封口，
                    # 后续 message 事件才能与刚完成的全文稳定去重。
                    _finish_open_blocks()
                    final_msg = evt_or_msg
                    if (
                        getattr(evt_or_msg, "finished_reason", None)
                        == ReplyFinishedReason.INTERRUPTED
                    ):
                        # reply_stream(yield_final_msg=True) 在部分 AgentScope
                        # 路径中会在中断消息后再产出一个空聚合 Msg。单独记住
                        # 中断标志，避免被后一个 Msg 覆盖。
                        interrupted_reply_seen = True
                    content = evt_or_msg.get_text_content() or ""
                    if content:
                        _emit("message", content=content)
                elif isinstance(evt_or_msg, TextBlockStartEvent):
                    # 防御异常事件序列：新块开始前先保留上一块的已有内容。
                    if text_started:
                        print(flush=True)
                        _emit("text_end", agent=agent_name)
                    text_started = False  # 重置，等待首个非空 delta
                elif isinstance(evt_or_msg, TextBlockDeltaEvent):
                    delta = evt_or_msg.delta or ""
                    if not text_started and not delta.strip():
                        continue  # 块开头纯空白：不建气泡
                    if not text_started:
                        text_started = True
                        print(f"{prefix}", end="", flush=True)
                        _emit("text_start", agent=agent_name)
                    if delta:
                        print(delta, end="", flush=True)
                        _emit("text_delta", delta=delta, agent=agent_name)
                elif isinstance(evt_or_msg, TextBlockEndEvent):
                    if text_started:
                        print(flush=True)
                        _emit("text_end", agent=agent_name)
                    text_started = False
                elif isinstance(evt_or_msg, ThinkingBlockStartEvent):
                    if thinking_started:
                        print(flush=True)
                        _emit("thinking_end", agent=agent_name)
                    thinking_started = False  # 重置，等待首个非空思考 delta
                elif isinstance(evt_or_msg, ThinkingBlockDeltaEvent):
                    delta = _clean_thinking_delta(evt_or_msg.delta)
                    if not delta:
                        continue  # 空 <think> 标签残留/纯空白：不打印、不广播、不入库
                    if not thinking_started:
                        thinking_started = True
                        print(f"{prefix}🧠 ", end="", flush=True)
                        _emit("thinking_start", agent=agent_name)
                    print(delta, end="", flush=True)
                    _emit("thinking_delta", delta=delta, agent=agent_name)
                elif isinstance(evt_or_msg, ThinkingBlockEndEvent):
                    if thinking_started:
                        print(flush=True)
                        _emit("thinking_end", agent=agent_name)
                    thinking_started = False
                elif isinstance(evt_or_msg, ToolCallStartEvent):
                    print(f"\n{prefix}🔧 [{evt_or_msg.tool_call_name}] ", end="", flush=True)
                    _emit("tool_call_start",
                          agent=agent_name,
                          tool_call_id=evt_or_msg.tool_call_id,
                          tool_name=evt_or_msg.tool_call_name)
                elif isinstance(evt_or_msg, ToolCallDeltaEvent):
                    print(evt_or_msg.delta, end="", flush=True)
                    _emit("tool_call_delta",
                          agent=agent_name,
                          tool_call_id=evt_or_msg.tool_call_id,
                          delta=evt_or_msg.delta)
                elif isinstance(evt_or_msg, ToolCallEndEvent):
                    print("", flush=True)
                    # AgentScope 版本/工具类型不同，结果字段可能叫 output/result/content；
                    # 有则一并转发给 WebUI 的工具审计面板，缺失时仍保留完整参数。
                    tool_output = (
                        getattr(evt_or_msg, "output", None)
                        or getattr(evt_or_msg, "result", None)
                        or getattr(evt_or_msg, "content", None)
                        or ""
                    )
                    _emit("tool_call_end",
                          agent=agent_name,
                          tool_call_id=evt_or_msg.tool_call_id,
                          tool_name=getattr(evt_or_msg, "tool_call_name", ""),
                          output=str(tool_output))
        finally:
            # 官方中断是 task.cancel()。无论取消落在哪个 await 点，都先把已
            # 展示的部分内容固化为 end 事件，避免 UI/DB 只剩悬挂快照。
            _finish_open_blocks(interrupted=asyncio.current_task().cancelling() > 0)

    # 官方中断机制要求 cancel 直接承载 reply_stream 的 task。
    parent_task = asyncio.current_task()
    reply_task = asyncio.create_task(
        _consume_reply_stream(),
        name=f"agent-reply:{agent_name}",
    )
    agent_tasks = _AGENT_TASKS.get()
    reply_task._lingshu_parent_agent_task = (
        parent_task if agent_tasks is not None and parent_task in agent_tasks else None
    )
    if agent_tasks is not None:
        agent_tasks.add(reply_task)
    try:
        await reply_task
    except asyncio.CancelledError:
        reply_task.cancel()
        await asyncio.gather(reply_task, return_exceptions=True)
        raise
    finally:
        if agent_tasks is not None:
            agent_tasks.discard(reply_task)

    if final_msg is None:
        raise RuntimeError("Agent did not produce a final message.")
    # AgentScope 处理中断后不会抛 CancelledError，而是以 finished_reason=
    # INTERRUPTED 的最终消息正常返回（并发工具路径会吞掉取消）。此处将其
    # 还原为 CancelledError，使中断信号沿 dispatch_* → Orchestrator 主循环
    # → run_mission 传播，触发统一的后台进程清理与 cancelled 终态收敛。
    if (
        interrupted_reply_seen
        or getattr(final_msg, "finished_reason", None)
        == ReplyFinishedReason.INTERRUPTED
    ):
        raise asyncio.CancelledError()
    # 超迭代（EXCEED_MAX_ITERS）同样以最终消息正常返回，但其文本是
    # "The maximum reasoning-acting iterations are exceeded." 这类占位串，
    # 不应被当成有效报告。此处抛出 AgentMaxIterationsError，由 dispatch_*
    # / 主循环统一收敛（P1 熔断）。
    if getattr(final_msg, "finished_reason", None) == ReplyFinishedReason.EXCEED_MAX_ITERS:
        raise AgentMaxIterationsError(
            f"Agent {agent_name} 达到最大推理迭代次数（max_iters），本轮未产出有效结果"
        )
    return final_msg


class AllowedFunctionTool(FunctionTool):
    """允许执行已在函数内部完成参数和范围校验的工具。"""

    async def check_permissions(self, *_args, **_kwargs) -> PermissionDecision:
        return PermissionDecision(
            behavior=PermissionBehavior.ALLOW,
            message="已通过灵枢内部范围校验",
        )


_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_EMPTY_TAG = re.compile(r"^\s*</?(?:think)>\s*$", re.IGNORECASE)


def _clean_thinking_delta(delta: str) -> str:
    """清洗思考流里的特殊标签残留（llama.cpp/Qwen 偶发把 <think> 当内容输出）。

    仅当整段 delta 就是空 <think>/</think> 标签或纯空白时清空，正常思考不受影响。
    """
    if not delta:
        return delta
    if _EMPTY_TAG.fullmatch(delta) or not delta.strip():
        return ""
    return delta
_NETWORK_TOOL_NAMES = frozenset({
    "nmap", "masscan", "amass", "subfinder", "theharvester", "dnsrecon",
    "feroxbuster", "curl", "wget", "whatweb", "nikto", "gobuster", "dirb",
    "ffuf", "wfuzz", "wpscan", "joomscan", "sqlmap", "commix", "hydra",
    "medusa", "netexec", "crackmapexec", "evil-winrm", "certipy",
    "certipy-ad", "bloodhound-python", "responder", "tcpdump", "tshark",
    "bettercap", "aircrack-ng", "nc", "netcat", "ssh", "scp", "socat",
    "msfconsole",
})
_DENIED = [
    re.compile(r"\brm\s+-[^\n]*r[^\n]*f\s+/(?:\s|$)"),
    re.compile(r"\b(?:reboot|shutdown|poweroff|halt)\b", re.IGNORECASE),
    re.compile(r"\bmkfs(?:\.|\s)", re.IGNORECASE),
    re.compile(r"\bdd\s+[^\n]*\bof=/dev/", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*;\s*\}\s*;\s*:"),
]


def _parse_target(target: str) -> tuple[str | None, str | None]:
    """从 target 字符串中提取 IP 和期望在命令中出现的标识。

    Returns:
        (ip, identifier): ip 为纯 IP 或 None（hostname），identifier 为命令中必须包含的字符串。
    """
    # 尝试解析为 IP:port 或纯 IP
    if ":" in target:
        host_part, _, port_part = target.partition(":")
        try:
            ip = str(ipaddress.ip_address(host_part))
            # 命令只需包含 IP 或 host_part，不需要 port
            return ip, host_part
        except ValueError:
            pass  # 不是有效 IP，当做 hostname:port
    else:
        try:
            return str(ipaddress.ip_address(target)), target
        except ValueError:
            pass
    # hostname 或无端口的目标
    return None, target


def _command_invokes_network_tool(command: str) -> bool:
    """按 shell 词法识别每个命令段的网络工具，支持绝对路径和 sudo/env。

    这里只负责识别是否应触发目标存在性检查；实际执行仍由 scoped_shell，
    IP/域名范围继续交给 ScopeRegistry 判断。
    """
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        # 引号不闭合最终也无法由 shell 正常、安全执行，提前拒绝。
        raise ValueError("命令包含不完整的 shell 引号") from None

    for token in tokens:
        if token and all(char in ";&|" for char in token):
            continue
        # 扫描整个命令段而非只看第一个 token，可覆盖 sudo -u、env -i、
        # timeout --signal 等包装形式。少量保守误报优于范围校验绕过。
        if Path(token).name.lower() in _NETWORK_TOOL_NAMES:
            return True
    return False


def _validate_scoped_command(
    command: str,
    target: str,
    registry: ScopeRegistry | None = None,
) -> None:
    if not command.strip() or len(command) > 12000 or "\x00" in command:
        raise ValueError("命令为空、过长或包含非法字符")
    if any(pattern.search(command) for pattern in _DENIED):
        raise PermissionError("命令命中本机破坏性操作拦截规则")

    target_ip, target_id = _parse_target(target)

    # ── IP 白名单检查 ──
    # 优先使用 ScopeRegistry（语义级，支持动态扩容），
    # 无 registry 时回退到旧的静态 allowed_ips 集合（向后兼容）。
    if registry is not None:
        foreign_ips: set[str] = set()
        for candidate in _IPV4_RE.findall(command):
            try:
                normalized = str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
            # 原始工具 target 本身就是本轮已确认的授权输入。即使旧会话
            # 尚未持久化 authorized_scope，也不能把它误判为范围外 IP。
            if target_ip and normalized == target_ip:
                continue
            if not registry.is_ip_allowed(normalized):
                foreign_ips.add(normalized)
        if foreign_ips:
            raise PermissionError(
                f"命令包含授权范围外 IP: {', '.join(sorted(foreign_ips))}。"
                f"如需探测内网主机，请先由 Orchestrator 调用 request_scope_expansion 审核授权。"
            )
    else:
        allowed_ips = {"127.0.0.1", "0.0.0.0"}
        if target_ip:
            allowed_ips.add(target_ip)
        foreign_ips = set()
        for candidate in _IPV4_RE.findall(command):
            try:
                normalized = str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
            if normalized not in allowed_ips:
                foreign_ips.add(normalized)
        if foreign_ips:
            raise PermissionError(f"命令包含授权范围外 IP: {', '.join(sorted(foreign_ips))}")

    # ── 网络工具目标检查 ──
    if _command_invokes_network_tool(command):
        if target_id in command or target in command:
            return
        if registry is not None and registry.is_any_target_in_command(command):
            return
        raise PermissionError("网络命令必须显式包含本次授权目标")


async def _run_scoped_command(
    command: str,
    *,
    target: str,
    workdir: str,
    timeout: int,
    registry: ScopeRegistry | None = None,
    role: str = "",
    artifacts_root: Path | None = None,
    return_tail: int = 4000,
    seq: int = 1,
    tool_name: str = "scoped_shell",
    command_index: int | None = None,
) -> str:
    """执行单条受范围约束的命令 — scoped_shell 与 parallel_scoped_shell 共用执行体。

    Args:
        command: 要执行的 shell 命令；所有网络命令必须显式包含授权目标。
        target: 授权目标（用于命令范围校验）。
        workdir: 命令执行目录。
        timeout: 命令超时秒数。
        registry: 动态授权范围注册表（可选）。
        role: 调用方角色（recon/attack/...），用于 artifacts 子目录。
        artifacts_root: Workspace v2 根；提供时启用流式 artifacts。
        return_tail: v2 模式下返回值携带的尾部字节数。
        seq: artifacts 目录序号（tool-{seq:04d}）。
        tool_name: manifest 中记录的工具名（并行工具传 parallel_scoped_shell）。
        command_index: 并行工具的子命令序号；非 None 时写入 manifest 供审计。
    """
    _validate_scoped_command(command, target, registry)
    started_at = datetime.now(timezone.utc).astimezone().isoformat()

    # ── v2 模式：准备 artifacts 目录 ──
    tool_dir: Path | None = None
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    if artifacts_root is not None:
        tool_dir = artifacts_root / "artifacts" / (role or "agent") / f"tool-{seq:04d}"
        tool_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = tool_dir / "stdout.txt"
        stderr_path = tool_dir / "stderr.txt"

    proc = await asyncio.create_subprocess_shell(
        command,
        cwd=workdir,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    tracker = _PROCESS_TRACKER.get()
    if tracker is not None:
        tracker.register(proc.pid)

    timed_out = False
    cancelled = False
    try:
        if stdout_path is not None:
            # v2：流式落盘，内存只保留尾部与哈希
            out_size, err_size, out_tail, err_tail, out_sha, err_sha = (
                await asyncio.wait_for(
                    _stream_to_artifact(proc, stdout_path, stderr_path, return_tail),
                    timeout=timeout,
                )
            )
            stdout_text = out_tail
            stderr_text = err_tail
            # drain 完成后进程可能尚未被事件循环收割，显式等待退出码
            await proc.wait()
            finished_at = datetime.now(timezone.utc).astimezone().isoformat()
            returncode = proc.returncode
            manifest_entry: dict[str, Any] = {
                "timestamp": finished_at,
                "role": role or "agent",
                "tool": tool_name,
                "command": command,
                "started_at": started_at,
                "finished_at": finished_at,
                "returncode": returncode,
                "timed_out": False,
                "stdout": {
                    "path": f"artifacts/{role or 'agent'}/tool-{seq:04d}/stdout.txt",
                    "bytes": out_size,
                    "sha256": out_sha,
                },
                "stderr": {
                    "path": f"artifacts/{role or 'agent'}/tool-{seq:04d}/stderr.txt",
                    "bytes": err_size,
                    "sha256": err_sha,
                },
            }
            if command_index is not None:
                manifest_entry["command_index"] = command_index
            # 追加 manifest 条目
            _append_manifest(artifacts_root, manifest_entry)
            relative_out = f"artifacts/{role or 'agent'}/tool-{seq:04d}/stdout.txt"
            return (
                f"<returncode>{returncode}</returncode>"
                f"<stdout_artifact>{relative_out} bytes={out_size} sha256={out_sha[:16]}</stdout_artifact>"
                f"<stdout_tail>{stdout_text}</stdout_tail>"
                f"<stderr_tail>{stderr_text}</stderr_tail>"
            )
        # ── legacy：内存截断（向后兼容） ──
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        out = stdout.decode("utf-8", errors="replace")[-20000:]
        err = stderr.decode("utf-8", errors="replace")[-6000:]
        return (
            f"<returncode>{proc.returncode}</returncode>"
            f"<stdout>{out}</stdout><stderr>{err}</stderr>"
        )
    except asyncio.TimeoutError:
        timed_out = True
        if tracker is not None:
            await tracker.terminate_group(proc.pid)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
        await proc.wait()
        if artifacts_root is not None and stdout_path is not None:
            # 超时后把剩余输出收尾落盘
            try:
                out_size, err_size, out_tail, err_tail, out_sha, err_sha = (
                    await _stream_to_artifact(proc, stdout_path, stderr_path, return_tail)
                )
            except Exception:  # noqa: BLE001
                out_size = err_size = 0
                out_tail = err_tail = out_sha = err_sha = ""
            timeout_entry: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).astimezone().isoformat(),
                "role": role or "agent",
                "tool": tool_name,
                "command": command,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).astimezone().isoformat(),
                "returncode": -1,
                "timed_out": True,
                "stdout": {
                    "path": f"artifacts/{role or 'agent'}/tool-{seq:04d}/stdout.txt",
                    "bytes": out_size,
                    "sha256": out_sha,
                },
                "stderr": {
                    "path": f"artifacts/{role or 'agent'}/tool-{seq:04d}/stderr.txt",
                    "bytes": err_size,
                    "sha256": err_sha,
                },
            }
            if command_index is not None:
                timeout_entry["command_index"] = command_index
            _append_manifest(artifacts_root, timeout_entry)
            return (
                f"<returncode>-1</returncode>"
                f"<stdout_artifact>artifacts/{role or 'agent'}/tool-{seq:04d}/stdout.txt"
                f" bytes={out_size} sha256={out_sha[:16] if out_sha else ''}</stdout_artifact>"
                f"<stderr>命令超过 {timeout} 秒，已终止（完整输出已落盘）</stderr>"
                f"<stdout_tail>{out_tail}</stdout_tail>"
            )
        return f"<returncode>-1</returncode><stderr>命令超过 {timeout} 秒，已终止</stderr>"
    except asyncio.CancelledError:
        cancelled = True
        if tracker is not None:
            await tracker.terminate_group(proc.pid)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
        await proc.wait()
        raise
    finally:
        if cancelled and artifacts_root is not None:
            # 取消时尽量留痕
            try:
                await _stream_to_artifact(proc, stdout_path, stderr_path, return_tail)
            except Exception:  # noqa: BLE001
                pass


def create_scoped_shell_tool(
    target: str,
    cwd: str | Path,
    timeout: int,
    registry: ScopeRegistry | None = None,
    *,
    role: str = "",
    artifact_root: str | Path | None = None,
    return_tail: int = 4000,
) -> AllowedFunctionTool:
    """创建仅允许触达指定目标的 Shell 工具。

    Args:
        target: 授权目标（用于命令范围校验）。
        cwd: 命令执行目录。
        timeout: 命令超时秒数。
        registry: 动态授权范围注册表（可选）。
        role: 调用方角色（recon/attack/...），用于 artifacts 子目录。
        artifact_root: Workspace v2 根（WorkDir/v2/sessions/...）。提供时
            启用流式 artifacts：stdout/stderr 直接写入
            ``artifacts/{role}/tool-{seq}/``，返回值只含尾部+摘要+相对引用，
            不再硬截断 20KB/6KB；同时维护 ``artifacts/manifest.jsonl``。
            为 None 时保持旧行为（内存截断，向后兼容）。
        return_tail: v2 模式下返回值携带的尾部字节数。
    """
    workdir = str(Path(cwd).resolve())
    artifacts_root = Path(artifact_root).resolve() if artifact_root is not None else None
    seq_counter = itertools.count(1)


    async def scoped_shell(command: str) -> str:
        """在 Kali 中执行受范围约束的命令。

        Args:
            command: 要执行的 shell 命令；所有网络命令必须显式包含授权目标。
        """
        return await _run_scoped_command(
            command,
            target=target,
            workdir=workdir,
            timeout=timeout,
            registry=registry,
            role=role,
            artifacts_root=artifacts_root,
            return_tail=return_tail,
            seq=next(seq_counter),
        )

    return AllowedFunctionTool(
        scoped_shell,
        name="scoped_shell",
        description="在 Kali 中执行仅限当前授权目标的命令，并返回退出码、标准输出和错误。",
        is_concurrency_safe=False,
    )


def create_parallel_scoped_shell_tool(
    target: str,
    cwd: str | Path,
    timeout: int,
    registry: ScopeRegistry | None = None,
    *,
    role: str = "",
    artifact_root: str | Path | None = None,
    return_tail: int = 4000,
    max_commands: int = 8,
) -> AllowedFunctionTool:
    """创建可并行执行多条只读命令的受限 Shell 工具。

    与 scoped_shell 共用同一执行体（范围校验 / artifacts 落盘 / 超时 / 取消清理），
    差异点：
    - 先对全部命令做范围校验：任一命令越界则整体拒绝，不启动任何子进程；
    - 互不依赖的命令用 ``asyncio.gather`` 并发执行，各自独立超时与 artifacts 目录；
    - manifest 每条记录 ``tool=parallel_scoped_shell`` 与 ``command_index`` 供审计。

    仅用于互不依赖的只读探测（端口/服务指纹、HTTP 头、目录枚举、file/strings 等）；
    写文件、利用 payload 等有共享状态的命令必须串行使用 scoped_shell。
    """
    workdir = str(Path(cwd).resolve())
    artifacts_root = Path(artifact_root).resolve() if artifact_root is not None else None
    seq_counter = itertools.count(1)

    async def parallel_scoped_shell(commands: list[str], per_command_timeout: int = 0) -> str:
        """并行执行多条互不依赖的受范围约束的只读命令。

        Args:
            commands: 互不依赖的命令列表（1~{max_commands} 条）；所有网络命令必须
                显式包含授权目标。任一命令越界时整体拒绝，不执行任何命令。
            per_command_timeout: 单条命令超时秒数；0 表示使用工具默认超时。
        """
        if not commands:
            return "<parallel>空命令列表，未执行任何命令</parallel>"
        if len(commands) > max_commands:
            return (
                f"[拒绝] 并行命令数 {len(commands)} 超过上限 {max_commands}，"
                "请拆分成多批执行"
            )
        # 先全量校验：任一越界整体拒绝，确保不启动任何子进程
        for index, cmd in enumerate(commands):
            _validate_scoped_command(cmd, target, registry)
        # 单条超时不高于工具级超时，避免一条慢命令把整体拖到工具超时
        effective_timeout = per_command_timeout if per_command_timeout > 0 else timeout
        per_timeout = min(int(effective_timeout), int(timeout))
        results = await asyncio.gather(
            *[
                _run_scoped_command(
                    cmd,
                    target=target,
                    workdir=workdir,
                    timeout=per_timeout,
                    registry=registry,
                    role=role,
                    artifacts_root=artifacts_root,
                    return_tail=return_tail,
                    seq=next(seq_counter),
                    tool_name="parallel_scoped_shell",
                    command_index=index,
                )
                for index, cmd in enumerate(commands)
            ],
            return_exceptions=True,
        )
        blocks: list[str] = []
        for index, (cmd, result) in enumerate(zip(commands, results)):
            if isinstance(result, Exception):
                blocks.append(
                    f"\n<cmd-{index} command={cmd[:120]!r}>\n"
                    f"<error>{type(result).__name__}: {result}</error>\n"
                    f"</cmd-{index}>"
                )
            else:
                blocks.append(
                    f"\n<cmd-{index} command={cmd[:120]!r}>\n{result}\n</cmd-{index}>"
                )
        return "<parallel>" + "".join(blocks) + "\n</parallel>"

    return AllowedFunctionTool(
        parallel_scoped_shell,
        name="parallel_scoped_shell",
        description=(
            "并行执行多条互不依赖的只读命令（先全量范围校验，任一越界整体拒绝），"
            "返回按 <cmd-N> 分节的合并结果；写文件/利用类命令请使用 scoped_shell 串行执行。"
        ),
        is_concurrency_safe=False,
    )


async def _stream_to_artifact(
    proc: asyncio.subprocess.Process,
    stdout_path: Path,
    stderr_path: Path,
    tail_bytes: int,
) -> tuple[int, int, str, str, str, str]:
    """把子进程 stdout/stderr 流式写入文件，返回 (out_size, err_size,
    out_tail_text, err_tail_text, out_sha256, err_sha256)。

    边写边维护 SHA-256 与有限尾部，避免把完整输出加载进内存。
    """
    out_hasher = hashlib.sha256()
    err_hasher = hashlib.sha256()
    out_tail = bytearray()
    err_tail = bytearray()
    out_size = 0
    err_size = 0

    async def _drain(stream, handle, hasher, tail, size_holder: list[int]) -> None:
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            handle.write(chunk)
            hasher.update(chunk)
            size_holder[0] += len(chunk)
            tail.extend(chunk)
            if len(tail) > tail_bytes:
                del tail[: len(tail) - tail_bytes]

    with stdout_path.open("wb") as out_f, stderr_path.open("wb") as err_f:
        size_out: list[int] = [0]
        size_err: list[int] = [0]
        tasks = [
            asyncio.create_task(_drain(proc.stdout, out_f, out_hasher, out_tail, size_out)),
            asyncio.create_task(_drain(proc.stderr, err_f, err_hasher, err_tail, size_err)),
        ]
        await asyncio.gather(*tasks)
    return (
        size_out[0],
        size_err[0],
        bytes(out_tail).decode("utf-8", errors="replace"),
        bytes(err_tail).decode("utf-8", errors="replace"),
        out_hasher.hexdigest(),
        err_hasher.hexdigest(),
    )


def _append_manifest(artifacts_root: Path, entry: dict[str, Any]) -> None:
    """向 artifacts/manifest.jsonl 追加一条记录（原子追加）。"""
    manifest_path = artifacts_root / "artifacts" / "manifest.jsonl"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with manifest_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # manifest 写入失败不阻断工具执行
