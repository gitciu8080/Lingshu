"""AgentScope 2.0 工具适配与目标范围约束。"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import signal
from collections.abc import Callable
from contextvars import ContextVar, Token
from pathlib import Path
from typing import Any, TYPE_CHECKING

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
from agentscope.message import Msg
from agentscope.permission import PermissionBehavior, PermissionDecision
from agentscope.types import ReplyFinishedReason
from agentscope.tool import FunctionTool


class AgentMaxIterationsError(RuntimeError):
    """Agent 触发 ReAct 超迭代（ReplyFinishedReason.EXCEED_MAX_ITERS）异常。

    由 stream_agent_reply 在检测到最终消息 finished_reason 为
    EXCEED_MAX_ITERS 时抛出，供调用方将"超迭代"收敛为可恢复事件，
    而不是把 AgentScope 的固定文本当正常结果。
    """


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


async def cancel_agent_tasks(tasks: set[asyncio.Task[Any]]) -> None:
    """按 AgentScope 官方中断方式取消承载 reply_stream 的 task。"""
    active = tuple(task for task in tasks if not task.done())
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
    agent_name = agent.name if hasattr(agent, "name") else prefix.strip("[] ")

    def _emit(event_type: str, **payload: Any) -> None:
        if on_event is not None:
            payload.setdefault("agent", agent_name)
            on_event(event_type, **payload)

    async def _consume_reply_stream() -> None:
        nonlocal final_msg
        # 惰性发送：文本/思考块直到出现首个非空 delta 才发 _start。
        # 空块（模型无实际内容）不发 start/end，避免 web 端出现空气泡。
        text_started = False
        thinking_started = False

        async for evt_or_msg in agent.reply_stream(
            inputs=inputs,
            yield_final_msg=True,
        ):
            if isinstance(evt_or_msg, Msg):
                final_msg = evt_or_msg
                content = evt_or_msg.get_text_content() or ""
                if content:
                    _emit("message", content=content)
            elif isinstance(evt_or_msg, TextBlockStartEvent):
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
                _emit("tool_call_end",
                      agent=agent_name,
                      tool_call_id=evt_or_msg.tool_call_id,
                      tool_name=getattr(evt_or_msg, "tool_call_name", ""))

    # 官方中断机制要求 cancel 直接承载 reply_stream 的 task。
    reply_task = asyncio.create_task(
        _consume_reply_stream(),
        name=f"agent-reply:{agent_name}",
    )
    agent_tasks = _AGENT_TASKS.get()
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
    if getattr(final_msg, "finished_reason", None) == ReplyFinishedReason.INTERRUPTED:
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
_NETWORK_TOOLS = re.compile(
    r"(?:^|[;&|]\s*)(?:sudo\s+)?(?:nmap|curl|wget|whatweb|nikto|gobuster|dirb|"
    r"ffuf|sqlmap|hydra|nc|netcat|ssh|scp|msfconsole)\b",
    re.IGNORECASE,
)
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
    if _NETWORK_TOOLS.search(command):
        if target_id in command or target in command:
            return
        if registry is not None and registry.is_any_target_in_command(command):
            return
        raise PermissionError("网络命令必须显式包含本次授权目标")


def create_scoped_shell_tool(
    target: str,
    cwd: str | Path,
    timeout: int,
    registry: ScopeRegistry | None = None,
) -> AllowedFunctionTool:
    """创建仅允许触达指定目标的 Shell 工具。"""
    workdir = str(Path(cwd).resolve())

    async def scoped_shell(command: str) -> str:
        """在 Kali 中执行受范围约束的命令。

        Args:
            command: 要执行的 shell 命令；所有网络命令必须显式包含授权目标。
        """
        _validate_scoped_command(command, target, registry)
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
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            if tracker is not None:
                await tracker.terminate_group(proc.pid)
            else:
                os.killpg(proc.pid, signal.SIGKILL)
            await proc.wait()
            return f"<returncode>-1</returncode><stderr>命令超过 {timeout} 秒，已终止</stderr>"
        except asyncio.CancelledError:
            if tracker is not None:
                await tracker.terminate_group(proc.pid)
            else:
                os.killpg(proc.pid, signal.SIGKILL)
            await proc.wait()
            raise
        out = stdout.decode("utf-8", errors="replace")[-20000:]
        err = stderr.decode("utf-8", errors="replace")[-6000:]
        return (
            f"<returncode>{proc.returncode}</returncode>"
            f"<stdout>{out}</stdout><stderr>{err}</stderr>"
        )

    return AllowedFunctionTool(
        scoped_shell,
        name="scoped_shell",
        description="在 Kali 中执行仅限当前授权目标的命令，并返回退出码、标准输出和错误。",
        is_concurrency_safe=False,
    )
