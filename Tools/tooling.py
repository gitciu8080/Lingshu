"""AgentScope 2.0 工具适配与目标范围约束。"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from collections.abc import Callable
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
from agentscope.tool import FunctionTool


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

    async for evt_or_msg in agent._reply(inputs=inputs):  # noqa: SLF001
        if isinstance(evt_or_msg, Msg):
            final_msg = evt_or_msg
            _emit("message", content=evt_or_msg.get_text_content() or "")
        elif isinstance(evt_or_msg, TextBlockStartEvent):
            print(f"{prefix}", end="", flush=True)
            _emit("text_start", agent=agent_name)
        elif isinstance(evt_or_msg, TextBlockDeltaEvent):
            print(evt_or_msg.delta, end="", flush=True)
            _emit("text_delta", delta=evt_or_msg.delta, agent=agent_name)
        elif isinstance(evt_or_msg, TextBlockEndEvent):
            print(flush=True)
            _emit("text_end", agent=agent_name)
        elif isinstance(evt_or_msg, ThinkingBlockStartEvent):
            print(f"{prefix}🧠 ", end="", flush=True)
            _emit("thinking_start", agent=agent_name)
        elif isinstance(evt_or_msg, ThinkingBlockDeltaEvent):
            print(evt_or_msg.delta, end="", flush=True)
            _emit("thinking_delta", delta=evt_or_msg.delta, agent=agent_name)
        elif isinstance(evt_or_msg, ThinkingBlockEndEvent):
            print(flush=True)
            _emit("thinking_end", agent=agent_name)
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
                  tool_name=getattr(evt_or_msg, 'tool_call_name', ''))

    if final_msg is None:
        raise RuntimeError("Agent did not produce a final message.")
    return final_msg


class AllowedFunctionTool(FunctionTool):
    """允许执行已在函数内部完成参数和范围校验的工具。"""

    async def check_permissions(self, *_args, **_kwargs) -> PermissionDecision:
        return PermissionDecision(
            behavior=PermissionBehavior.ALLOW,
            message="已通过灵枢内部范围校验",
        )


_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
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
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return f"<returncode>-1</returncode><stderr>命令超过 {timeout} 秒，已终止</stderr>"
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
