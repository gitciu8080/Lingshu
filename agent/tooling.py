"""AgentScope 2.0 工具适配与目标范围约束。"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from pathlib import Path

from agentscope.agent import Agent
from agentscope.event import (
    TextBlockDeltaEvent,
    TextBlockEndEvent,
    TextBlockStartEvent,
    ThinkingBlockDeltaEvent,
    ThinkingBlockEndEvent,
    ThinkingBlockStartEvent,
)
from agentscope.message import Msg
from agentscope.permission import PermissionBehavior, PermissionDecision
from agentscope.tool import FunctionTool


async def stream_agent_reply(
    agent: Agent,
    inputs: Msg | list[Msg] | None = None,
    prefix: str = "",
) -> Msg:
    """调用 agent 并流式输出到控制台，返回最终 Msg。

    Args:
        agent: 要调用的 Agent。
        inputs: 输入消息。
        prefix: 每个文本块起始行的前缀标签，如 "[Brain] "（仅打印一次）。

    Returns:
        agent.reply() 返回的最终 Msg。
    """
    final_msg: Msg | None = None

    async for evt_or_msg in agent._reply(inputs=inputs):  # noqa: SLF001
        if isinstance(evt_or_msg, Msg):
            final_msg = evt_or_msg
        elif isinstance(evt_or_msg, TextBlockStartEvent):
            # 文本块开始时打印一次前缀
            print(f"{prefix}", end="", flush=True)
        elif isinstance(evt_or_msg, TextBlockDeltaEvent):
            print(evt_or_msg.delta, end="", flush=True)
        elif isinstance(evt_or_msg, TextBlockEndEvent):
            print(flush=True)
        elif isinstance(evt_or_msg, ThinkingBlockStartEvent):
            print(f"{prefix}🧠 ", end="", flush=True)
        elif isinstance(evt_or_msg, ThinkingBlockDeltaEvent):
            print(evt_or_msg.delta, end="", flush=True)
        elif isinstance(evt_or_msg, ThinkingBlockEndEvent):
            print(flush=True)

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


def _validate_scoped_command(command: str, target: str) -> None:
    if not command.strip() or len(command) > 12000 or "\x00" in command:
        raise ValueError("命令为空、过长或包含非法字符")
    if any(pattern.search(command) for pattern in _DENIED):
        raise PermissionError("命令命中本机破坏性操作拦截规则")

    foreign_ips: set[str] = set()
    for candidate in _IPV4_RE.findall(command):
        try:
            normalized = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if normalized not in {target, "127.0.0.1", "0.0.0.0"}:
            foreign_ips.add(normalized)
    if foreign_ips:
        raise PermissionError(f"命令包含授权范围外 IP: {', '.join(sorted(foreign_ips))}")
    if _NETWORK_TOOLS.search(command) and target not in command:
        raise PermissionError("网络命令必须显式包含本次授权目标")


def create_scoped_shell_tool(target: str, cwd: str | Path, timeout: int) -> AllowedFunctionTool:
    """创建仅允许触达指定目标的 Shell 工具。"""
    workdir = str(Path(cwd).resolve())

    async def scoped_shell(command: str) -> str:
        """在 Kali 中执行受范围约束的命令。

        Args:
            command: 要执行的 shell 命令；所有网络命令必须显式包含授权目标。
        """
        _validate_scoped_command(command, target)
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
