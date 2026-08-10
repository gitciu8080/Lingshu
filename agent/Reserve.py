"""逆向分析 Agent — 通过 IDA MCP 对二进制文件执行反编译分析。

流程：
  1. scoped_shell 启动 IDA Text 模式（idat），插件自动在 13337 端口起 MCP 服务
  2. 通过 HttpMCPConfig 连接后端，调用 decompile / list_funcs / list_strings 等工具
  3. 返回反编译报告和 Flag 给 Orchestrator
"""
from __future__ import annotations

from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from agentscope.mcp import MCPClient, StdioMCPConfig
from agentscope.message import UserMsg
from agentscope.tool import Toolkit

from agent.Attack import _build_skill_list
from Tools.IntelPwn import create_intelpwn_tool
from Tools.ScopeRegistry import ScopeRegistry
from Tools.tooling import AllowedFunctionTool, create_scoped_shell_tool, stream_agent_reply

RESERVE_SYS_PROMPT = """你是二进制逆向分析专家（Reserve）。
你只能处理 Orchestrator 给出的单一授权目标，并且只使用提供的工具。

可用工具：
1. scoped_shell: 本地命令执行（用于启动 IDA、文件解压等）。
2. ida_mcp: IDA 逆向工具集（decompile / list_funcs / list_strings / xrefs_to 等）。
3. analysis: 委托 Analysis 专家独立研判。
4. intelpwn_analyze: IntelPwn 二进制静态漏洞分析工具。

工作流程（严格遵守顺序）：
1. 先调用 analysis 获取独立研判，确定分析重点。
2. 对文件先调用 intelpwn_analyze 获取保护机制和潜在漏洞概览。
3. 用 scoped_shell 执行：
      /home/kali/ida-pro-9.1/idat {exe_path}
    等待分析完成后 ida_mcp 可连接。
4. 调用 ida_mcp 工具获取反编译结果、字符串、交叉引用等信息。
    （idalib-mcp 已通过 stdio 自动管理进程，无需手动启动 IDA）
5. 只有证据充分时才用 scoped_shell 做验证。
6. 禁止拒绝服务、破坏数据、植入持久化、清除日志或扩大目标范围。
7. 你只返回结果，不改变任务状态，也不宣布整个任务完成。

**关键：分析完成后必须立即输出结构化报告并停止。严禁反复验证或继续调用工具。**

报告结构：已验证事实、失败尝试、证据、当前权限、发现的 Flag（如有）和建议下一步。"""


async def create_reverse_agent(
    model,
    analysis_agent: Agent,
    target: str,
    project_dir: str | Path,
    timeout: int,
    category_decision: dict | None = None,
    scope_registry: ScopeRegistry | None = None,
) -> Agent:
    async def analysis(service_info: str) -> str:
        """委托 Analysis 专家研判真实证据。

        Args:
            service_info: Recon 得到的文件信息和初步结论。
        """
        result = await stream_agent_reply(
            analysis_agent,
            UserMsg(name="Reserve", content=service_info),
            prefix="[Analysis] ",
        )
        return result.get_text_content() or "[Analysis] 未返回文本结果"

    skill_list = _build_skill_list(category_decision, project_dir)

    ida_mcp = MCPClient(
        name="IDA_Tool",
        is_stateful=True,
        mcp_config=StdioMCPConfig(
            command="idalib-mcp",
            args=["--stdio"],
        ),
    )
    await ida_mcp.connect()

    toolkit = Toolkit(
        tools=[
            AllowedFunctionTool(analysis, is_read_only=True),
            create_intelpwn_tool(timeout),
            create_scoped_shell_tool(target, project_dir, timeout, registry=scope_registry),
        ],
        skills_or_loaders=skill_list,
        mcps=[ida_mcp],
    )
    return Agent(
        name="Reserve",
        system_prompt=RESERVE_SYS_PROMPT,
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=20),
    )
