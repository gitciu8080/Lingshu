"""逆向分析 Agent — 通过 IDA MCP 对二进制文件执行反编译分析。

流程：
  1. idalib-mcp 通过 stdio 启动并连接
  2. 调用 idb_open 打开二进制并取得 database 会话 ID
  3. 所有分析工具携带 database，完成后调用 idb_close
"""
from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from agentscope.mcp import MCPClient, StdioMCPConfig
from agentscope.message import UserMsg
from agentscope.tool import Toolkit

from agent.Attack import _build_skill_list
from Tools.IntelPwn import create_intelpwn_tool
from Tools.ScopeRegistry import ScopeRegistry
from Tools.tooling import AllowedFunctionTool, create_scoped_shell_tool, run_interruptible_agent_reply
from agent.experts import REVERSE_EXPERT

RESERVE_SYS_PROMPT = """你是二进制逆向分析专家（Reserve）。
你只能处理 Orchestrator 给出的单一授权目标，并且只使用提供的工具。

可用工具：
1. scoped_shell: 受限的本地命令执行工具。
2. ida_open_binary: 为原始二进制生成 IDA 数据库并打开，返回 database 会话 ID。
3. IDA_Tool: IDA 逆向工具集（survey_binary / decompile / list_funcs / xrefs_to 等）。
4. analysis: 委托 Analysis 专家独立研判。
5. intelpwn_analyze: IntelPwn 二进制静态漏洞分析工具。

工作流程（严格遵守顺序）：
1. 先调用 analysis 获取独立研判，确定分析重点。
2. 对文件先调用 intelpwn_analyze 获取保护机制和潜在漏洞概览。
3. 严禁手动启动 idat，也不要直接调用 IDA_Tool.idb_open。必须先调用
   ida_open_binary(input_path=二进制绝对路径)，并保存返回的 database 会话 ID。
4. 先调用 survey_binary 获取概览，再按需调用 decompile / analyze_function / xrefs_to。
   idb_open 之外的每个 IDA 分析工具都必须传入同一个 database。
5. 分析结束后调用 idb_close(database=..., save=false) 释放会话。
6. 只有证据充分时才用 scoped_shell 做验证。
7. 禁止拒绝服务、破坏数据、植入持久化、清除日志或扩大目标范围。
8. 你只返回结果，不改变任务状态，也不宣布整个任务完成。

**关键：分析完成后必须立即输出结构化报告并停止。严禁反复验证或继续调用工具。**

报告结构：已验证事实、失败尝试、证据、当前权限、发现的 Flag（如有）和建议下一步。"""


_IDA_DIR = Path("/home/kali/ida-pro-9.1")
_IDALIB_MCP = Path("/home/kali/.local/bin/idalib-mcp")
_IDA_READ_ONLY_TOOLS = [
    "server_health", "lookup_funcs", "int_convert", "list_funcs", "func_query",
    "list_globals", "entity_query", "imports", "imports_query", "find_regex",
    "search_text", "decompile", "disasm", "func_profile", "analyze_batch",
    "xrefs_to", "xref_query", "xrefs_to_field", "callees", "find_bytes",
    "basic_blocks", "find", "insn_query", "export_funcs", "callgraph",
    "get_bytes", "get_int", "get_string", "get_global_value", "read_struct",
    "search_structs", "type_query", "type_inspect", "stack_frame",
    "survey_binary", "analyze_function", "analyze_component", "trace_data_flow",
    "make_signature", "make_signature_for_function", "make_signature_for_range",
    "find_xref_signatures", "idb_open", "idb_list", "idb_close",
]


async def create_reverse_agent(
    model,
    analysis_agent: Agent,
    target: str,
    project_dir: str | Path,
    timeout: int,
    category_decision: dict | None = None,
    scope_registry: ScopeRegistry | None = None,
    max_iters: int = 20,
    event_callback=None,
) -> Agent:
    async def analysis(service_info: str) -> str:
        """委托 Analysis 专家研判真实证据。

        Args:
            service_info: Recon 得到的文件信息和初步结论。
        """
        result = await run_interruptible_agent_reply(
            analysis_agent,
            UserMsg(name="Reserve", content=service_info),
            prefix="[Analysis] ",
            on_event=event_callback,
        )
        return result.get_text_content() or "[Analysis] 未返回文本结果"

    skill_list = _build_skill_list(category_decision, project_dir)

    if not _IDALIB_MCP.is_file():
        raise RuntimeError(f"IDA MCP 启动器不存在: {_IDALIB_MCP}")
    if not _IDA_DIR.is_dir():
        raise RuntimeError(f"IDA 安装目录不存在: {_IDA_DIR}")

    ida_mcp = MCPClient(
        name="IDA_Tool",
        is_stateful=True,
        mcp_config=StdioMCPConfig(
            command=str(_IDALIB_MCP),
            args=["--stdio"],
            cwd=project_dir,
            env={**os.environ, "IDADIR": str(_IDA_DIR)},
        ),
        enable_tools=_IDA_READ_ONLY_TOOLS,
        execution_timeout=max(float(timeout), 120.0),
    )
    try:
        await asyncio.wait_for(ida_mcp.connect(), timeout=30.0)
        ida_tools = await ida_mcp.list_tools()
    except Exception as exc:
        await ida_mcp.close()
        raise RuntimeError(f"IDA MCP 连接失败: {exc}") from exc

    # AgentScope 默认要求逐次批准 MCP；这里只暴露只读分析和会话生命周期工具。
    for tool in ida_tools:
        tool.is_read_only = True

    idb_open_tool = next(
        tool for tool in ida_tools if tool.name.endswith("__idb_open")
    )
    exposed_ida_tools = [
        tool for tool in ida_tools if not tool.name.endswith("__idb_open")
    ]

    async def ida_open_binary(input_path: str) -> str:
        """生成并打开 IDA 数据库，返回包含 database 会话 ID 的 JSON。

        Args:
            input_path: 本任务工作区内待分析二进制的绝对路径。
        """
        source = Path(input_path).expanduser().resolve()
        project_root = Path(project_dir).resolve()
        target_path = Path(target).expanduser().resolve()
        target_root = target_path if target_path.is_dir() else target_path.parent
        if not source.is_file():
            return f'{{"error":"待分析文件不存在: {source}"}}'
        if not (
            source.is_relative_to(project_root)
            or source.is_relative_to(target_root)
        ):
            return '{"error":"文件不在本任务授权工作区内"}'

        database_path = source
        if source.suffix.lower() not in {".i64", ".idb"}:
            stat = source.stat()
            cache_key = hashlib.sha256(
                f"{source}:{stat.st_size}:{stat.st_mtime_ns}".encode(),
            ).hexdigest()[:16]
            cache_dir = project_root / "WorkDir" / "ida_databases"
            cache_dir.mkdir(parents=True, exist_ok=True)
            database_path = cache_dir / f"{source.stem}-{cache_key}.i64"
            if not database_path.is_file():
                process = await asyncio.create_subprocess_exec(
                    str(_IDA_DIR / "idat"),
                    "-A",
                    "-B",
                    f"-o{database_path}",
                    str(source),
                    cwd=str(cache_dir),
                    env={**os.environ, "IDADIR": str(_IDA_DIR)},
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    _, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=max(float(timeout), 120.0),
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    return '{"error":"IDA 数据库生成超时"}'
                if process.returncode != 0 or not database_path.is_file():
                    error = stderr.decode("utf-8", errors="replace")[-1000:]
                    return f'{{"error":"IDA 数据库生成失败: {error}"}}'

        result = await idb_open_tool.call(
            input_path=str(database_path),
            mode="force_headless",
            run_auto_analysis=True,
            build_caches=True,
            init_hexrays=True,
        )
        return "\n".join(
            str(getattr(block, "text", block))
            for block in result.content
        )

    toolkit = Toolkit(
        tools=[
            AllowedFunctionTool(analysis, is_read_only=True),
            create_intelpwn_tool(timeout),
            create_scoped_shell_tool(target, project_dir, timeout, registry=scope_registry),
            AllowedFunctionTool(ida_open_binary, is_read_only=True),
            *exposed_ida_tools,
        ],
        skills_or_loaders=skill_list,
    )
    agent = Agent(
        name=REVERSE_EXPERT,
        system_prompt=RESERVE_SYS_PROMPT,
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
    )
    agent._ida_mcp_client = ida_mcp
    return agent


async def close_reverse_agent(agent: Agent | None) -> None:
    """关闭任务持有的 IDA MCP supervisor 与 worker。"""
    client = getattr(agent, "_ida_mcp_client", None) if agent is not None else None
    if client is not None:
        await client.close()
