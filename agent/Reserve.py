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
import shutil
from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from agentscope.mcp import HttpMCPConfig, MCPClient, StdioMCPConfig
from agentscope.message import UserMsg

from agent.Attack import _build_skill_list
from Tools.IntelPwn import create_intelpwn_tool
from Tools.ScopeRegistry import ScopeRegistry
from Tools.tooling import AllowedFunctionTool, StrictJSONToolkit, create_scoped_shell_tool, run_interruptible_agent_reply
from agent.experts import REVERSE_EXPERT

RESERVE_SYS_PROMPT = """你是二进制逆向与动态调试专家（Reserve）。
你只能处理 Orchestrator 给出的单一授权目标，并且只使用提供的工具。

可用工具：
1. scoped_shell: 受限的本地命令执行工具。
2. ida_open_binary: 为原始二进制生成 IDA 数据库并打开，返回 database 会话 ID。
3. IDA_Tool: IDA 逆向工具集（survey_binary / decompile / list_funcs / xrefs_to 等）。
4. gdb_create_session / gdb_load_core: 在授权工作区内创建 GDB 动态调试或核心转储会话。
5. GDB_Tool: 多会话 GDB/MI 工具集（断点、运行、上下文、寄存器、内存、反汇编等）。
6. analysis: 委托 Analysis 专家独立研判。
7. intelpwn_analyze: IntelPwn 二进制静态漏洞分析工具。

工作流程（严格遵守顺序）：
1. 先调用 analysis 获取独立研判，确定分析重点。
2. 对文件先调用 intelpwn_analyze 获取保护机制和潜在漏洞概览。
3. 严禁手动启动 idat，也不要直接调用 IDA_Tool.idb_open。必须先调用
   ida_open_binary(input_path=二进制绝对路径)，并保存返回的 database 会话 ID。
4. 先调用 survey_binary 获取概览，再按需调用 decompile / analyze_function / xrefs_to。
   idb_open 之外的每个 IDA 分析工具都必须传入同一个 database。
5. 分析结束后调用 idb_close(database=..., save=false) 释放会话。
6. 需要动态验证时先调用 gdb_create_session，保存 session_id；先设置断点再运行，
   每个 GDB 工具都传入同一个 session_id，结束后必须调用 close_session。
7. GDB 工具返回结构化 JSON，必须检查 ok 字段；执行超时后先调用 interrupt，
   不得把超时误判为程序退出。
8. 只有证据充分时才用 scoped_shell 做验证。
9. 禁止拒绝服务、破坏数据、植入持久化、清除日志或扩大目标范围。
10. 你只返回结果，不改变任务状态，也不宣布整个任务完成。

**关键：分析完成后必须立即输出结构化报告并停止。严禁反复验证或继续调用工具。**

报告结构：已验证事实、失败尝试、证据、当前权限、发现的 Flag（如有）和建议下一步。"""


# IDA MCP 已容器化（见 /home/gitciu/ida/IDA-MCP-使用文档.md），宿主不再需要
# ida-pro 安装目录或 idalib-mcp 启动器；仅保留 GDB MCP 的宿主启动器探测。
_GDB_MCP_SOURCE = (
    "git+https://github.com/Mistyovo/gdb-multi-mcp"
    "@6e8048b8e933bbbae79b6da16fe69249f56fe30d"
)


def _find_gdb_mcp_executable() -> str | None:
    """跨平台探测 gdb-multi-mcp / uvx 可执行文件。

    搜索顺序（第一个命中即返回）：
      1. ``$LINGSHU_GDB_MCP_COMMAND`` 环境变量（绝对路径或命令名）
      2. ``gdb-multi-mcp`` 在 PATH 中（pip/uv tool/pipx 安装到系统）
      3. ``uvx`` 在 PATH 中
      4. 当前用户 ``~/.local/bin/`` 下的 gdb-multi-mcp / uvx
         （覆盖 ``uv tool install`` 在任意 Linux 用户下的默认位置）
      5. 常见备选路径（/home/kali, /opt 等历史部署位置）

    Returns:
        找到的可执行文件绝对路径，或 None。
    """
    # 1. 环境变量优先
    configured = os.getenv("LINGSHU_GDB_MCP_COMMAND", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        resolved = shutil.which(configured)
        if resolved:
            return resolved
        return None

    # 2-3. PATH 搜索
    for name in ("gdb-multi-mcp", "uvx"):
        resolved = shutil.which(name)
        if resolved:
            return resolved

    # 4. 当前用户 ~/.local/bin/
    user_bin = Path.home() / ".local" / "bin"
    for name in ("gdb-multi-mcp", "uvx"):
        candidate = user_bin / name
        if candidate.is_file():
            return str(candidate.resolve())

    # 5. conda 环境 bin/（CONDA_PREFIX 或 sys.executable 同级目录）
    import sys
    conda_dirs: list[Path] = []
    conda_prefix = os.getenv("CONDA_PREFIX")
    if conda_prefix:
        conda_dirs.append(Path(conda_prefix) / "bin")
    # sys.executable 同级 bin/（覆盖 conda run / systemd 指定解释器场景）
    py_bin = Path(sys.executable).parent
    if py_bin.name == "bin":
        conda_dirs.append(py_bin)
    # 常见 conda 环境名
    for env_name in ("agentscope", "lingshu", "base"):
        candidate = py_bin.parent.parent / "envs" / env_name / "bin"
        if candidate.is_dir():
            conda_dirs.append(candidate)
        # miniconda 默认路径
        candidate = Path.home() / "miniconda3" / "envs" / env_name / "bin"
        if candidate.is_dir():
            conda_dirs.append(candidate)
    for bin_dir in conda_dirs:
        for name in ("gdb-multi-mcp", "uvx"):
            candidate = bin_dir / name
            if candidate.is_file():
                return str(candidate.resolve())

    # 6. 历史部署路径（向后兼容）
    for base in ("/home/kali/.local/bin", "/opt/lingshu/bin"):
        for name in ("gdb-multi-mcp", "uvx"):
            candidate = Path(base) / name
            if candidate.is_file():
                return str(candidate.resolve())

    return None
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

# 这些入口可以越过灵枢的文件/网络范围控制，因此不直接暴露。受支持的本地
# 会话入口由下方 gdb_create_session / gdb_load_core 包装并执行路径校验。
_GDB_RESTRICTED_ENTRY_TOOLS = frozenset({
    "create_session",
    "attach",
    "load_core",
    "connect_target",
    "rr_record",
    "start_replay_session",
})


def _resolve_gdb_mcp_command() -> str:
    """返回 GDB MCP 启动器路径，支持多路径自动探测与环境变量覆盖。

    Raises:
        RuntimeError: 所有探测路径均未找到可执行文件时抛出，
            包含跨平台安装指引。
    """
    found = _find_gdb_mcp_executable()
    if found is not None:
        return found
    raise RuntimeError(
        "gdb-multi-mcp / uvx 均未找到。安装方式（任选其一）：\n"
        "  1. uv tool install --from "
        f'"{_GDB_MCP_SOURCE}" gdb-multi-mcp\n'
        "  2. pipx install --from "
        f'"{_GDB_MCP_SOURCE}" gdb-multi-mcp\n'
        "  3. 设置环境变量 LINGSHU_GDB_MCP_COMMAND 指向已安装路径\n"
        "  4. 安装 uv: curl -LsSf https://astral.sh/uv/install.sh | sh",
    )


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
    *,
    offloader=None,
    context_config=None,
    state=None,
    artifact_root: str | Path | None = None,
    executor: "Any | None" = None,
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

    # IDA MCP 已容器化部署：宿主直连 127.0.0.1:8745 的 SSE 端点，
    # 二进制经 /upload API 上传后自动分析（无需宿主 idat / idalib-mcp）。
    ida_base_url = os.getenv("LINGSHU_IDA_MCP_URL", "http://127.0.0.1:8745").rstrip("/")
    ida_mcp: MCPClient | None = None
    exposed_ida_tools: list = []
    _ida_allowed_tools = frozenset(_IDA_READ_ONLY_TOOLS)
    try:
        ida_mcp = MCPClient(
            name="IDA_Tool",
            is_stateful=False,
            mcp_config=HttpMCPConfig(url=f"{ida_base_url}/sse", timeout=30.0),
            # idle 状态下服务器仅暴露少量工具；完整 47 个工具在 POST /upload
            # 加载二进制后才可用。不设 enable_tools（idle 状态无法预过滤），
            # 改由 _ida_allowed_tools 在运行时过滤。
            execution_timeout=max(float(timeout), 120.0),
        )
        ida_tools = await ida_mcp.list_tools()
        for tool in ida_tools:
            tool.is_read_only = True
        exposed_ida_tools = [
            tool for tool in ida_tools
            if tool.name.rsplit("__", 1)[-1] in _ida_allowed_tools
            and not tool.name.endswith("__idb_open")
        ]
    except Exception as exc:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "IDA MCP 不可用（%s），Reserve 将在无 IDA 工具下降级运行: %s",
            ida_base_url, exc,
        )
        ida_mcp = None
        exposed_ida_tools = []

    # GDB MCP 连接：stdio 模式，宿主启动 gdb-multi-mcp 进程。
    gdb_mcp: MCPClient | None = None
    exposed_gdb_tools: list = []
    gdb_create_session_tool = None
    gdb_load_core_tool = None
    try:
        gdb_mcp_command = _resolve_gdb_mcp_command()
        gdb_mcp_args = [
            "--transport", "stdio",
            "--exec-timeout", str(max(1, int(timeout))),
        ]
        if Path(gdb_mcp_command).name == "uvx":
            gdb_mcp_args = [
                "--offline",
                "--from", _GDB_MCP_SOURCE,
                "gdb-multi-mcp",
                *gdb_mcp_args,
            ]

        gdb_mcp = MCPClient(
            name="GDB_Tool",
            is_stateful=True,
            mcp_config=StdioMCPConfig(
                command=gdb_mcp_command,
                args=gdb_mcp_args,
                cwd=project_dir,
                env={
                    **os.environ,
                    "FASTMCP_CHECK_FOR_UPDATES": "off",
                    "FASTMCP_SHOW_SERVER_BANNER": "false",
                },
            ),
            execution_timeout=max(float(timeout), 120.0),
        )
        async with asyncio.timeout(45.0):
            await gdb_mcp.connect()
        gdb_tools = await gdb_mcp.list_tools()

        def _gdb_tool(short_name: str):
            tool = next(
                (c for c in gdb_tools if c.name.endswith(f"__{short_name}")),
                None,
            )
            if tool is None:
                raise RuntimeError(f"GDB MCP 缺少必要工具: {short_name}")
            return tool

        gdb_create_session_tool = _gdb_tool("create_session")
        gdb_load_core_tool = _gdb_tool("load_core")
        exposed_gdb_tools = [
            tool for tool in gdb_tools
            if tool.name.rsplit("__", 1)[-1] not in _GDB_RESTRICTED_ENTRY_TOOLS
        ]
        for tool in exposed_gdb_tools:
            tool.is_read_only = True
    except Exception as exc:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "GDB MCP 不可用，Reserve 将在无 GDB 工具下降级运行: %s", exc,
        )
        if gdb_mcp is not None:
            try:
                await gdb_mcp.close()
            except RuntimeError:
                pass
        gdb_mcp = None
        exposed_gdb_tools = []
        gdb_create_session_tool = None
        gdb_load_core_tool = None

    project_root = Path(project_dir).resolve()
    target_path = Path(target).expanduser().resolve()
    authorized_file_roots: list[Path] = []
    if target_path.exists():
        authorized_file_roots.append(
            target_path if target_path.is_dir() else target_path.parent,
        )
    if artifact_root is not None:
        authorized_file_roots.append(Path(artifact_root).expanduser().resolve())

    def _authorized_file(value: str, label: str) -> Path:
        source = Path(value).expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(f"{label}不存在: {source}")
        if not any(source.is_relative_to(root) for root in authorized_file_roots):
            raise PermissionError(f"{label}不在本任务授权工作区内: {source}")
        return source

    def _tool_result_text(result) -> str:
        return "\n".join(
            str(getattr(block, "text", block))
            for block in result.content
        )

    async def gdb_create_session(
        program: str,
        args: list[str] | None = None,
        architecture: str | None = None,
    ) -> str:
        """为授权工作区内的本地二进制创建安全模式 GDB 会话。

        Args:
            program: 待调试二进制的绝对路径。
            args: 传给目标程序的参数列表。
            architecture: 可选 GDB 架构名，如 i386:x86-64。
        """
        if gdb_create_session_tool is None:
            return '{"error":"GDB MCP 不可用，无法创建调试会话"}'
        source = _authorized_file(program, "待调试文件")
        result = await gdb_create_session_tool.call(
            program=str(source),
            args=args,
            architecture=architecture,
            cwd=str(source.parent),
        )
        return _tool_result_text(result)

    async def gdb_load_core(executable: str, core: str) -> str:
        """加载授权工作区内的二进制和核心转储进行只读事后分析。

        Args:
            executable: 与核心转储匹配的二进制绝对路径。
            core: 核心转储文件绝对路径。
        """
        if gdb_load_core_tool is None:
            return '{"error":"GDB MCP 不可用，无法加载核心转储"}'
        executable_path = _authorized_file(executable, "可执行文件")
        core_path = _authorized_file(core, "核心转储")
        result = await gdb_load_core_tool.call(
            executable=str(executable_path),
            core=str(core_path),
        )
        return _tool_result_text(result)

    # 延迟绑定：ida_open_binary 需要在上传成功后向 toolkit 动态注册新工具，
    # 但 toolkit 在本函数返回前才创建。用可变容器传递引用。
    _toolkit_ref: list = [None]

    async def ida_open_binary(input_path: str) -> str:
        """上传二进制到容器化 IDA MCP 并等待分析完成，返回元数据 JSON。

        上传成功后自动刷新 IDA MCP 工具列表（idle → ready 后完整 47 个
        工具可用），并将新工具动态注册到 Agent toolkit。

        Args:
            input_path: 本任务工作区内待分析二进制的绝对路径。
        """
        if ida_mcp is None:
            return '{"error":"IDA MCP 不可用，无法执行逆向分析"}'
        try:
            source = _authorized_file(input_path, "待分析文件")
        except (FileNotFoundError, PermissionError) as exc:
            return f'{{"error":"{exc}"}}'

        # POST /upload（阻塞至自动分析完成），multipart 字段 file。
        # 上传成功即完成切库，随后 MCP 工具直接分析当前库。
        import aiohttp

        upload_url = f"{ida_base_url}/upload"
        async with aiohttp.ClientSession() as session:
            with source.open("rb") as fh:
                data = aiohttp.FormData()
                data.add_field("file", fh, filename=source.name)
                try:
                    async with session.post(
                        upload_url,
                        data=data,
                        timeout=aiohttp.ClientTimeout(
                            total=max(float(timeout), 600.0),
                        ),
                    ) as resp:
                        body = await resp.text()
                        if resp.status != 200:
                            return (
                                f'{{"error":"IDA 上传失败 HTTP {resp.status}: '
                                f'{body[:500]}"}}'
                            )
                except Exception as exc:  # noqa: BLE001
                    return f'{{"error":"IDA 上传异常: {exc}"}}'

        try:
            import json as _json

            meta = _json.loads(body)
            if not meta.get("ok"):
                return f'{{"error":"IDA 未就绪: {body[:500]}"}}'

            # ── 上传成功：刷新 IDA 工具列表并动态注册 ──
            # idle 状态下只有 1 个工具；上传后服务器暴露完整 47 个工具。
            # 通过 toolkit.add_tool() 将新工具注入 Agent，使其可被调用。
            try:
                refreshed = await ida_mcp.list_tools()
                existing_names: set[str] = set()
                if _toolkit_ref[0] is not None:
                    existing = await _toolkit_ref[0]._get_available_tools(None)
                    existing_names = set(existing.keys())
                added = 0
                for tool in refreshed:
                    short = tool.name.rsplit("__", 1)[-1]
                    if (
                        short in _ida_allowed_tools
                        and not tool.name.endswith("__idb_open")
                        and tool.name not in existing_names
                    ):
                        tool.is_read_only = True
                        if _toolkit_ref[0] is not None:
                            _toolkit_ref[0].add_tool(tool)
                            added += 1
                if added:
                    import logging as _logging
                    _logging.getLogger(__name__).info(
                        "IDA 上传成功，已动态注册 %d 个新工具", added,
                    )
            except Exception as refresh_exc:  # noqa: BLE001
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    "IDA 工具刷新失败（已有工具仍可用）: %s", refresh_exc,
                )

            # 返回给 Agent 的关键字段：module/base/functions/md5/sha256 等。
            return _json.dumps(
                {
                    "status": meta.get("server_status", "ready"),
                    "binary": meta.get("binary"),
                    "module": meta.get("module"),
                    "base": meta.get("base"),
                    "functions": meta.get("functions"),
                    "size": meta.get("size"),
                    "md5": meta.get("md5"),
                    "sha256": meta.get("sha256"),
                },
                ensure_ascii=False,
            )
        except ValueError:
            return f'{{"error":"IDA 返回非 JSON: {body[:500]}"}}'

    toolkit = StrictJSONToolkit(
        tools=[
            AllowedFunctionTool(analysis, is_read_only=True),
            create_intelpwn_tool(timeout),
            create_scoped_shell_tool(target, project_dir, timeout, registry=scope_registry, role="reserve", artifact_root=artifact_root, executor=executor),
            AllowedFunctionTool(ida_open_binary, is_read_only=True),
            AllowedFunctionTool(gdb_create_session, is_read_only=False),
            AllowedFunctionTool(gdb_load_core, is_read_only=True),
            *exposed_ida_tools,
            *exposed_gdb_tools,
        ],
        skills_or_loaders=skill_list,
    )
    # 绑定 toolkit 引用，供 ida_open_binary 上传后动态注册新 IDA 工具。
    _toolkit_ref[0] = toolkit
    agent = Agent(
        name=REVERSE_EXPERT,
        system_prompt=RESERVE_SYS_PROMPT,
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )
    agent._ida_mcp_client = ida_mcp
    agent._gdb_mcp_client = gdb_mcp
    return agent


async def close_reverse_agent(agent: Agent | None) -> None:
    """关闭任务持有的 IDA 与 GDB MCP 进程。"""
    if agent is None:
        return
    for attr in ("_gdb_mcp_client", "_ida_mcp_client"):
        client = getattr(agent, attr, None)
        if client is not None:
            try:
                await client.close()
            except RuntimeError:
                pass
