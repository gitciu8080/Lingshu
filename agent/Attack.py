"""Attack：在授权范围内完成分析、验证和利用。

Skill 加载从 MissionState.category_decision 动态生成，不再硬编码 ctf-web。
"""
from __future__ import annotations
from agent.prompt_loader import load_prompt

import asyncio
import logging
import os
import re
from collections.abc import Callable
from pathlib import Path
from types import MethodType

from agentscope.agent import Agent, ReActConfig
from agentscope.mcp import HttpMCPConfig, MCPClient
from agentscope.message import UserMsg
from agentscope.permission import PermissionBehavior, PermissionDecision
from agentscope.tool import ToolGroup

from Tools.CVE_Search import cve_search
from Tools.OCR import create_tesseract_ocr_tool
from Tools.SageMath import execute_sagemath        
from Tools.ScopeRegistry import ScopeRegistry
from Tools.TonyDec import create_tonydec_tool
from Tools.Vision import create_vision_analysis_tool
from Tools.Volatility import create_volatility_tools
from Tools.tooling import (
    AgentMaxIterationsError,
    AllowedFunctionTool,
    StrictJSONToolkit,
    create_parallel_scoped_shell_tool,
    create_scoped_shell_tool,
    run_interruptible_agent_reply,
    run_expert_reply_with_continuation,
)
from Tools.tool_catalog import append_capability_summary, create_tool_catalog_tools
from Tools.WebShot import create_web_screenshot_tool, resolve_headless_browser
from agent.experts import attack_expert_name

logger = logging.getLogger(__name__)


_ANTSWORD_MCP_URL = "http://127.0.0.1:30080/sse"
_ANTSWORD_TOOLS = (
    "shell_list", "shell_get", "shell_add", "shell_edit", "shell_del",
    "shell_capabilities",
    "base_info", "base_probedb",
    "cmd_exec", "cmd_list", "cmd_quote",
    "file_dir", "file_read", "file_write", "file_delete", "file_copy",
    "file_rename", "file_retime", "file_chmod", "file_mkdir", "file_wget",
    "file_hash", "file_upload", "file_download",
    "db_list_confs", "db_get_conf", "db_add_conf", "db_del_conf",
    "db_show_databases", "db_show_tables", "db_show_columns", "db_query",
    "raw_request",
    "mcp_status", "mcp_logs", "mcp_config_get", "mcp_config_set",
)
_ANTSWORD_READ_ONLY_TOOLS = frozenset({
    "shell_list", "shell_get", "shell_capabilities",
    "base_info", "base_probedb", "cmd_list",
    "file_dir", "file_read", "file_hash", "file_download",
    "db_list_confs", "db_get_conf", "db_show_databases", "db_show_tables",
    "db_show_columns", "mcp_status", "mcp_logs", "mcp_config_get",
})


ATTACK_SYS_PROMPT = load_prompt("ATTACK")

# ── Skill 路径映射 ──
_SKILL_PATH_MAP: dict[str, str] = {
    "web": "Skills/ctf-skills/ctf-web",
    "pwn": "Skills/ctf-skills/ctf-pwn",
    "reverse": "Skills/ctf-skills/ctf-reverse",
    "crypto": "Skills/ctf-skills/ctf-crypto",
    "forensics": "Skills/ctf-skills/ctf-forensics",
    "malware": "Skills/ctf-skills/ctf-malware",
    "misc": "Skills/ctf-skills/ctf-misc",
    "osint": "Skills/ctf-skills/ctf-osint",
    "ai-ml": "Skills/ctf-skills/ctf-ai-ml",
    "writeup": "Skills/ctf-skills/ctf-writeup",
}

_CYBERPENDA_SKILL_MAP: dict[str, list[str]] = {
    "web": ["api-security", "pentest-tools"],
    "pwn": ["pwn-chain"],
    "reverse": ["reverse-skill-router", "reverse-engineering"],
    "crypto": ["ctf-sandbox-orchestrator"],
    "forensics": ["digital-forensics", "competition-forensic-timeline"],
    "malware": ["malware-analysis", "competition-malware-config"],
    # 应急响应：库存 IR bundle 全量激活（数字取证/威胁狩猎/AD 溯源/
    # 时间线重建/凭证窃取痕迹）
    "ir": [
        "digital-forensics", "threat-hunting", "windows-ad",
        "competition-forensic-timeline", "competition-lsass-ticket-material",
    ],
    "misc": ["ctf-sandbox-orchestrator"],
    "osint": ["pentest-tools"],
    "ai-ml": ["llm-security"],
}
_CYBERPENDA_ROOT = "Skills/cyberpenda-bundles"

_ATTACK_CATALOG_CATEGORIES: dict[str, set[str]] = {
    # web 附加 credential（仅 hydra 一个工具）：授权 Web 任务按需暴露
    # 凭证爆破能力，不影响其他分类。
    "web": {"recon", "web", "credential"},
    "pwn": {"reverse"},
    "reverse": {"reverse"},
    "mobile": {"mobile", "reverse"},
    "crypto": {"crypto"},
    "forensics": {"forensics"},
    "malware": {"forensics", "reverse"},
    "ir": {"forensics", "misc"},
    "misc": {"forensics", "crypto", "reverse"},
    "osint": {"recon"},
    "ai-ml": set(),
}


def select_antsword_tools(context: str) -> tuple[str, ...]:
    """有 WebShell 证据时挂载完整 AntSword MCP 工具集。"""
    lowered = context.lower()
    # Recon/计划经常包含“未发现 WebShell”这类否定结论；先剔除否定片段，
    # 避免仅因出现关键词就初始化整个外部 MCP。
    lowered = re.sub(
        r"(?:未发现|未检测到|没有|不存在|缺少|无|no|not found)"
        r"[^\n。；;]{0,24}(?:web\s*shell|webshell|antsword|蚁剑|shell_id)",
        "",
        lowered,
    )
    if not any(term in lowered for term in (
        "webshell", "web shell", "antsword", "蚁剑", "shell_id", "shell 密码",
    )):
        return ()
    # 不能按当前文本中的“命令/文件/数据库”等关键词裁剪 schema：WebShell
    # 会话通常先 shell_list，后续才知道需要文件或数据库能力。裁剪会造成
    # Attack 已识别 WebShell 却反馈“没有工具”的断层。写入/执行类仍由下面
    # 的实时审批钩子控制。
    return _ANTSWORD_TOOLS


async def _connect_antsword_mcp(
    timeout: int,
    exploitation_approved: Callable[[], bool] | None = None,
    enabled_tools: tuple[str, ...] | None = None,
) -> tuple[MCPClient, list]:
    """连接 API 托管的 AntSword SSE MCP，并注册本轮完整工具集。"""
    selected_tools = tuple(enabled_tools) if enabled_tools is not None else _ANTSWORD_TOOLS
    url = os.getenv("LINGSHU_ANTSWORD_MCP_URL", _ANTSWORD_MCP_URL).strip()
    client = MCPClient(
        name="AntSword_Tool",
        # AntSword SSE 是 HTTP 服务；Attack 使用无状态 MCP，避免长连接在
        # 任务取消/收尾时跨 asyncio task 关闭 anyio cancel scope。
        is_stateful=False,
        mcp_config=HttpMCPConfig(url=url, timeout=15.0),
        enable_tools=list(selected_tools),
        execution_timeout=max(float(timeout), 120.0),
    )
    try:
        tools = await client.list_tools()
        available = {tool.name.rsplit("__", 1)[-1] for tool in tools}
        missing = set(selected_tools) - available
        if missing:
            # AntSword 发行版可能不含管理扩展。不能因一项可选扩展缺失就
            # 丢弃已经返回的整组 WebShell 工具；实际可用集合仍会注册给 Agent。
            logger.warning(
                "AntSword MCP 未提供 %d 项声明工具，继续注册 %d 项可用工具: %s",
                len(missing), len(tools), ", ".join(sorted(missing)),
            )
        if not tools:
            raise RuntimeError("AntSword MCP 未返回任何可用工具")
    except BaseException:
        # stateless MCP 没有需要由外层关闭的连接上下文。
        raise

    # 读取/探测类操作可用于分析；任何可执行命令或修改目标的工具
    # 都与 MissionState.exploitation_approved 实时联动，不依赖模型遵守提示词。
    for tool in tools:
        short_name = tool.name.rsplit("__", 1)[-1]
        tool.is_read_only = short_name in _ANTSWORD_READ_ONLY_TOOLS

        async def _check_permissions(
            _self,
            *_args,
            _short_name: str = short_name,
            **_kwargs,
        ) -> PermissionDecision:
            if _short_name in _ANTSWORD_READ_ONLY_TOOLS:
                return PermissionDecision(
                    behavior=PermissionBehavior.ALLOW,
                    message="AntSword 只读信息收集已放行",
                )
            if exploitation_approved is not None and exploitation_approved():
                return PermissionDecision(
                    behavior=PermissionBehavior.ALLOW,
                    message="AntSword 操作已通过灵枢攻击阶段人工审批",
                )
            return PermissionDecision(
                behavior=PermissionBehavior.DENY,
                message="AntSword 写入/执行操作需先通过攻击阶段人工审批",
            )

        tool.check_permissions = MethodType(_check_permissions, tool)
    return client, tools


def _build_skill_list(
    category_decision: dict | None,
    project_dir: str | Path = "",
    *,
    include_secondary: bool = True,
    include_writeup: bool = True,
    include_attack_chain: bool = True,
) -> list[str]:
    """根据题型分类决策构建 Skill 加载路径。

    Args:
        category_decision: MissionState.category_decision 的字典形式。
        project_dir: 项目根目录（用于路径存在性检查）。

    Returns:
        Skill 路径列表，始终包含 writeup。

    Raises:
        FileNotFoundError: 题型已确定但对应 Skill 目录缺失。
    """
    skill_paths: list[str] = []
    project_path = Path(project_dir).expanduser().resolve() if project_dir else None

    if category_decision and category_decision.get("primary", "unknown") != "unknown":
        primary = category_decision["primary"]
        if primary in _SKILL_PATH_MAP:
            path = _SKILL_PATH_MAP[primary]
            if project_path and not (project_path / path).is_dir():
                raise FileNotFoundError(
                    f"题型 {primary!r} 的 Skill 目录不存在: {path}. "
                    f"请确认 Skills/ctf-skills/ctf-{primary}/ 已安装。"
                )
            skill_paths.append(str((project_path / path).resolve()) if project_path else path)

        # secondary 仅供兼容/低置信分类使用；正式执行默认只加载 primary。
        for cat in category_decision.get("secondary", []) if include_secondary else []:
            if cat in _SKILL_PATH_MAP and cat != primary:
                p = _SKILL_PATH_MAP[cat]
                if project_path and not (project_path / p).is_dir():
                    continue  # 次要 Skill 缺失不阻塞
                skill_paths.append(str((project_path / p).resolve()) if project_path else p)

    if include_writeup:
        writeup = _SKILL_PATH_MAP["writeup"]
        skill_paths.append(str((project_path / writeup).resolve()) if project_path else writeup)
    # CyberPenda bundles 完整保存在仓库中，但运行时只加载与当前分类相关的目录。
    categories: list[str] = []
    if category_decision:
        primary = str(category_decision.get("primary") or "")
        categories = [primary]
        if include_secondary:
            categories.extend(str(value) for value in category_decision.get("secondary", []))
    cyberpenda_names = ["attack-chain"] if include_attack_chain else []
    for category in categories:
        cyberpenda_names.extend(_CYBERPENDA_SKILL_MAP.get(category, []))
    for name in dict.fromkeys(cyberpenda_names):
        path = f"{_CYBERPENDA_ROOT}/{name}"
        if project_path and not (project_path / path / "SKILL.md").is_file():
            continue
        skill_paths.append(str((project_path / path).resolve()) if project_path else path)
    return skill_paths


async def create_attack_agent(
    model,
    analysis_agent: Agent,
    target: str,
    project_dir: str | Path,
    timeout: int,
    category_decision: dict | None = None,
    scope_registry: ScopeRegistry | None = None,
    max_iters: int = 20,
    expert_context: str = "",
    event_callback=None,
    rag_middleware=None,
    *,
    offloader=None,
    context_config=None,
    state=None,
    artifact_root: str | Path | None = None,
    exploitation_approved: Callable[[], bool] | None = None,
    vision_model=None,
    vision_roots: tuple[str | Path, ...] = (),
    forensic_roots: tuple[str | Path, ...] = (),
    target_kind: str = "",
    capability_context: str = "",
    enable_framework: bool = False,
    command_workdir: str | Path | None = None,
    mission=None,
    store=None,
) -> Agent:
    """创建 Attack Agent。

    Args:
        model: LLM 模型。
        analysis_agent: Analysis 子 Agent。
        target: 授权目标字符串（向后兼容）。
        project_dir: 项目根目录（仅用于加载项目 Skill）。
        command_workdir: 本任务命令工作目录；相对脚本和产物写入这里。
        timeout: 命令超时秒数。
        category_decision: 题型分类决策（v0.2.0 新增）。为 None 时仅加载 writeup。
        max_iters: ReAct 最大推理迭代次数，由调用方按任务复杂度分配。
        mission: 共享任务状态（可选）。提供时 Analysis 委托研判会登记
            Evidence，Attack 失败后 Orchestrator 仍可复用研判结论。
        store: MissionStore（可选），配合 mission 使用。
    """
    async def analysis(service_info: str) -> str:
        """请求 Analysis 专家研判真实服务证据。

        Args:
            service_info: Recon 得到的服务、版本和响应证据。
        """
        try:
            text = await run_expert_reply_with_continuation(
                analysis_agent,
                UserMsg(name="Attack", content=service_info),
                prefix="[Analysis] ",
                on_event=event_callback,
                label="Analysis",
            )
        except AgentMaxIterationsError:
            return "[Analysis] 超迭代，本轮无研判输出；请基于现有证据自行推进。"
        result = text or (
            "[Analysis] 未返回文本结果（含补轮）。"
            "可再次调用本工具重试；若再次为空请基于现有证据自行研判推进。"
        )
        # 研判入库：专家间委托的结论也进入证据链，避免 Attack 失败后
        # Orchestrator 看不到研判而重派重复分析；入库失败不阻断返回。
        if mission is not None and text:
            try:
                mission.add_evidence(
                    analysis_agent.name, "analysis_report", text,
                    confidence=0.7,
                )
                if store is not None:
                    store.save(mission)
            except Exception:  # noqa: BLE001 - 入库仅为可观测性增强
                pass
        return result




    command_cwd = Path(command_workdir or artifact_root or project_dir).expanduser().resolve()
    command_cwd.mkdir(parents=True, exist_ok=True)
    # 文件型任务优先以附件/解压目录作为只读分析与解码根；网络任务或缺少
    # 附件时才使用会话 WorkDir。绝不以项目源码根作为可写工具根目录。
    task_file_root = Path(
        forensic_roots[0] if forensic_roots else command_cwd,
    ).expanduser().resolve()
    primary = str((category_decision or {}).get("primary") or "unknown")
    confidence = float((category_decision or {}).get("confidence") or 0.0)
    # 首轮 Recon 已完成正式分类：高置信时只加载 primary；仅 unknown/低置信
    # 才保留一个 secondary，避免多套完整 Skill 同时进入每轮上下文。
    skill_decision = dict(category_decision or {})
    if confidence < 0.55 and skill_decision.get("secondary"):
        skill_decision["secondary"] = list(skill_decision["secondary"][:1])
    skill_list = _build_skill_list(
        skill_decision,
        project_dir,
        include_secondary=confidence < 0.55,
        include_writeup=False,
        include_attack_chain=primary in {"web", "pwn"},
    )

    categories = {
        primary,
        *(
            [str(item) for item in skill_decision.get("secondary", [])[:1]]
            if confidence < 0.55 else []
        ),
    }
    catalog_categories = set().union(*(
        _ATTACK_CATALOG_CATEGORIES.get(category, set()) for category in categories
    ))
    if primary == "unknown":
        catalog_categories = {"recon", "web", "forensics", "reverse"}
    # Android 逆向任务的 Attack 路由补充：apktool 在 Reserve/Triage 侧经
    # mobile 目录可达，此处让 Attack 在明确 Android 信号时同样获得该目录，
    # 避免跨专家交接断层。
    route_text = str(capability_context or "").lower()
    if (
        "mobile" in categories
        or (primary == "reverse" and re.search(
            r"\.apk\b|\.apk|\.dex\b|smali|android|安卓|jadx", route_text,
        ))
    ):
        catalog_categories.add("mobile")
    # Metasploit 按任务路由暴露：仅授权渗透/混合任务书模式或存在明确 CVE
    # 利用证据时开放 framework 目录（其中仅 msfconsole 一项），由调用方计算。
    if enable_framework:
        catalog_categories.add("framework")

    antsword_mcp: MCPClient | None = None
    antsword_tools: list = []
    selected_antsword_tools = (
        select_antsword_tools(capability_context) if primary in {"web", "unknown", "ir"} else ()
    )
    if selected_antsword_tools:
        try:
            antsword_mcp, antsword_tools = await _connect_antsword_mcp(
                timeout,
                exploitation_approved,
                selected_antsword_tools,
            )
        except Exception as exc:  # AntSword 不可用不应让非 WebShell 任务整体失败
            logger.warning("Attack 未能接入 AntSword MCP: %s", exc)

    tools = [
            AllowedFunctionTool(analysis, is_read_only=True),
            create_scoped_shell_tool(target, command_cwd, timeout, registry=scope_registry, role="attack", artifact_root=artifact_root),
            create_parallel_scoped_shell_tool(target, command_cwd, timeout, registry=scope_registry, role="attack", artifact_root=artifact_root),
            *antsword_tools,
            *create_tool_catalog_tools("attack", categories=catalog_categories),
        ]
    if target_kind == "network" or categories.intersection({"web", "malware", "unknown"}):
        tools.append(AllowedFunctionTool(cve_search, is_read_only=True))
    # Web 页面截图：网络/Web 类任务的漏洞证明证据（浏览器缺失时自动降级不挂载）
    if (
        resolve_headless_browser() is not None
        and (target_kind == "network" or categories.intersection({"web", "unknown"}))
    ):
        tools.append(create_web_screenshot_tool(
            scope_registry, workspace_root=artifact_root, workdir=command_cwd,
            timeout=min(timeout, 90), role="attack",
        ))
    if categories.intersection({"crypto", "misc"}):
        tools.append(AllowedFunctionTool(execute_sagemath, is_read_only=True))
    if categories.intersection({"forensics", "malware", "misc", "osint", "ai-ml"}):
        tools.append(create_tesseract_ocr_tool(task_file_root, timeout=min(timeout, 90)))
    if categories.intersection({"forensics", "malware", "misc"}):
        tools.append(create_tonydec_tool(task_file_root))
    if vision_model is not None and vision_roots and categories.intersection({
        "web", "forensics", "malware", "misc", "osint", "ai-ml",
    }):
        tools.append(create_vision_analysis_tool(vision_model, vision_roots))
    if categories.intersection({"forensics", "malware"}) and forensic_roots:
        tools.extend(create_volatility_tools(forensic_roots, timeout=max(timeout, 300)))
    skill_groups = []
    if skill_list:
        skill_groups.append(ToolGroup(
            name="task_skills",
            description=(
                f"当前 {primary} 题型的按需方法库；仅在需要具体方法或检查清单时激活，"
                "不用于一般工具调用。"
            ),
            skills_or_loaders=skill_list,
        ))
    toolkit = StrictJSONToolkit(tools=tools, tool_groups=skill_groups)
    agent = Agent(
        name=attack_expert_name(
            str((category_decision or {}).get("primary") or "unknown"),
            str((category_decision or {}).get("target_kind") or ""),
            expert_context,
        ),
        system_prompt=append_capability_summary(
            ATTACK_SYS_PROMPT,
            "attack",
            categories=catalog_categories,
        ),
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
        middlewares=[rag_middleware] if rag_middleware is not None else [],
        offloader=offloader,
        context_config=context_config,
        state=state,
    )
    agent._antsword_mcp_client = antsword_mcp
    return agent


async def close_attack_agent(agent: Agent | None) -> None:
    """关闭 Attack 任务持有的 AntSword SSE 会话，不关闭 GUI 服务。"""
    if agent is None:
        return
    if hasattr(agent, "get_if_loaded"):
        agent = agent.get_if_loaded()
        if agent is None:
            return
    client = getattr(agent, "_antsword_mcp_client", None)
    if (
        client is not None
        and getattr(client, "is_stateful", True)
        and getattr(client, "is_connected", True)
    ):
        try:
            await client.close()
        except RuntimeError:
            pass
