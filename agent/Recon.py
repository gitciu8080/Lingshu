"""Recon：信息收集 — 网络侦察（NetworkReconAgent）和文件分析（ArtifactTriageAgent）。

两类任务的权限模型完全不同：
  - 网络 Recon：只访问授权主机:端口，禁止扫描其他目标
  - 文件 Triage：静态分析工作目录，禁止联网、禁止执行不可信二进制
"""
from __future__ import annotations
from agent.prompt_loader import load_prompt

from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from Tools.CVE_Search import create_cve_search_tool
from Tools.OCR import create_tesseract_ocr_tool
from Tools.ScopeRegistry import ScopeRegistry
from Tools.TonyDec import create_tonydec_tool
from Tools.Vision import create_vision_analysis_tool
from Tools.Volatility import create_volatility_tools
from Tools.tooling import (
    StrictJSONToolkit,
    create_parallel_scoped_shell_tool,
    create_scoped_shell_tool,
)
from Tools.tool_catalog import append_capability_summary, create_tool_catalog_tools
from agent.experts import ARTIFACT_TRIAGE_EXPERT, NETWORK_RECON_EXPERT

# ---------------------------------------------------------------------------
# NetworkReconAgent — 网络扫描
# ---------------------------------------------------------------------------

NETWORK_RECON_SYS_PROMPT = load_prompt("NETWORK_RECON")


def create_network_recon_agent(
    model,
    target: str,
    project_dir: str | Path,
    timeout: int,
    scope_registry: ScopeRegistry | None = None,
    max_iters: int = 20,
    *,
    offloader=None,
    context_config=None,
    state=None,
    artifact_root: str | Path | None = None,
    vision_model=None,
    vision_roots: tuple[str | Path, ...] = (),
    include_cve_search: bool = True,
) -> Agent:
    tools = [
        create_scoped_shell_tool(target, project_dir, timeout, registry=scope_registry, role="recon", artifact_root=artifact_root),
        create_parallel_scoped_shell_tool(target, project_dir, timeout, registry=scope_registry, role="recon", artifact_root=artifact_root),
        *create_tool_catalog_tools("recon", categories={"recon", "web"}),
    ]
    if include_cve_search:
        tools.append(create_cve_search_tool())
    if vision_model is not None and vision_roots:
        tools.append(create_vision_analysis_tool(vision_model, vision_roots))
    toolkit = StrictJSONToolkit(tools=tools)
    return Agent(
        name=NETWORK_RECON_EXPERT,
        system_prompt=append_capability_summary(
            NETWORK_RECON_SYS_PROMPT, "recon", categories={"recon", "web"},
        ),
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )


# ---------------------------------------------------------------------------
# ArtifactTriageAgent — 本地文件分析
# ---------------------------------------------------------------------------

ARTIFACT_TRIAGE_SYS_PROMPT = load_prompt("ARTIFACT_TRIAGE")


def create_artifact_triage_agent(
    model,
    workdir: str | Path,
    project_dir: str | Path,
    timeout: int,
    max_iters: int = 20,
    *,
    offloader=None,
    context_config=None,
    state=None,
    artifact_root: str | Path | None = None,
    vision_model=None,
    vision_roots: tuple[str | Path, ...] = (),
    capability_categories: set[str] | None = None,
) -> Agent:
    """创建文件分析 Agent，工作目录约束在 workdir 内。"""
    selected = set(capability_categories or {"forensics", "reverse", "mobile", "misc"})
    catalog_categories = selected.intersection({"forensics", "reverse", "mobile"})
    tools = [
            create_scoped_shell_tool(str(workdir), project_dir, timeout, role="recon", artifact_root=artifact_root),
            create_parallel_scoped_shell_tool(str(workdir), project_dir, timeout, role="recon", artifact_root=artifact_root),
            *create_tool_catalog_tools("triage", categories=catalog_categories),
        ]
    if selected.intersection({"forensics", "misc", "osint", "ai-ml"}):
        tools.append(create_tesseract_ocr_tool(workdir, timeout=min(timeout, 90)))
    if selected.intersection({"forensics", "malware", "misc"}):
        tools.append(create_tonydec_tool(workdir))
    if selected.intersection({"forensics", "malware"}):
        tools.extend(create_volatility_tools((workdir,), timeout=max(timeout, 300)))
    if vision_model is not None and selected.intersection({
        "forensics", "misc", "osint", "ai-ml",
    }):
        tools.append(create_vision_analysis_tool(vision_model, vision_roots or (workdir,)))
    toolkit = StrictJSONToolkit(tools=tools)
    return Agent(
        name=ARTIFACT_TRIAGE_EXPERT,
        system_prompt=append_capability_summary(
            ARTIFACT_TRIAGE_SYS_PROMPT, "triage", categories=catalog_categories,
        ),
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )


# ---------------------------------------------------------------------------
# 向后兼容
# ---------------------------------------------------------------------------

# 旧名称别名
RECON_SYS_PROMPT = NETWORK_RECON_SYS_PROMPT
create_recon_agent = create_network_recon_agent
