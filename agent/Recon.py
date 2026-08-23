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
from Tools.Plan import create_submit_plan_tool
from Tools.ScopeRegistry import ScopeRegistry
from Tools.TonyDec import create_tonydec_tool
from Tools.tooling import StrictJSONToolkit, create_scoped_shell_tool
from core.TaskState import MissionState, MissionStore  # noqa: F401 (类型标注)
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
    executor: "Any",
    mission: MissionState | None = None,
    store: MissionStore | None = None,
    event_callback=None,
) -> Agent:
    recon_tools = [
        create_scoped_shell_tool(
            target, project_dir, timeout,
            registry=scope_registry, role="recon",
            artifact_root=artifact_root, executor=executor,
        ),
        create_cve_search_tool(),
    ]
    # 把原 Brain 的「制定作战计划」职责并入首次 Recon：
    # Recon 在完成侦察后直接用 SubmitPlan 登记结构化计划，省去单独的
    # Brain 往返，并让计划与题型识别基于真实侦察证据。
    if mission is not None and store is not None:
        recon_tools.append(
            create_submit_plan_tool(mission, store, event_callback)
        )
    toolkit = StrictJSONToolkit(tools=recon_tools)
    return Agent(
        name=NETWORK_RECON_EXPERT,
        system_prompt=NETWORK_RECON_SYS_PROMPT,
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
    executor: "Any",
    mission: MissionState | None = None,
    store: MissionStore | None = None,
    event_callback=None,
) -> Agent:
    """创建文件分析 Agent，工作目录约束在 workdir 内。"""
    recon_tools = [
        create_scoped_shell_tool(str(workdir), project_dir, timeout, role="recon", artifact_root=artifact_root, executor=executor),
        create_tesseract_ocr_tool(workdir, timeout=min(timeout, 90), executor=executor),
        create_tonydec_tool(workdir, executor=executor),
    ]
    # 把原 Brain 的「制定作战计划」职责并入首次 Recon（同上）。
    if mission is not None and store is not None:
        recon_tools.append(
            create_submit_plan_tool(mission, store, event_callback)
        )
    toolkit = StrictJSONToolkit(tools=recon_tools)
    return Agent(
        name=ARTIFACT_TRIAGE_EXPERT,
        system_prompt=ARTIFACT_TRIAGE_SYS_PROMPT,
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
