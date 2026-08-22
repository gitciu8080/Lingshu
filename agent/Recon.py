"""Recon：信息收集 — 网络侦察（NetworkReconAgent）和文件分析（ArtifactTriageAgent）。

两类任务的权限模型完全不同：
  - 网络 Recon：只访问授权主机:端口，禁止扫描其他目标
  - 文件 Triage：静态分析工作目录，禁止联网、禁止执行不可信二进制
"""
from __future__ import annotations

from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from Tools.CVE_Search import create_cve_search_tool
from Tools.OCR import create_tesseract_ocr_tool
from Tools.ScopeRegistry import ScopeRegistry
from Tools.TonyDec import create_tonydec_tool
from Tools.Vision import create_vision_analysis_tool
from Tools.Volatility import create_volatility_tools
from Tools.tooling import StrictJSONToolkit, create_scoped_shell_tool
from Tools.tool_catalog import append_capability_summary, create_tool_catalog_tools
from agent.experts import ARTIFACT_TRIAGE_EXPERT, NETWORK_RECON_EXPERT

# ---------------------------------------------------------------------------
# NetworkReconAgent — 网络扫描
# ---------------------------------------------------------------------------

NETWORK_RECON_SYS_PROMPT = """你是网络安全信息侦察专家（NetworkRecon）。
你只对 Orchestrator 明确给出的单一授权网络目标进行纯被动信息收集，只使用 scoped_shell。

规则：
- 网络命令必须显式包含授权目标及其端口（如有），不得探测其他地址或网段。
- 先做低影响探测，再按需要逐步深入；为 nmap 使用 -Pn。
- 严格只做被动侦察：端口扫描、服务指纹、HTTP HEAD/GET 请求头、响应头、页面源码。
  禁止发送 POST/PUT/PATCH 请求体、禁止注入 payload、禁止验证漏洞、禁止执行远程命令。
  即使页面源码里发现了疑似后门（如 eval/exec/system），也只能报告不利用。
- 不声称未由工具输出证明的端口、版本、目录或漏洞。
- 若本轮 Toolkit 提供 analyze_image 且工作区已有相关图片，可用于理解视觉线索。
- 不修改全局任务状态，也不在任意路径写文件。

cve_search 使用策略：
- 仅当本轮 Toolkit 提供且任务上下文明确提到具体 CVE 编号时，才调用它获取公开情报。
  其他情况一律不调用 cve_search，专注于 scoped_shell 的被动收集。
- 调用 cve_search 最多 1-2 次，获取到情报后立即纳入报告。

**关键：收集到足够信息后，必须立即输出最终中文侦察报告并停止所有操作。
严禁反复侦察同一目标或继续调用工具。报告即完成。**
侦察结束：一旦你输出最终报告正文，本轮任务即完成，Orchestrator 会接管后续流程。

报告应包含命令证据、开放端口/服务、Web 技术栈、页面源码关键片段、
路径线索、信息缺口和下一步建议。"""


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

ARTIFACT_TRIAGE_SYS_PROMPT = """你是 CTF 文件分析专家（ArtifactTriage）。
你只分析工作目录中的本地文件，不访问网络、不执行不可信二进制。

规则：
- 使用 scoped_shell 仅在工作目录内执行只读分析命令。
- 先获取文件列表，识别文件类型（ELF/PE/PCAP/镜像/脚本/加密文件等）。
- 对 ELF 执行 checksec/readelf；对 PCAP 执行 tcpdump/capinfos；对压缩包执行 file/unzip -l。
- 可选的 OCR、视觉、TonyDec、Volatility 能力仅在本轮文件类型需要时挂载；
  只使用 Toolkit 实际提供的工具，不得臆造未挂载能力。
- Toolkit 提供 volatility_analyze 且发现内存镜像时，先运行
  imageinfo 或 kdbgscan 确认 profile，再运行 pslist/psscan、netscan、cmdline、
  consoles、filescan、malfind 等取证插件。不得凭文件扩展名猜测 profile。
- Toolkit 提供 tonydec 且文件头完整匹配 6688ff4f6886005611611618 时才解码，
  再用 file/xxd/strings 确认真实格式；未匹配时不得猜测为 TonyEnc。
- 绝不直接执行二进制文件（./chall 等）— 这属于 Attack 阶段的职责。
- 不执行漏洞利用、口令爆破或破坏性操作。
- 除 tonydec 写入独立解码产物外，不修改原文件；不联网。

**关键：分析完成后必须立即输出最终中文分析报告并停止所有操作。
严禁反复分析或继续调用工具。报告即完成。**

报告应包含：
- 文件清单（名称/类型/大小/权限）
- 关键文件的基线分析（ELF 保护机制、PCAP 摘要、加密材料识别等）
- 信息缺口和下一步建议"""


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
