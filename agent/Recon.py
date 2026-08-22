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
- 若授权会话工作区中已有网页截图或目标图片，可主动调用 analyze_image 理解
  页面结构和视觉线索；不得借此读取本任务目录之外的图片。
- 不修改全局任务状态，也不在任意路径写文件。

cve_search 使用策略：
- 仅在任务上下文中明确提到具体 CVE 编号时（如 "CVE-2018-2894"），才调用 cve_search 获取公开情报。
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
) -> Agent:
    tools = [
        create_scoped_shell_tool(target, project_dir, timeout, registry=scope_registry, role="recon", artifact_root=artifact_root),
        create_cve_search_tool(),
    ]
    if vision_model is not None and vision_roots:
        tools.append(create_vision_analysis_tool(vision_model, vision_roots))
    toolkit = StrictJSONToolkit(tools=tools)
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

ARTIFACT_TRIAGE_SYS_PROMPT = """你是 CTF 文件分析专家（ArtifactTriage）。
你只分析工作目录中的本地文件，不访问网络、不执行不可信二进制。

规则：
- 使用 scoped_shell 仅在工作目录内执行只读分析命令。
- 先获取文件列表，识别文件类型（ELF/PE/PCAP/镜像/脚本/加密文件等）。
- 对 ELF 执行 checksec/readelf；对 PCAP 执行 tcpdump/capinfos；对压缩包执行 file/unzip -l。
- 对图片、截图或扫描文档可调用 ocr_image，使用 Tesseract 提取文本。
- 发现图片、截图、图表、二维码、界面或视觉型题目时，主动调用 analyze_image
  理解画面语义和安全线索；需要逐字提取时再用 ocr_image 交叉验证。
- 发现 .raw/.mem/.vmem/.dmp 等内存镜像时，使用 volatility_analyze：先运行
  imageinfo 或 kdbgscan 确认 profile，再运行 pslist/psscan、netscan、cmdline、
  consoles、filescan、malfind 等取证插件。不得凭文件扩展名猜测 profile。
- 若文件头完整匹配 6688ff4f6886005611611618，调用 tonydec 解码到新的输出路径，
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
) -> Agent:
    """创建文件分析 Agent，工作目录约束在 workdir 内。"""
    tools = [
            create_scoped_shell_tool(str(workdir), project_dir, timeout, role="recon", artifact_root=artifact_root),
            create_tesseract_ocr_tool(workdir, timeout=min(timeout, 90)),
            create_tonydec_tool(workdir),
            *create_volatility_tools((workdir,), timeout=max(timeout, 300)),
        ]
    if vision_model is not None:
        tools.append(create_vision_analysis_tool(vision_model, vision_roots or (workdir,)))
    toolkit = StrictJSONToolkit(tools=tools)
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
