"""Human-readable expert identities used by the mission roster UI."""

from __future__ import annotations


BRAIN_EXPERT = "Sophia - 战略规划专家"
ORCHESTRATOR_EXPERT = "Alex - 行动指挥专家"
NETWORK_RECON_EXPERT = "Ethan - 网络侦察专家"
ARTIFACT_TRIAGE_EXPERT = "Iris - 文件分析专家"
ANALYSIS_EXPERT = "Nora - 漏洞研判专家"
REVERSE_EXPERT = "Ryan - 逆向程序专家"
SCOPE_AUDITOR_EXPERT = "Grace - 授权范围审计专家"

_ATTACK_EXPERTS = {
    "web": "Mike - WEB渗透专家",
    "pwn": "Victor - 二进制利用专家",
    "reverse": "Ryan - 逆向利用专家",
    "crypto": "Alice - 密码分析专家",
    "forensics": "Iris - 数字取证专家",
    "malware": "Morgan - 恶意代码分析专家",
    "misc": "Taylor - 综合安全专家",
    "osint": "Olivia - 开源情报专家",
    "ai-ml": "Ada - AI安全专家",
}


def attack_expert_name(
    category: str,
    target_kind: str = "",
    context: str = "",
) -> str:
    """Select an Attack persona from category and planning context."""
    resolved = category
    lowered = context.lower()
    if resolved == "unknown":
        signals = {
            "web": ("http", "web", "网站", "接口", "路由", "目录枚举"),
            "pwn": ("pwn", "rop", "栈溢出", "堆利用"),
            "reverse": ("逆向", "反编译", "ida", "ghidra"),
            "crypto": ("密码", "解密", "rsa", "aes"),
            "forensics": ("取证", "pcap", "内存镜像", "隐写"),
            "malware": ("恶意软件", "木马", "勒索", "c2"),
            "osint": ("开源情报", "osint", "whois"),
            "ai-ml": ("提示注入", "llm", "机器学习"),
        }
        resolved = next(
            (
                name
                for name, keywords in signals.items()
                if any(keyword in lowered for keyword in keywords)
            ),
            "unknown",
        )
    if resolved in _ATTACK_EXPERTS:
        return _ATTACK_EXPERTS[resolved]
    if target_kind == "network":
        return "Mike - 网络渗透专家"
    return "Taylor - 安全验证专家"


def build_expert_assignments(
    category: str,
    target_kind: str,
    context: str,
    recon_expert: str,
) -> tuple[dict[str, str], str]:
    """Return per-phase owners and a human-readable roster section."""
    attack_expert = attack_expert_name(category, target_kind, context)
    phase_owners = {
        "recon": recon_expert,
        "analysis": ANALYSIS_EXPERT,
        "exploitation": attack_expert,
        "post_exploitation": attack_expert,
        "complete": ORCHESTRATOR_EXPERT,
    }
    members = [
        (BRAIN_EXPERT, "制定作战计划、拆解阶段目标与证据要求"),
        (ORCHESTRATOR_EXPERT, "统筹调度、阶段推进、审批和任务收尾"),
        (recon_expert, "负责授权范围内的信息收集与基础证据固定"),
        (ANALYSIS_EXPERT, "根据真实侦察证据研判漏洞与误报风险"),
        (attack_expert, "负责题型对应的安全验证、利用与目标达成"),
    ]
    if category in {"pwn", "reverse", "malware"} or target_kind != "network":
        members.append((REVERSE_EXPERT, "负责二进制逆向、反编译与算法分析"))
    members.append((SCOPE_AUDITOR_EXPERT, "在需要扩展授权范围时独立审核证据"))
    section = "## 专家分工\n" + "\n".join(
        f"- **{name}**：{responsibility}"
        for name, responsibility in members
    )
    return phase_owners, section
