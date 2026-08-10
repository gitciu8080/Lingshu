"""ScopeAuditor — IP 授权范围审核 Agent（纯推理，不执行命令）。

审核 Orchestrator 提交的 IP/网段扩容请求：
仅当证据链中确实出现过该 IP 且属于私有地址段时才批准。
公网 IP、无证据来源一律拒绝。
"""
from __future__ import annotations

from agentscope.agent import Agent, ReActConfig
from agentscope.tool import Toolkit

SCOPE_AUDITOR_SYS_PROMPT = """你是授权范围审核专家（ScopeAuditor）。
你的唯一职责是审核 Orchestrator 提交的 IP/网段扩容请求，防止未授权目标被纳入攻击范围。

审核规则（严格遵守，优先级从高到低）：
1. 以下情况一律拒绝：
   - 公网 IP（非 RFC1918 私有地址、非 loopback、非 link-local）
   - 请求中未提供有效证据（evidence 为空或与目标无关）
   - 证据文本中未明确出现所请求的 IP 地址
2. 以下情况可批准：
   - IP 属于 RFC1918 私有地址段（10.0.0.0/8、172.16.0.0/12、192.168.0.0/16）
   - 且证据文本中明确出现了该 IP（如 "remoteAddr=10.42.3.240"）
   - 且证据来源可信（Recon/Attack 的工具输出、Jolokia 日志、HTTP 响应头等）
3. 网段（CIDR）审核更严格：
   - 仅当多个证据指向同一网段（如多个 /24 内 IP）时才可批准 /16 或更大范围
   - 单 IP 证据优先批准单 IP 而非网段

输出格式（严格遵守，不要输出其他内容）：
第一行：APPROVED 或 REJECTED
第二行起：理由（一两句话，引用关键证据）"""


def create_scope_auditor_agent(model) -> Agent:
    """创建 IP 审核 Agent（无工具，纯推理）。"""
    return Agent(
        name="ScopeAuditor",
        system_prompt=SCOPE_AUDITOR_SYS_PROMPT,
        model=model,
        toolkit=Toolkit(tools=[]),
        react_config=ReActConfig(max_iters=3),
    )
