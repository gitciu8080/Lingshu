"""ScopeAuditor — IP 授权范围审核 Agent（纯推理，不执行命令）。

审核 Orchestrator 提交的 IP/网段扩容请求：
仅当证据链中确实出现过该 IP 且属于私有地址段时才批准。
公网 IP、无证据来源一律拒绝。
"""
from __future__ import annotations
from agent.prompt_loader import load_prompt

from agentscope.agent import Agent, ReActConfig
from Tools.tooling import StrictJSONToolkit
from agent.experts import SCOPE_AUDITOR_EXPERT

SCOPE_AUDITOR_SYS_PROMPT = load_prompt("SCOPE_AUDITOR")


def create_scope_auditor_agent(model) -> Agent:
    """创建 IP 审核 Agent（无工具，纯推理）。"""
    return Agent(
        name=SCOPE_AUDITOR_EXPERT,
        system_prompt=SCOPE_AUDITOR_SYS_PROMPT,
        model=model,
        toolkit=StrictJSONToolkit(tools=[]),
        react_config=ReActConfig(max_iters=3, interruption_raise_cancelled_error=True),
    )
