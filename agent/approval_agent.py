# Agents/approval_agent.py
from agentscope.agent import Agent
from agentscope.tool import Toolkit, tool

@tool(require_confirm=True)
async def approve_phase(phase: str, reason: str) -> str:
    """请求人工批准进入指定攻击阶段"""
    # 此函数体仅在用户确认后执行
    return f"PHASE_APPROVED:{phase}"

def create_approval_agent(model):
    toolkit = Toolkit()
    toolkit.register(approve_phase)
    return Agent(
        name="PhaseApprover",
        model=model,
        toolkit=toolkit,
        system_prompt=(
            "你是一个阶段审批代理。当被要求审批时，调用 approve_phase 工具。\n"
            "不要做任何其他事情，不要分析，不要建议，只调用工具。"
        ),
    )