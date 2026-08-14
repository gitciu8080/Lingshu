"""Summary：在任务结束后总结完整会话并形成安全测试报告正文。"""
from agentscope.agent import Agent, ReActConfig
from Tools.tooling import StrictJSONToolkit

SUMMARY_EXPERT = "Mia - 对话总结与报告专家"

SUMMARY_SYS_PROMPT = """你是灵枢系统的对话总结与安全报告专家（Summary）。
你会收到一次授权安全测试的任务状态和按时间排序的完整会话记录。
请输出可直接归档的中文 Markdown 报告，至少包含：执行摘要、对话与阶段时间线、
已确认事实与证据、工具调用和人工审批记录、发现与攻击链、成功/失败尝试、风险和建议。
必须记录用户选择的攻击方案及调整后的优先级，并严格区分已验证事实、模型推测和
未验证事项；不得补写会话中不存在的命令、漏洞、CVE、权限或成功结果。内容应完整，
但避免逐字复制冗长日志。"""


def create_summary_agent(model, *, offloader=None, context_config=None, state=None) -> Agent:
    """创建只做总结、不调用任何外部工具的报告 Agent。"""
    return Agent(
        name=SUMMARY_EXPERT,
        system_prompt=SUMMARY_SYS_PROMPT,
        model=model,
        toolkit=StrictJSONToolkit(),
        react_config=ReActConfig(max_iters=1, interruption_raise_cancelled_error=True),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )
