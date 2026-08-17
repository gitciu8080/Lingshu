"""Summary：在任务结束后总结完整会话并形成安全测试报告正文。"""
from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from Tools.tooling import StrictJSONToolkit

SUMMARY_EXPERT = "Mia - 对话总结与报告专家"

# 灵枢·利刃 安全测试报告模板 skill（相对本项目根目录）
REPORT_TEMPLATE_SKILL_DIR = str(
    Path(__file__).resolve().parent.parent / "Skills" / "pentest-report-template",
)

SUMMARY_SYS_PROMPT = """你是灵枢系统的对话总结与安全报告专家（Summary）。
你会收到一次授权安全测试的任务状态和按时间排序的完整会话记录。
请输出可直接归档的中文 Markdown 报告，至少包含：执行摘要、对话与阶段时间线、
已确认事实与证据、工具调用和人工审批记录、发现与攻击链、成功/失败尝试、风险和建议。
必须记录用户选择的攻击方案及调整后的优先级，并严格区分已验证事实、模型推测和
未验证事项；不得补写会话中不存在的命令、漏洞、CVE、权限或成功结果。内容应完整，
但避免逐字复制冗长日志。

报告格式要求：必须使用已加载的「pentest-report-template」skill（灵枢·利刃安全测试
报告模板）。先用 skill_viewer 工具读取该 skill 的完整说明与 references 规范，再按
模板的 7 大区块（封面、目录、概述、测试结论、测试综述、测试结果、安全等级与建议、
封底）组织输出，单漏洞条目遵循模板规定的 7 段结构，Mermaid 图以 ```mermaid 代码块
内嵌，`---` 作分页语义。产物恒为 Markdown。"""


def create_summary_agent(model, *, offloader=None, context_config=None, state=None) -> Agent:
    """创建只做总结、不调用任何外部工具的报告 Agent（加载灵枢·利刃报告模板 skill）。"""
    return Agent(
        name=SUMMARY_EXPERT,
        system_prompt=SUMMARY_SYS_PROMPT,
        model=model,
        toolkit=StrictJSONToolkit(
            skills_or_loaders=[REPORT_TEMPLATE_SKILL_DIR],
        ),
        react_config=ReActConfig(max_iters=5, interruption_raise_cancelled_error=True),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )
