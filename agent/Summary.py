"""Summary：在任务结束后总结完整会话并形成安全测试报告正文。"""
from agent.prompt_loader import load_prompt
from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from Tools.tooling import StrictJSONToolkit

SUMMARY_EXPERT = "Mia - 对话总结与报告专家"

# 灵枢·利刃 安全测试报告模板 skill（相对本项目根目录）
REPORT_TEMPLATE_SKILL_DIR = str(
    Path(__file__).resolve().parent.parent / "Skills" / "pentest-report-template",
)

SUMMARY_SYS_PROMPT = load_prompt("SUMMARY")


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
