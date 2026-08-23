"""内部 Agent 的统一上下文配置与角色会话状态。

- ``build_agent_context_config``：ContextConfig 契约（trigger_ratio=0.75、
  reserve_ratio=0.12、tool_result_limit=4000）＋自定义摘要 Schema，保证压缩
  摘要保留授权范围、审批状态、计划项、证据路径、失败指纹、Flag 提交结果与
  下一动作，不丢失恢复所需语义。
- ``build_role_agent_state``：确定性角色会话 ID（``{mission_id}-{role}``），
  使 offload_context / offload_tool_result 落到
  ``sessions/{mission_id}-{role}/`` 分区。
"""

from __future__ import annotations

import string

from agentscope.agent import ContextConfig
from agentscope.state import AgentState

# 计划锁定的上下文契约
TRIGGER_RATIO = 0.75
RESERVE_RATIO = 0.12
TOOL_RESULT_LIMIT = 4000

# 自定义摘要 Schema：压缩时必须保留的恢复语义字段。
# 由 agent 的压缩模型按此结构输出，缺失字段时旧摘要不丢失关键信息。
SUMMARY_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "authorized_scope": {
            "type": "array",
            "items": {"type": "string"},
            "description": "当前授权目标与动态扩容后的范围",
        },
        "approval_status": {
            "type": "string",
            "enum": ["not_required", "pending", "approved", "rejected"],
            "description": "人工审批闸门状态（首次进入 EXPLOITATION 前）",
        },
        "plan_items": {
            "type": "array",
            "items": {"type": "object"},
            "description": "作战计划清单快照（id/status/evidence）",
        },
        "evidence_paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Workspace 相对产物路径（stdout/报告/flag 证据）",
        },
        "failed_fingerprints": {
            "type": "array",
            "items": {"type": "string"},
            "description": "已失败动作指纹（熔断与去重依据）",
        },
        "flag_submission": {
            "type": "object",
            "description": "最近一次 Flag/NSS 提交结果（correct/attempt_id）",
        },
        "next_action": {
            "type": "string",
            "description": "恢复后应执行的下一动作",
        },
    },
    "required": [
        "authorized_scope",
        "approval_status",
        "plan_items",
        "evidence_paths",
        "failed_fingerprints",
        "flag_submission",
        "next_action",
    ],
}


# 压缩摘要渲染模板：占位符必须与 SUMMARY_SCHEMA 字段一一对应。
# 库在压缩时执行 ``summary_template.format(**summary_schema 输出)``，
# 若模板出现 Schema 中不存在的占位符会直接 KeyError 导致压缩崩溃
# （2026-08-23 easyjs 会话事故根因），故此处显式声明并在构造时校验。
SUMMARY_TEMPLATE: str = (
    "<system-info>Here is a summary of your previous work\n"
    "# Authorized Scope\n"
    "{authorized_scope}\n\n"
    "# Approval Status\n"
    "{approval_status}\n\n"
    "# Plan Items\n"
    "{plan_items}\n\n"
    "# Evidence Paths\n"
    "{evidence_paths}\n\n"
    "# Failed Fingerprints\n"
    "{failed_fingerprints}\n\n"
    "# Flag Submission\n"
    "{flag_submission}\n\n"
    "# Next Action\n"
    "{next_action}"
    "</system-info>"
)


def _validate_summary_template() -> None:
    """启动期校验：模板占位符与 SUMMARY_SCHEMA 字段必须一致。"""
    expected = set(SUMMARY_SCHEMA["properties"])
    actual = {
        field for _, field, _, _ in string.Formatter().parse(SUMMARY_TEMPLATE) if field
    }
    if actual != expected:
        raise ValueError(
            "summary_template 占位符与 SUMMARY_SCHEMA 字段失配: "
            f"仅模板有={sorted(actual - expected)}, 仅Schema有={sorted(expected - actual)}"
        )


_validate_summary_template()


def build_agent_context_config() -> ContextConfig:
    """返回灵枢统一的 ContextConfig（计划锁定的参数与摘要 Schema/Template）。"""
    return ContextConfig(
        trigger_ratio=TRIGGER_RATIO,
        reserve_ratio=RESERVE_RATIO,
        tool_result_limit=TOOL_RESULT_LIMIT,
        summary_schema=SUMMARY_SCHEMA,
        summary_template=SUMMARY_TEMPLATE,
    )


def build_role_agent_state(mission_id: str, role: str) -> AgentState:
    """返回角色会话状态：offload 分区键 = ``{mission_id}-{role}``。"""
    return AgentState(session_id=f"{mission_id}-{role}")
