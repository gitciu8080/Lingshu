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


def build_agent_context_config() -> ContextConfig:
    """返回灵枢统一的 ContextConfig（计划锁定的参数与摘要 Schema）。"""
    return ContextConfig(
        trigger_ratio=TRIGGER_RATIO,
        reserve_ratio=RESERVE_RATIO,
        tool_result_limit=TOOL_RESULT_LIMIT,
        summary_schema=SUMMARY_SCHEMA,
    )


def build_role_agent_state(mission_id: str, role: str) -> AgentState:
    """返回角色会话状态：offload 分区键 = ``{mission_id}-{role}``。"""
    return AgentState(session_id=f"{mission_id}-{role}")
