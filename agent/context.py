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

_ROLE_CONTEXT_PROFILES: dict[str, tuple[float, float, int]] = {
    "brain": (0.75, 0.10, 1800),
    "recon": (0.70, 0.10, 2400),
    "analysis": (0.70, 0.10, 1800),
    "attack": (0.68, 0.10, 2600),
    "reserve": (0.68, 0.10, 2800),
    "orchestrator": (0.70, 0.10, 2400),
    "summary": (0.70, 0.10, 2600),
}

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
            # O13：放宽为 object|string——小模型复刻对象数组易失败触发全量
            # reset 自愈（代价最大）；字符串形式（如 "p1 done,p2 doing"）可接受
            "type": ["array", "string"],
            "items": {"type": "object"},
            "description": "作战计划清单快照（id/status/evidence），亦可为紧凑字符串",
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
            # O13：放宽——空提交场景小模型常回字符串
            "type": ["object", "string"],
            "description": "最近一次 Flag/NSS 提交结果（correct/attempt_id）",
        },
        "key_runtime_state": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "压缩后必须存活的活性工具状态，每条一个：IDA database 会话 ID、"
                "WebShell URL/shell_id、已获凭据（user:pass@host）、GDB session ID、"
                "容器/反弹监听地址——丢失会导致压缩后重找会话/重找 shell 的整轮浪费"
            ),
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
        "key_runtime_state",
        "next_action",
    ],
}


# 压缩摘要模板：必须与 SUMMARY_SCHEMA 的 required 字段一一对应。
# 框架用 summary_template.format(**res.content) 渲染压缩结果——模板引用了
# schema 中不存在的字段（如默认模板的 {task_overview}）会在每次压缩时
# 抛 KeyError 并杀死专家回复（61aebfeb 复盘）。
SUMMARY_TEMPLATE: str = (
    "<system-info>Here is a summary of your previous work\n"
    "# Authorized Scope\n{authorized_scope}\n\n"
    "# Approval Status\n{approval_status}\n\n"
    "# Plan Items\n{plan_items}\n\n"
    "# Evidence Paths\n{evidence_paths}\n\n"
    "# Failed Fingerprints\n{failed_fingerprints}\n\n"
    "# Flag Submission\n{flag_submission}\n\n"
    "# Key Runtime State (IDA session ids / shell urls / credentials — reuse them, do not re-discover)\n{key_runtime_state}\n\n"
    "# Next Action\n{next_action}"
    "</system-info>"
)


def build_agent_context_config(role: str = "") -> ContextConfig:
    """返回角色级 ContextConfig；无 role 时保持第一批默认契约。"""
    trigger, reserve, tool_limit = _ROLE_CONTEXT_PROFILES.get(
        role.strip().lower(),
        (TRIGGER_RATIO, RESERVE_RATIO, TOOL_RESULT_LIMIT),
    )
    return ContextConfig(
        trigger_ratio=trigger,
        reserve_ratio=reserve,
        tool_result_limit=tool_limit,
        summary_schema=SUMMARY_SCHEMA,
        summary_template=SUMMARY_TEMPLATE,
    )


def build_role_agent_state(mission_id: str, role: str) -> AgentState:
    """返回角色会话状态：offload 分区键 = ``{mission_id}-{role}``。"""
    return AgentState(session_id=f"{mission_id}-{role}")
