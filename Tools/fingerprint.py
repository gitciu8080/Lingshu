"""动作指纹与循环收敛辅助。

计划第 6 节：
- 动作指纹由工具名、目标、规范化参数、目标描述和证据版本计算，
  而不是只比较 objective 文本。
- 相同动作＋相同错误最多执行两次；第三次自动熔断并标记对应计划项
  blocked/interrupted。
- Connection refused、固定 404、超时等错误按类型累计；没有新证据时
  禁止通过改写自然语言绕过去重。
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

# 熔断阈值：相同动作+相同错误最多执行 MAX_RETRIES 次
MAX_ACTION_RETRIES = 2

# 常见确定性错误指纹（按类型累计，防止改写措辞绕过熔断）
_DETERMINISTIC_ERROR_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("connection_refused", re.compile(r"connection\s+refused", re.IGNORECASE)),
    ("timeout", re.compile(r"timed?\s*out|timeout", re.IGNORECASE)),
    ("http_404", re.compile(r"\b404\b|not\s+found", re.IGNORECASE)),
    ("http_403", re.compile(r"\b403\b|forbidden", re.IGNORECASE)),
    ("invalid_flag", re.compile(r"flag.*(?:wrong|incorrect|错误)|wrong.*flag", re.IGNORECASE)),
    ("auth_failed", re.compile(r"(?:authentication|login|auth)\s+(?:failed|错误)", re.IGNORECASE)),
]


def compute_action_fingerprint(
    tool_name: str,
    target: str,
    params: dict[str, Any] | None,
    objective: str,
    evidence_version: int,
) -> str:
    """计算动作指纹：工具名|目标|规范化参数|目标描述|证据版本。

    - params 规范化（排序键、紧凑 JSON），等价参数得到同一指纹；
    - objective 参与但不再唯一决定（防止只改措辞绕过去重）；
    - evidence_version 变化（有新证据）允许新动作。
    """
    normalized = json.dumps(params or {}, sort_keys=True, ensure_ascii=False)
    raw = f"{tool_name}|{target}|{normalized}|{objective.strip()}|{evidence_version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def error_type(result_text: str) -> str | None:
    """从工具/Agent 返回文本中识别确定性错误类型；无匹配返回 None。"""
    for name, pattern in _DETERMINISTIC_ERROR_PATTERNS:
        if pattern.search(result_text):
            return name
    return None


def should_meltdown(
    retry_counters: dict[str, int],
    fingerprint: str,
    *,
    max_retries: int = MAX_ACTION_RETRIES,
) -> bool:
    """判断是否触发熔断：相同指纹已执行 >= max_retries 次。"""
    return retry_counters.get(fingerprint, 0) >= max_retries


def mark_plan_item_blocked(mission, fingerprint: str, reason: str) -> str | None:
    """把与指纹相关的 in_progress 计划项标记为 blocked/interrupted。

    返回被标记的计划项 id；无匹配时返回 None。
    """
    for item in mission.plan_items:
        if item.get("status") == "in_progress":
            item["status"] = "interrupted"
            item.setdefault("evidence", "")
            item["interrupt_reason"] = reason
            mission.record(
                "Orchestrator",
                "plan_item_meltdown",
                item_id=item["id"],
                fingerprint=fingerprint,
                reason=reason,
            )
            return item["id"]
    return None
