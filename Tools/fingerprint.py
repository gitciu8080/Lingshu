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

_FAILURE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("transient", re.compile(
        r"timed?\s*out|timeout|temporar(?:y|ily)|connection\s+(?:reset|refused)|"
        r"rate.?limit|\b429\b|\b502\b|\b503\b|\b504\b", re.IGNORECASE,
    )),
    ("parameter", re.compile(
        r"invalid\s+(?:argument|parameter)|bad\s+request|schema|json.*(?:invalid|error)|"
        r"参数.*(?:错误|无效)|格式.*(?:错误|无效)", re.IGNORECASE,
    )),
    ("tool", re.compile(
        r"tool.*(?:unavailable|not found|missing|不可用)|command\s+not\s+found|"
        r"no such tool|mcp.*(?:failed|unavailable|连接失败)", re.IGNORECASE,
    )),
    ("environment", re.compile(
        r"permission\s+denied|no such file|read.?only file system|"
        r"环境.*(?:错误|不可用)|依赖.*(?:缺失|不存在)|预算.*耗尽", re.IGNORECASE,
    )),
    ("hypothesis_rejected", re.compile(
        r"hypothesis.*(?:false|rejected|disproved)|假设.*(?:证伪|不成立)|"
        r"明确排除|not vulnerable", re.IGNORECASE,
    )),
    ("method", re.compile(
        r"超迭代|maximum\s+(?:reasoning[- ]acting\s+)?iterations|"
        r"exceed_max_iters|未返回(?:文本)?结果|\[熔断\]", re.IGNORECASE,
    )),
]

_SUCCESS_MARKERS = re.compile(
    r"\b(success|succeeded|confirmed|valid)\b|成功|已确认|flag\{", re.IGNORECASE,
)
_FAILURE_MARKERS = re.compile(
    r"<returncode>(?!0</returncode>)-?\d+</returncode>|"
    r"^\s*(?:\[(?:[^\]]*失败|拒绝|不可用|超时|ERROR|FAILED)[^\]]*\]|"
    r"(?:error|failed|failure)\s*:)", re.IGNORECASE,
)


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


def compute_tool_signature(
    tool_name: str,
    target: str,
    params: dict[str, Any] | None,
) -> tuple[str, dict[str, str]]:
    """生成工具/MCP 的确定性签名，并提取决策所需字段。

    完整规范化参数参与签名；target/context/endpoint/method/payload/command
    被单独抽取，方便 Failed Path 展示。调用者若确需合法重放，应显式改变
    context/precondition 等参数，或由 transient retry 策略放行。
    """
    values = params or {}

    def _pick(*names: str) -> str:
        for name in names:
            value = values.get(name)
            if value is not None and value != "":
                if isinstance(value, (dict, list)):
                    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                return str(value).strip()
        return ""

    fields = {
        "target": _pick("target", "host", "url", "target_info") or target,
        "context": _pick("context", "focus", "objective", "precondition", "service_info"),
        "endpoint": _pick("endpoint", "url", "path", "uri"),
        "method": _pick("method", "http_method").upper(),
        "payload": _pick("payload", "body", "data", "json"),
        "command": _pick("command", "cmd", "code", "query"),
    }
    # hypothesis_id 仅是状态关联键，不是执行语义；把它计入签名会允许模型通过
    # 新建同义假设绕过去重。其余参数（包括 context/objective/precondition）
    # 全部参与签名，以保留合法的新上下文执行。
    signature_parameters = {
        key: value for key, value in values.items() if key != "hypothesis_id"
    }
    canonical = json.dumps(
        {"tool": tool_name, "target": target, "parameters": signature_parameters},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), fields


def classify_failure(result_text: str, *, raised: bool = False) -> tuple[str | None, str, str]:
    """返回 (failure_type, reason, resolution)。None 表示有效/未识别为失败。"""
    text = result_text or ""
    if not raised and _SUCCESS_MARKERS.search(text) and not _FAILURE_MARKERS.search(text):
        return None, "", "continue"
    for failure_type, pattern in _FAILURE_PATTERNS:
        match = pattern.search(text)
        if match:
            resolution = {
                "transient": "retry",
                "parameter": "modify_parameters",
                "tool": "fallback",
                "environment": "fallback",
                "hypothesis_rejected": "stop_path",
                "method": "fallback",
            }[failure_type]
            return failure_type, match.group(0)[:300], resolution
    if not raised and not _FAILURE_MARKERS.search(text):
        return None, "", "continue"
    reason = text.strip().replace("\n", " ")[:300] or "工具执行失败"
    return "method", reason, "fallback"


def has_success_signal(result_text: str) -> bool:
    """确定性识别明确成功信号；普通有效输出不等同于支持假设。"""
    return bool(_SUCCESS_MARKERS.search(result_text or ""))


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
