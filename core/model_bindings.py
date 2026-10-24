"""用户级 Agent 模型分工（每角色绑定一个 LLM 运行时 key + 模型名）。

存储在 users.db 的 ``agent_model_bindings`` 表（建表迁移见 core/auth.py）。
绑定是用户级默认值：创建任务时仍只选一个主模型，未绑定的角色沿用主模型；
绑定解析失败（配置已被删除等）自动回退主模型，不阻断任务启动。
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from core.auth import get_db

# 参与模型分工的 Agent 角色（scope_auditor 等轻量角色不开放，沿用主模型）。
AGENT_MODEL_ROLES: tuple[str, ...] = (
    "orchestrator", "brain", "recon", "triage", "attack",
    "reserve", "analysis", "summary",
)

ROLE_LABELS: dict[str, str] = {
    "orchestrator": "调度中枢（Alex）",
    "brain": "战略规划（Sophia）",
    "recon": "网络侦察（Ethan）",
    "triage": "文件分析（Iris）",
    "attack": "攻击专家",
    "reserve": "逆向分析（Ryan）",
    "analysis": "漏洞研判（Nora）",
    "summary": "任务总结（Mia）",
}

INTENSITIES: tuple[str, ...] = ("off", "low", "medium", "high")


def get_agent_model_bindings(user_id: int) -> dict[str, dict[str, Any]]:
    """返回 {role: {provider, model, thinking_intensity}}；无绑定时为空 dict。"""
    conn: sqlite3.Connection = get_db()
    try:
        rows = conn.execute(
            "SELECT role, provider, model, thinking_intensity "
            "FROM agent_model_bindings WHERE user_id = ?",
            (user_id,),
        ).fetchall()
    finally:
        conn.close()
    return {
        str(row["role"]): {
            "provider": str(row["provider"] or ""),
            "model": str(row["model"] or ""),
            "thinking_intensity": row["thinking_intensity"],
        }
        for row in rows
        if str(row["role"] or "") in AGENT_MODEL_ROLES
    }


def set_agent_model_binding(
    user_id: int,
    role: str,
    provider: str,
    model: str,
    thinking_intensity: str | None = None,
) -> None:
    """UPSERT 单个角色的绑定；thinking_intensity 传 None 表示跟随主模型。"""
    if role not in AGENT_MODEL_ROLES:
        raise ValueError(f"未知的 Agent 角色: {role}")
    if not provider or not model:
        raise ValueError("绑定必须同时提供供应商与模型")
    if thinking_intensity is not None and thinking_intensity not in INTENSITIES:
        raise ValueError("思考强度仅支持 off/low/medium/high 或留空")
    conn: sqlite3.Connection = get_db()
    try:
        conn.execute(
            """
            INSERT INTO agent_model_bindings
                (user_id, role, provider, model, thinking_intensity, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, role) DO UPDATE SET
                provider = excluded.provider,
                model = excluded.model,
                thinking_intensity = excluded.thinking_intensity,
                updated_at = excluded.updated_at
            """,
            (
                user_id, role, provider, model, thinking_intensity,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def clear_agent_model_binding(user_id: int, role: str) -> None:
    """删除单个角色的绑定（恢复“跟随主模型”）。"""
    conn: sqlite3.Connection = get_db()
    try:
        conn.execute(
            "DELETE FROM agent_model_bindings WHERE user_id = ? AND role = ?",
            (user_id, role),
        )
        conn.commit()
    finally:
        conn.close()


def resolve_role_models(
    bindings: dict[str, dict[str, Any]],
    build_model: Callable[..., Any],
    shared_model: Any,
    default_intensity: str,
) -> tuple[dict[str, Any], list[str]]:
    """把绑定字典解析为 {role: 模型实例}。

    - ``build_model(provider, model, thinking_intensity)`` 由调用方注入
      （内部按 (provider, model, intensity) 去重，同组合只构建一次）；
    - 解析失败（如绑定的供应商配置已被删除）不抛错：记录到 warnings 并
      让该角色回退 ``shared_model``，任务照常启动；
    - 未绑定的角色不出现在结果里，调用方按主模型处理。
    """
    resolved: dict[str, Any] = {}
    warnings: list[str] = []
    cache: dict[tuple[str, str, str], Any] = {}
    for role, binding in (bindings or {}).items():
        provider = str((binding or {}).get("provider") or "")
        model_name = str((binding or {}).get("model") or "")
        intensity = (binding or {}).get("thinking_intensity") or default_intensity
        if not provider or not model_name:
            continue
        cache_key = (provider, model_name, str(intensity))
        try:
            if cache_key not in cache:
                cache[cache_key] = build_model(provider, model_name, str(intensity))
            resolved[role] = cache[cache_key]
        except Exception as exc:  # noqa: BLE001
            warnings.append(
                f"角色 {role} 绑定的模型 {provider}/{model_name} 不可用"
                f"（{exc}），已回退主模型"
            )
    return resolved, warnings
