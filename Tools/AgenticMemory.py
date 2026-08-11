"""
长期经验记忆 — 存储历史任务的成功攻击链
供 Brain 制定计划时参考历史经验。
"""
import json
import os
from datetime import datetime

from Tools.tooling import AllowedFunctionTool

# 记忆文件路径
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_MEMORY_FILE = os.path.join(_PROJECT_ROOT, "../.LongMemory", "agentic_memory.json")


def _load():
    """加载经验记忆。"""
    if not os.path.exists(_MEMORY_FILE):
        return {"missions": [], "techniques": {}}
    try:
        with open(_MEMORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"missions": [], "techniques": {}}


def _save(data):
    """保存经验记忆。"""
    os.makedirs(os.path.dirname(_MEMORY_FILE), exist_ok=True)
    with open(_MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def save_mission(target, goal, plan, attack_chain, success, summary, flag=None):
    """保存一次任务的完整经验。

    Args:
        target: 目标 IP/域名
        goal: 任务目标
        plan: Brain 制定的计划
        attack_chain: 攻击链步骤列表
        success: 是否成功
        summary: 任务总结
    """
    data = _load()
    mission = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "goal": goal,
        "plan": str(plan),
        "attack_chain": attack_chain,
        "success": success,
        "summary": summary,
        "flag": flag,
    }
    data["missions"].append(mission)

    # 如果成功，记录技术映射
    if success and attack_chain:
        for step in attack_chain:
            if isinstance(step, dict) and "service" in step and "cve" in step:
                key = step["service"]
                data["techniques"].setdefault(key, []).append({
                    "cve": step["cve"],
                    "timestamp": datetime.now().isoformat(),
                    "success": True,
                })

    # 只保留最近 50 条任务
    if len(data["missions"]) > 50:
        data["missions"] = data["missions"][-50:]

    _save(data)


def query_experience(service=None, limit=5):
    """查询历史经验。

    Args:
        service: 服务名称（如 "Apache 2.4.49"），为 None 时返回最近任务
        limit: 最大返回条数

    Returns:
        dict: 查询结果
    """
    data = _load()

    if service:
        techniques = data["techniques"].get(service, [])
        related_missions = []
        for m in data["missions"]:
            plan_str = str(m.get("plan", ""))
            if service.lower() in plan_str.lower():
                related_missions.append(m)

        return {
            "service": service,
            "known_exploits": techniques[-limit:],
            "related_missions": related_missions[-3:],
        }

    return {
        "recent_missions": data["missions"][-limit:],
        "total_missions": len(data["missions"]),
    }


def get_experience_hint():
    """生成给 Brain 的经验提示文本。"""
    data = _load()
    if not data["techniques"]:
        return ""

    hints = ["## 历史成功经验"]
    for service, entries in list(data["techniques"].items())[-5:]:
        cves = list(set(e["cve"] for e in entries[-3:]))
        hints.append(f"- {service}: 可利用 {', '.join(cves)}")
    return "\n".join(hints)


def _format_experience(result: dict, service: str) -> str:
    """把 query_experience 结果格式化为给 LLM 的 markdown 文本。"""
    if service:
        exploits = result.get("known_exploits", [])
        missions = result.get("related_missions", [])
        if not exploits and not missions:
            return (
                f"未找到服务「{service}」相关的历史攻击经验，"
                "请依靠当前侦察证据制定方案，不要臆测 CVE。"
            )
        lines = [f"## 历史经验：{service}"]
        if exploits:
            lines.append("已知可利用 CVE：")
            for e in exploits:
                lines.append(f"- {e.get('cve', '?')}（记录于 {e.get('timestamp', '?')}）")
        if missions:
            lines.append("相关历史任务：")
            for m in missions:
                mark = "成功" if m.get("success") else "失败"
                lines.append(
                    f"- [{mark}] 目标 {m.get('target', '?')}，目标 {m.get('goal', '?')}"
                    f" → {str(m.get('summary', ''))[:200]}",
                )
        return "\n".join(lines)

    recent = result.get("recent_missions", [])
    total = result.get("total_missions", 0)
    if not recent:
        return "当前暂无历史任务经验。"
    lines = [f"## 近期历史任务（共 {total} 条，最近 {len(recent)} 条）"]
    for m in recent:
        mark = "成功" if m.get("success") else "失败"
        flag = f"，flag={m.get('flag')}" if m.get("flag") else ""
        lines.append(
            f"- [{mark}] {m.get('target', '?')} · {m.get('goal', '?')} · {m.get('timestamp', '?')}{flag}",
        )
    return "\n".join(lines)


def create_query_memory_tool() -> AllowedFunctionTool:
    """创建 QueryMemory 工具：按服务名查询长期记忆中的历史攻击经验。"""

    def QueryMemory(service: str = "", limit: int = 5) -> str:
        """查询长期记忆中的历史攻击经验。

        服务名精确匹配已知 CVE 与相关历史任务；
        服务名为空时返回近期任务概览。

        Args:
            service: 服务名（如 "Apache 2.4.49"），留空则返回近期任务。
            limit: 返回条数上限，默认 5。
        """
        result = query_experience(service=service.strip() or None, limit=limit)
        return _format_experience(result, service.strip())

    return AllowedFunctionTool(QueryMemory, is_read_only=True)
