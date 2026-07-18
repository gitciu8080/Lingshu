"""
长期经验记忆 — 存储历史任务的成功攻击链
供 Brain 制定计划时参考历史经验。
"""
import json
import os
from datetime import datetime

# 记忆文件路径
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_MEMORY_FILE = os.path.join(_PROJECT_ROOT, ".LongMemory", "agentic_memory.json")


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
