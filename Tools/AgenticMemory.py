"""
长期经验记忆 — 存储历史任务的成功攻击链
供 Brain 制定计划时参考历史经验。
"""
import json
import os
import hashlib
import re
from datetime import datetime
from pathlib import Path

from Tools.tooling import AllowedFunctionTool

# 记忆文件路径
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_MEMORY_FILE = os.path.join(_PROJECT_ROOT, "../.LongMemory", "agentic_memory.json")
_RAG_ARCHIVE_DIR = Path(_PROJECT_ROOT).parent / ".RAG" / "long-memory"
_MAX_HOT_MISSIONS = 50


def _atomic_write(path: Path, content: str) -> None:
    """原子写入归档卡片，避免任务中断产生半个 Markdown 文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _redact(text: object) -> str:
    """移除冷记忆中不应进入 RAG 的目标、URL、flag 和疑似凭据。"""
    value = str(text or "")
    value = re.sub(r"https?://\S+", "[已脱敏 URL]", value, flags=re.IGNORECASE)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[已脱敏目标]", value)
    value = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "[已脱敏域名]", value)
    value = re.sub(r"(?:flag|ctf|nssctf)\{[^}\r\n]{1,512}\}", "[已脱敏 Flag]", value, flags=re.IGNORECASE)
    value = re.sub(r"(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*\S+", r"\1=[已脱敏]", value)
    return " ".join(value.split())[:300]


def _collect_technique_tags(mission: dict) -> list[str]:
    """只提取结构化/明确标记，绝不把原始报告或命令写入知识库。"""
    tags: set[str] = set()
    for value in (mission.get("goal"), mission.get("plan"), mission.get("summary")):
        tags.update(re.findall(r"\bCVE-\d{4}-\d{4,8}\b", str(value or ""), re.IGNORECASE))
    for step in mission.get("attack_chain") or []:
        if not isinstance(step, dict):
            continue
        for key in ("service", "cve", "technique", "category"):
            value = step.get(key)
            if isinstance(value, str) and value.strip():
                tags.add(_redact(value.strip())[:80])
    return sorted(tag for tag in tags if tag)[:12]


def _archive_cold_mission(mission: dict) -> Path:
    """将超出热记忆上限的任务压缩为脱敏经验卡片。"""
    timestamp = str(mission.get("timestamp") or "unknown")
    digest = hashlib.sha256(timestamp.encode("utf-8")).hexdigest()[:12]
    safe_date = re.sub(r"[^0-9]", "", timestamp)[:14] or "unknown"
    destination = _RAG_ARCHIVE_DIR / f"mission-{safe_date}-{digest}.md"
    tags = _collect_technique_tags(mission)
    outcome = "成功" if mission.get("success") else "未成功"
    goal = _redact(mission.get("goal")) or "未记录任务目标"
    tag_text = ", ".join(tags) if tags else "无可确认的服务或漏洞标识"
    content = "\n".join([
        "---",
        "type: mission_lesson",
        "source: long_memory_archive",
        f"outcome: {outcome}",
        "sensitivity: sanitized",
        "---",
        "",
        "# 历史任务经验卡片",
        "",
        f"- 归档时间：{safe_date}",
        f"- 任务类型：{goal}",
        f"- 关联技术：{tag_text}",
        f"- 攻击链步骤数：{len(mission.get('attack_chain') or [])}",
        "",
        "## 使用约束",
        "",
        "该卡片仅用于提供历史方向；必须以当前授权目标的侦察证据重新验证。"
        "卡片不包含原始目标、Flag、凭据、完整命令或原始工具输出。",
        "",
    ])
    _atomic_write(destination, content)
    return destination


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

    # 将本次任务同步生成一张脱敏经验卡片。此前只有热记忆溢出时才写入
    # `.RAG/long-memory`，导致绝大多数刚完成的任务不能被 RAG 检索到。
    # 卡片经 _redact 处理，不包含原始目标、Flag、凭据或完整工具输出。
    try:
        _archive_cold_mission(mission)
    except OSError:
        # RAG 归档是派生数据；热记忆仍会保存，后续任务可以再次尝试归档。
        pass

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

    # 热记忆只保留最近任务；较早记录先压缩成脱敏 Markdown 卡片，供 `.RAG`
    # 在下次同步时索引。归档失败不能阻断任务收尾，原记录仍会留在热记忆中。
    overflow = data["missions"][:-_MAX_HOT_MISSIONS]
    if overflow:
        archived = 0
        for old_mission in overflow:
            try:
                _archive_cold_mission(old_mission)
                archived += 1
            except OSError:
                # 保留未归档原记录，下一次保存时重试，避免静默丢失历史经验。
                break
        if archived:
            data["missions"] = data["missions"][archived:]

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
