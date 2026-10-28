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
from typing import Any

from Tools.tooling import AllowedFunctionTool

# 记忆文件路径
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_MEMORY_FILE = os.path.join(_PROJECT_ROOT, "../.LongMemory", "agentic_memory.json")
_RAG_ARCHIVE_DIR = Path(_PROJECT_ROOT).parent / ".RAG" / "long-memory"
_MAX_HOT_MISSIONS = 50

# 反思经验提炼的上限条数
_LESSON_MAX = 8


# 确定性失败分类 → 人类可读教训前缀（与 Tools/fingerprint.py 的 failure_type 对齐）
_LESSON_LABELS = {
    "transient": "临时性失败",
    "parameter": "参数错误",
    "tool": "工具不可用",
    "environment": "环境受限",
    "method": "方法失效",
    "hypothesis_rejected": "假设被证伪",
}


def extract_lessons(
    failed_paths: list[Any] | None = None,
    attack_chain: list[dict[str, Any]] | None = None,
    success: bool = False,
) -> list[str]:
    """从失败路径与攻击链中确定性提炼脱敏经验条目（不调用 LLM）。

    - failed_paths: FailedPathRecord 或同构 dict，取 failure_type/failure_reason。
    - attack_chain: 攻击链步骤（dict），成功时提取 service/cve 成功路径。
    - 输出统一经 ``_redact`` 脱敏并去重，最多 ``_LESSON_MAX`` 条。

    Returns:
        教训列表；无失败路径且未成功时返回空列表。
    """
    lessons: list[str] = []
    seen: set[str] = set()

    def _push(text: str) -> None:
        cleaned = _redact(text)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            lessons.append(cleaned)

    for entry in failed_paths or []:
        if isinstance(entry, dict):
            ftype = entry.get("failure_type")
            reason = entry.get("failure_reason")
        else:
            ftype = getattr(entry, "failure_type", None)
            reason = getattr(entry, "failure_reason", None)
        label = _LESSON_LABELS.get(str(ftype or ""), "失败路径")
        if reason:
            _push(f"{label}: {str(reason)[:200]}")
        elif ftype:
            _push(f"{label}（无详细原因）")

    if success:
        for step in attack_chain or []:
            if not isinstance(step, dict):
                continue
            service = step.get("service")
            cve = step.get("cve")
            if service:
                _push(f"成功路径: {service} 可利用 {cve or '未记录 CVE'}")

    return lessons[: _LESSON_MAX]


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
    # IPv6（含压缩形式与 zone id）；前置负断言避免误伤单冒号文本
    value = re.sub(
        r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?:%\w+)?",
        "[已脱敏目标]",
        value,
    )
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
    lesson_lines = mission.get("lessons") or []
    lesson_section: list[str] = []
    if lesson_lines:
        lesson_section.append("lessons:")
        for line in lesson_lines:
            # 防御性脱敏：即使 lessons 未经 extract_lessons 生成，归档也不泄露目标信息
            lesson_section.append(f"  - {_redact(line)}")
    content = "\n".join([
        "---",
        "type: mission_lesson",
        "source: long_memory_archive",
        f"outcome: {outcome}",
        "sensitivity: sanitized",
        *lesson_section,
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
    """加载经验记忆。损坏时隔离原文件并告警，不再静默清零历史。"""
    if not os.path.exists(_MEMORY_FILE):
        return {"missions": [], "techniques": {}}
    try:
        with open(_MEMORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        corrupt = f"{_MEMORY_FILE}.corrupt.{datetime.now().strftime('%Y%m%d%H%M%S')}"
        try:
            os.replace(_MEMORY_FILE, corrupt)
        except OSError:
            corrupt = "(隔离失败)"
        print(
            f"[memory] ⚠ 长期记忆文件损坏（{exc}），已隔离为 {corrupt}；"
            "历史经验从空开始重建。", flush=True,
        )
        return {"missions": [], "techniques": {}}


def _save(data):
    """保存经验记忆。"""
    os.makedirs(os.path.dirname(_MEMORY_FILE), exist_ok=True)
    with open(_MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def save_mission(target, goal, plan, attack_chain, success, summary, flag=None, lessons=None):
    """保存一次任务的完整经验。

    Args:
        target: 目标 IP/域名
        goal: 任务目标
        plan: Brain 制定的计划
        attack_chain: 攻击链步骤列表
        success: 是否成功
        summary: 任务总结
        flag: 已确认 Flag（可选）
        lessons: 任务后反思沉淀的脱敏教训列表（可选，默认空）
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
        "lessons": list(lessons or []),
    }
    data["missions"].append(mission)

    # 记录技术映射：步骤含 service/cve/technique/category 任一即写入。
    # （旧逻辑要求 service 与 cve 同时命中，实测 techniques 几乎恒空。）
    if success and attack_chain:
        for step in attack_chain:
            if not isinstance(step, dict):
                continue
            service = str(step.get("service") or step.get("technique")
                          or step.get("category") or "").strip()
            cve = str(step.get("cve") or "").strip()
            if not service and not cve:
                continue
            key = _redact(service or cve)[:80]
            if not key:
                continue
            data["techniques"].setdefault(key, []).append({
                "cve": cve or "未记录 CVE",
                "objective": _redact(step.get("objective"))[:120],
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


def _tokenize(text: object) -> set[str]:
    """轻量分词：中英文/数字混合（小写），过滤单字符噪音。"""
    return {
        token for token in re.split(r"[^\w\u4e00-\u9fff\-]+", str(text or "").lower())
        if len(token) >= 2
    }


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
        # 大小写不敏感的包含匹配：查询词与 techniques 键任一方包含另一方即命中。
        lowered = service.lower()
        techniques = []
        for key, entries in data["techniques"].items():
            key_l = str(key).lower()
            if key_l == lowered or lowered in key_l or key_l in lowered:
                techniques.extend(entries)
        # 相关任务：分词加权打分（goal/plan/summary 与查询词的词元交集），
        # 替代旧的 plan 单字段包含匹配——措辞不同但同技术的任务也能命中
        query_tokens = _tokenize(service)
        scored: list[tuple[float, dict]] = []
        for m in data["missions"]:
            if str(service).lower() in str(m.get("plan", "")).lower():
                scored.append((10.0, m))
                continue
            mission_tokens = _tokenize(
                f"{m.get('goal', '')} {m.get('plan', '')} {m.get('summary', '')}")
            overlap = len(query_tokens & mission_tokens)
            if overlap >= 2:
                scored.append((float(overlap), m))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        related_missions = [m for _score, m in scored[:3]]

        return {
            "service": service,
            "known_exploits": techniques[-limit:],
            "related_missions": related_missions,
        }

    return {
        "recent_missions": data["missions"][-limit:],
        "total_missions": len(data["missions"]),
    }


def get_experience_hint():
    """生成规划期经验提示文本（Brain 注入 + fast 模式 Captain 首条输入）。

    内容三段（各自为空则跳过）：历史成功技术、最近失败教训（lessons
    此前无任何消费路径，这里补上闭环）、近期任务概览。全部脱敏。
    """
    data = _load()
    missions = data.get("missions") or []
    techniques = data.get("techniques") or {}
    hints: list[str] = []

    if techniques:
        block = ["## 历史成功经验"]
        for service, entries in list(techniques.items())[-5:]:
            cves = list({str(e.get("cve") or "?") for e in entries[-3:]})
            block.append(f"- {_redact(service)}: 可利用 {', '.join(cves)}")
        hints.append("\n".join(block))

    lessons: list[str] = []
    seen: set[str] = set()
    for mission in reversed(missions[-10:]):
        for line in mission.get("lessons") or []:
            cleaned = _redact(line)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                lessons.append(cleaned)
    if lessons:
        block = ["## 历史失败教训（同类任务避免重蹈）"]
        lessons.sort()   # 时间倒序收集，按内容稳定排序保证提示确定性
        for line in lessons[-6:]:
            block.append(f"- {line}")
        hints.append("\n".join(block))

    if missions:
        block = [f"## 近期任务概览（共 {len(missions)} 条，最近 3 条）"]
        for mission in missions[-3:]:
            mark = "成功" if mission.get("success") else "失败"
            block.append(
                f"- [{mark}] {_redact(mission.get('goal'))[:80]}"
                f"（{str(mission.get('timestamp') or '?')[:10]}）"
            )
        hints.append("\n".join(block))

    return "\n\n".join(hints)


def _format_experience(result: dict, service: str) -> str:
    """把 query_experience 结果格式化为给 LLM 的 markdown 文本（全量脱敏）。

    跨任务提示一律不回传原始 target/URL/flag——上一任务的 flag 进入后续
    任务上下文既泄漏也无决策价值。
    """
    if service:
        exploits = result.get("known_exploits", [])
        missions = result.get("related_missions", [])
        if not exploits and not missions:
            return (
                f"未找到服务「{_redact(service)}」相关的历史攻击经验，"
                "请依靠当前侦察证据制定方案，不要臆测 CVE。"
            )
        lines = [f"## 历史经验：{_redact(service)}"]
        if exploits:
            lines.append("已知可利用 CVE：")
            for e in exploits:
                lines.append(f"- {e.get('cve', '?')}（记录于 {e.get('timestamp', '?')}）")
        if missions:
            lines.append("相关历史任务：")
            for m in missions:
                mark = "成功" if m.get("success") else "失败"
                lines.append(
                    f"- [{mark}] 目标类型 {_redact(m.get('goal'))[:80]}"
                    f" → {_redact(m.get('summary'))[:160]}"
                )
        return "\n".join(lines)

    recent = result.get("recent_missions", [])
    total = result.get("total_missions", 0)
    if not recent:
        return "当前暂无历史任务经验。"
    lines = [f"## 近期历史任务（共 {total} 条，最近 {len(recent)} 条）"]
    for m in recent:
        mark = "成功" if m.get("success") else "失败"
        lines.append(
            f"- [{mark}] {_redact(m.get('goal'))[:80]} · {m.get('timestamp', '?')}",
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
