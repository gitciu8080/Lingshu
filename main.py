#!/usr/bin/env python3
"""灵枢：基于 AgentScope 2.x 的多智能体授权安全测试入口。

v0.2.0 数据流:
  parse_target() → prepare_workspace() → initial_classify()
  → Brain(含分类结果) → Orchestrator(根据 kind 路由 Recon/Triage)
  → post_recon_classify() → 创建 Attack(动态加载 Skill) → Writeup
"""
from __future__ import annotations

import argparse  # 命令行参数解析
import asyncio  # 异步事件循环，驱动整个多智能体任务
import json  # 审批方案选择协议与结构化消息解析
import os  # 环境变量与路径操作
import re  # 从最终证据中提取 CVE 等标题特征
import sys  # 修改模块搜索路径，确保能 import 本目录下的包
from collections.abc import Callable  # 回调类型注解
from pathlib import Path  # 跨平台路径对象
from typing import Any  # 通用任意类型注解

# 将本文件所在目录加入模块搜索路径，
# 这样无论从哪里启动 main.py 都能正确导入 config / LLM / agent 等兄弟模块。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentscope.message import UserMsg  # AgentScope 用户消息封装
from agentscope.types import ReplyFinishedReason

from config import RuntimeConfig  # 运行时配置（API Key、超时等，从环境变量读取）
from LLM.model import create_model  # 创建 LLM 模型实例（deepseek / qwen）
from TaskState import MissionState, MissionStore, Phase  # 任务状态、持久化存储、阶段枚举
from agent.Analysis import create_analysis_agent  # 漏洞研判专家（纯推理）
from Tools.archive import safe_extract, SafeExtractError  # 安全解压（防路径穿越等）
from agent.Attack import create_attack_agent  # 攻击手 Agent（分析 + 利用）
from agent.Brain import create_brain_agent  # 战略规划 Agent
from agent.categorize import classify  # 题型自动分类（CTF 题型识别）
from agent.Orchestrator import create_orchestrator_agent  # 战术调度核心 Agent
from agent.Recon import (
    create_artifact_triage_agent,  # 文件/归档目标的侦察（triage）Agent
    create_network_recon_agent,  # 网络目标侦察 Agent
)
from agent.Reserve import close_reverse_agent, create_reverse_agent  # 逆向分析 Agent（IDA MCP）
from agent.ScopeAuditor import create_scope_auditor_agent  # IP 授权审核 Agent
from agent.experts import build_expert_assignments
from Tools.Plan import create_add_plan_tool, push_plan_update  # Brain 登记计划条目的工具
from Tools.ScopeRegistry import ScopeRegistry  # 动态授权范围注册表
from Tools.KnowledgeBase import get_rag_service
from Tools.target import TargetSpec, normalize_target  # 目标规范化
from Tools.tooling import (  # 流式获取 Agent 回复并转发事件
    AgentMaxIterationsError,
    bind_agent_tasks,
    bind_expert_roster,
    bind_process_tracker,
    cancel_agent_tasks,
    reset_agent_tasks,
    reset_expert_roster,
    reset_process_tracker,
    run_interruptible_agent_reply,
)


# ── 工作目录规划 ──
# 所有网络任务的工作目录统一放在本文件同级目录下的 WorkDir/ 中，
# 文件/归档任务则在其下按「文件名_sha256前12位」建立独立子目录。
_WORKDIR_ROOT = Path(__file__).resolve().parent / "WorkDir"


# 肯定的审批答复（其余一律视为拒绝，安全默认）
_APPROVAL_YES = {"y", "yes", "ok", "approve", "approved", "是", "批准", "同意"}

# 用户任务描述中的明确目标声明。它只用于补充本次任务的初始授权范围；
# Agent 从扫描结果、页面内容等运行时证据中发现的新地址，仍必须走 ScopeAuditor。
_DECLARED_TARGET_LABEL = re.compile(
    r"(?:目标\s*(?:服务器|主机|地址|域名|IP|信息)?\s*[:：]|"
    r"(?:靶机|服务器|主机|域名)\s*(?:地址|信息)?\s*[:：]|"
    r"\b(?:ip|host|hostname)\s*[:：]|\bssh\s*(?:连接|地址))",
    re.IGNORECASE,
)
_DECLARED_URL = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_DECLARED_HOST_PORT = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}:\d{1,5}(?!\d)",
)
_DECLARED_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_DECLARED_HOSTNAME = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![\w.-])",
)

_CATEGORY_TITLES = {
    "web": "Web 安全",
    "pwn": "二进制利用",
    "reverse": "逆向分析",
    "crypto": "密码分析",
    "forensics": "数字取证",
    "malware": "恶意代码分析",
    "misc": "综合安全",
    "osint": "开源情报",
    "ai-ml": "AI 安全",
}


def build_mission_title(
    category: str,
    target_kind: str,
    goal: str,
    plan: str,
) -> str:
    """Generate a concise title without exposing the concrete target."""
    context = f"{goal}\n{plan[:6000]}".lower()
    resolved_category = category
    if resolved_category == "unknown":
        category_signals = {
            "web": ("http", "web", "网站", "接口", "路由", "目录枚举"),
            "pwn": ("pwn", "rop", "栈溢出", "堆利用", "二进制利用"),
            "reverse": ("逆向", "反编译", "ida", "ghidra", "crackme"),
            "crypto": ("密码", "解密", "rsa", "aes", "cipher"),
            "forensics": ("取证", "pcap", "内存镜像", "磁盘镜像", "隐写"),
            "malware": ("恶意软件", "木马", "勒索", "c2", "沙箱分析"),
            "osint": ("开源情报", "osint", "whois", "地理定位"),
            "ai-ml": ("提示注入", "模型", "llm", "机器学习"),
        }
        resolved_category = next(
            (
                name
                for name, signals in category_signals.items()
                if any(signal in context for signal in signals)
            ),
            "unknown",
        )

    category_title = _CATEGORY_TITLES.get(resolved_category)
    if category_title is None:
        category_title = {
            "network": "网络安全",
            "archive": "文件分析",
            "single_file": "文件分析",
            "directory": "代码审计",
        }.get(target_kind, "安全测试")

    intent_signals = (
        (("web shell", "webshell", "命令执行"), "权限获取"),
        (("提权", "权限提升"), "权限提升"),
        (("源码审计", "代码审计"), "代码审计"),
        (("解密", "密钥", "明文"), "密钥恢复"),
        (("逆向", "反编译", "程序分析"), "程序分析"),
        (("取证", "证据", "流量分析"), "证据提取"),
        (("漏洞", "验证", "利用"), "漏洞验证"),
        (("flag", "获取 flag"), "Flag 获取"),
    )
    def resolve_intent(source: str) -> str | None:
        return next(
            (
                label
                for signals, label in intent_signals
                if any(signal in source for signal in signals)
            ),
            None,
        )

    intent = resolve_intent(goal.lower()) or resolve_intent(plan.lower()) or "安全分析"
    return f"{category_title} - {intent}"


def prefix_session_title(session_id: str, title: str) -> str:
    """Prefix a title with a stable, compact session identifier."""
    return f"[{session_id[:8]}] {title}" if session_id else title


def build_final_mission_title(mission: MissionState) -> str:
    """Build a more specific title from the completed mission evidence."""
    category = str((mission.category_decision or {}).get("primary") or "unknown")
    target_kind = str((mission.target_spec or {}).get("kind") or "")
    reports = [mission.summary]
    reports.extend(str(item.get("report") or "") for item in mission.findings)
    reports.extend(
        f"{item.get('objective', '')} {item.get('report', '')} {item.get('cve', '')}"
        for item in mission.attack_chain
    )
    evidence = "\n".join(reports).lower()
    detail_signals = (
        (("sql注入", "sql 注入", "sql injection", "sqli"), "SQL 注入"),
        (("模板注入", "ssti"), "模板注入"),
        (("命令执行", "remote code execution", "rce"), "命令执行"),
        (("文件上传", "upload"), "文件上传"),
        (("任意文件读取", "目录穿越", "path traversal", "lfi"), "文件读取"),
        (("反序列化", "deserialization"), "反序列化"),
        (("身份绕过", "认证绕过", "auth bypass"), "认证绕过"),
        (("ssrf", "请求伪造"), "SSRF"),
        (("jwt",), "JWT 安全"),
        (("xxe",), "XXE"),
        (("xss", "跨站"), "XSS"),
        (("栈溢出", "堆溢出", "buffer overflow"), "内存破坏"),
        (("rop", "ret2libc"), "ROP 利用"),
        (("解密", "密钥恢复", "decrypt"), "密钥恢复"),
        (("隐写", "stego"), "隐写分析"),
        (("流量分析", "pcap"), "流量取证"),
    )
    detail = next(
        (
            label
            for signals, label in detail_signals
            if any(signal in evidence for signal in signals)
        ),
        None,
    )
    if detail is None:
        cve = re.search(r"cve-\d{4}-\d+", evidence, re.IGNORECASE)
        if cve:
            detail = cve.group(0).upper()
    base_title = build_mission_title(category, target_kind, mission.goal, evidence)
    category_title, _, initial_intent = base_title.partition(" - ")
    detail = detail or initial_intent
    if mission.success and mission.flag:
        outcome = "Flag 获取成功"
    elif mission.success:
        outcome = "验证成功"
    else:
        outcome = "任务未完成"
    return prefix_session_title(
        mission.session_id,
        f"{category_title} - {detail} - {outcome}",
    )

# 各角色基础迭代预算（按目标类型）——P2 自适应预算的基准表。
# 网络渗透任务涉及扫描/枚举/利用，预算最高；单文件取证相对收敛。
_ROLE_BASE_BUDGET = {
    "network": {"recon": 26, "attack": 28, "reserve": 22, "brain": 16},
    "archive": {"recon": 22, "attack": 28, "reserve": 28, "brain": 16},
    "single_file": {"recon": 16, "attack": 24, "reserve": 24, "brain": 14},
    "directory": {"recon": 22, "attack": 28, "reserve": 26, "brain": 16},
}

# 思考级别迭代加成：Max 深度推理多给，Low 快速收敛少给
_THINK_BONUS = {"Low": -4, "Min": 8, "Max": 16}
_ITER_BUDGET_MIN, _ITER_BUDGET_MAX = 12, 40


def _iter_budget(
    kind: str,
    role: str,
    model_ver: str = "Min",
    plan_items: int = 0,
) -> int:
    """按目标类型 + 思考级别 + 计划复杂度自适应计算 Agent 的 ReAct 迭代预算。

    Args:
        kind: 目标类型（network/archive/single_file/directory）。
        role: 角色（recon/attack/reserve/brain）。
        model_ver: 思考级别（Low/Min/Max）。
        plan_items: 已登记的结构化计划条目数（Brain 运行前为 0）。
    """
    base = _ROLE_BASE_BUDGET.get(kind, _ROLE_BASE_BUDGET["directory"])[role]
    # 计划越复杂给越多迭代（每 2 条计划 +2 轮，封顶 +8）
    plan_bonus = min(plan_items, 8) * 2
    think = _THINK_BONUS.get(model_ver, 0)
    return max(_ITER_BUDGET_MIN, min(_ITER_BUDGET_MAX, base + plan_bonus + think))


class _ApprovalBroker:
    """人工审批协调器：首次进入攻击阶段前等待操作员批准。

    双通道：
    - CLI 模式（无 input_queue）：在终端阻塞式询问 y/n；
    - API 模式：通过 event_callback 推送 approval_required 事件，
      并挂起等待 _poll_input_queue 经由 feed() 送入的用户答复。
    """

    def __init__(
        self,
        event_callback: Callable[[str, dict[str, Any]], None] | None,
        input_queue: asyncio.Queue | None,
    ) -> None:
        self._event_callback = event_callback
        self._input_queue = input_queue
        self._pending: asyncio.Future[dict[str, Any]] | None = None
        self._current_options: list[dict[str, Any]] = []
        self._recent_inputs: list[str] = []  # 近 5 条未被审批消费的消息，用于审批挂起时回看

    @property
    def waiting(self) -> bool:
        """当前是否有挂起等待答复的审批请求。"""
        return self._pending is not None and not self._pending.done()

    def stash_input(self, user_input: str) -> None:
        """缓存未被审批消费的用户消息（最多 5 条）。审批挂起时可用于回看。"""
        self._recent_inputs.append(user_input)
        if len(self._recent_inputs) > 5:
            self._recent_inputs.pop(0)

    async def request(self, reason: str, scan_summary: dict | None = None) -> dict[str, Any]:
        """发起一次攻击阶段审批请求，返回是否批准。

        Args:
            reason: LLM 写的攻击理由
            scan_summary: 可选的结构化扫描摘要（目标/侦察发现/作战计划等）
        """
        if self._input_queue is None:
            return await self._ask_cli(reason, scan_summary)
        return await self._ask_api(reason, scan_summary)

    async def _ask_cli(self, reason: str, scan_summary: dict | None = None) -> dict[str, Any]:
        """CLI 通道：终端询问操作员（executor 中运行避免阻塞事件循环）。"""
        print(f"\n{'='*60}")
        print(f"[人工审批] Orchestrator 请求进入攻击阶段（EXPLOITATION）")
        if scan_summary:
            target = scan_summary.get("target", "未知")
            print(f"[目标] {target}")
            findings = scan_summary.get("findings", [])
            if findings:
                print(f"[侦察发现] ({len(findings)} 条)")
                for f in findings[-3:]:  # 最近 3 条
                    print(f"  • [{f.get('source','?')}] {f.get('report','')[:200]}")
            plan_items = scan_summary.get("plan_items", [])
            if plan_items:
                print(f"[作战计划] ({len(plan_items)} 条)")
                for item in plan_items:
                    emoji = {"completed": "✅", "in_progress": "🔄", "pending": "⏳"}.get(item.get("status"), "⏳")
                    print(f"  {emoji} [{item.get('phase','?')}] {item.get('content','')}")
            options = scan_summary.get("approval_options", [])
            if options:
                print(f"[候选攻击方案] ({len(options)} 个)")
                for index, option in enumerate(options, 1):
                    print(f"  {index}. {option.get('title')} [风险 {option.get('risk')}] — {option.get('summary')}")
        print(f"[攻击理由] {reason}")
        print(f"{'='*60}")
        loop = asyncio.get_running_loop()
        try:
            answer = await loop.run_in_executor(
                None, input, "[人工审批] 是否批准？(y/n): ",
            )
        except (EOFError, KeyboardInterrupt):
            print("\n[人工审批] 输入中断，视为拒绝。")
            return {"approved": False, "decision": "拒绝", "selected_plan_id": "", "priority_order": []}
        approved = answer.strip().lower() in _APPROVAL_YES
        options = (scan_summary or {}).get("approval_options", [])
        selected = options[0].get("id", "") if options else ""
        priority_order = [str(option.get("id", "")) for option in options if option.get("id")]
        if approved and options:
            try:
                selection = await loop.run_in_executor(
                    None, input, f"[人工审批] 选择方案 (1-{len(options)}，默认 1): ",
                )
                if selection.strip().isdigit() and 1 <= int(selection) <= len(options):
                    selected = str(options[int(selection) - 1].get("id", selected))
            except (EOFError, KeyboardInterrupt):
                pass
        print(f"[人工审批] 操作员{'批准' if approved else '拒绝'}了攻击阶段授权。")
        return {
            "approved": approved,
            "decision": "批准" if approved else "拒绝",
            "selected_plan_id": selected,
            "priority_order": priority_order,
        }

    async def _ask_api(self, reason: str, scan_summary: dict | None = None) -> dict[str, Any]:
        """API 通道：推送 approval_required 事件，挂起等待用户答复。"""
        if self.waiting:
            return {"approved": False, "decision": "拒绝", "selected_plan_id": "", "priority_order": []}
        # 推送审批事件到 SSE
        payload: dict[str, Any] = {"reason": reason, "agent": "Orchestrator"}
        if scan_summary:
            payload["scan_summary"] = scan_summary
        self._current_options = list((scan_summary or {}).get("approval_options", []))
        if self._event_callback is not None:
            self._event_callback("approval_required", **payload)
        loop = asyncio.get_running_loop()
        self._pending = loop.create_future()
        # 回看近期缓存：若用户在审批请求到达前已发送了答复，直接消费
        for recent in self._recent_inputs:
            if self.feed(recent):
                self._recent_inputs.clear()
                return await self._pending
        self._recent_inputs.clear()
        try:
            return await self._pending
        finally:
            self._pending = None
            self._current_options = []

    def feed(self, user_input: str) -> bool:
        """处理 input_queue 收到的用户消息；返回 True 表示已被审批消费。
        支持三态决策：批准 / 补充侦察（视为拒绝但语义保留）/ 拒绝。
        """
        if not self.waiting:
            return False
        raw = user_input.strip()
        parsed: dict[str, Any] = {}
        if raw.startswith("{"):
            try:
                value = json.loads(raw)
                if isinstance(value, dict):
                    parsed = value
            except json.JSONDecodeError:
                pass
        decision = str(parsed.get("decision") or raw).strip()
        lower = decision.lower()
        approved = lower in _APPROVAL_YES
        allowed_ids = [str(option.get("id")) for option in self._current_options if option.get("id")]
        selected_plan_id = str(parsed.get("selected_plan_id") or (allowed_ids[0] if allowed_ids else ""))
        if allowed_ids and selected_plan_id not in allowed_ids:
            selected_plan_id = allowed_ids[0]
        priority_order = [
            str(value) for value in parsed.get("priority_order", [])
            if str(value) in allowed_ids
        ]
        for option_id in allowed_ids:
            if option_id not in priority_order:
                priority_order.append(option_id)
        result = {
            "approved": approved,
            "decision": decision,
            "selected_plan_id": selected_plan_id,
            "priority_order": priority_order,
        }
        if self._event_callback is not None:
            self._event_callback(
                "approval_resolved",
                approved=approved,
                decision=decision,
                selected_plan_id=selected_plan_id,
                priority_order=priority_order,
                agent="Orchestrator",
            )
        self._pending.set_result(result)
        return True


def _prepare_workspace(target_spec: TargetSpec) -> tuple[str, Path, dict | None]:
    """为文件/归档目标准备工作目录。

    根据目标类型（network / archive / single_file / directory）分别处理：
    - network:        直接返回 "host:port" 字符串与全局 WorkDir，无清单；
    - archive:        安全解压到独立子目录，并返回文件清单（数量/大小/文件列表）；
    - single_file:    工作目录为文件所在目录，目标字符串即文件绝对路径；
    - directory:      工作目录即目录本身。

    Returns:
        (target_string, workspace_path, manifest_dict|None)
        - target_string: 传给 Agent 的规范化目标描述
        - workspace_path: Agent 可用的工作目录（写入扫描产物等）
        - manifest_dict:  归档解压清单；非归档目标为 None
    """
    # ── 网络目标：无需解压，直接拼接 host:port ──
    if target_spec.kind == "network":
        host = target_spec.host or target_spec.original_input  # 兜底使用原始输入
        if target_spec.port is not None:
            return f"{host}:{target_spec.port}", _WORKDIR_ROOT, None
        return host, _WORKDIR_ROOT, None

    # ── 归档目标（.zip/.tar.gz/.pcapng 等）：安全解压到独立工作目录 ──
    if target_spec.kind == "archive" and target_spec.original_path is not None:
        # 以「文件名 + 内容 hash 前 12 位」命名工作目录，避免不同任务相互污染
        sha256 = target_spec.sha256 or "unknown"
        workdir = _WORKDIR_ROOT / f"{target_spec.original_path.stem}_{sha256[:12]}"
        print(f"[系统] 安全解压: {target_spec.original_path.name} → {workdir}")
        try:
            # safe_extract 内部校验校验和、拦截路径穿越/软链攻击等
            manifest = safe_extract(target_spec.original_path, workdir, sha256)
            # 转成普通 dict，便于后续传给 classify() 与持久化
            manifest_dict = {
                "file_count": manifest.file_count,
                "total_bytes": manifest.total_bytes,
                "files": manifest.files,
            }
            print(
                f"[系统] 解压完成: {manifest.file_count} 个文件, "
                f"{manifest.total_bytes:,} 字节"
            )
            return str(workdir), workdir, manifest_dict
        except SafeExtractError as exc:
            # 安全校验失败视为致命错误，直接终止任务
            raise SystemExit(f"[安全错误] 解压失败: {exc}") from exc

    # ── 单个文件目标：直接使用文件所在目录，目标即文件路径 ──
    if target_spec.kind == "single_file" and target_spec.original_path is not None:
        workdir = target_spec.original_path.parent
        return str(target_spec.original_path), workdir, None

    # ── 目录目标：目录本身就是工作区 ──
    if target_spec.kind == "directory" and target_spec.workspace is not None:
        return str(target_spec.workspace), target_spec.workspace, None

    # 理论上 normalize_target 已保证不会走到这里，兜底防御
    raise SystemExit(f"无法处理目标类型: {target_spec.kind}")


def _extract_declared_network_targets(text: str) -> list[str]:
    """提取用户明确写在任务说明中的网络目标。

    文件型任务常会把“目标服务器 IP / 域名 / SSH 端口”写在任务书中。
    这些信息与 API 中直接填写目标同属用户的初始授权输入，不能再被误判为
    Agent 运行时发现的范围扩容。为避免把一般文本中的域名误纳入范围，裸 IP
    与裸域名仅从带有目标语义的行（及其后两行）提取；完整 URL 和 host:port
    则被视为明确目标表达。
    """
    candidates: dict[str, int | None] = {}

    def add(value: str) -> None:
        value = value.rstrip(".,;，；:：")
        if not value:
            return
        try:
            spec = normalize_target(value)
        except ValueError:
            return
        if spec.kind == "network" and spec.host:
            # 同一个 URL 会同时命中 URL 与 hostname；显式端口优先，
            # 避免把 example.com 与 example.com:443 记成两个授权目标。
            if spec.port is not None or spec.host not in candidates:
                candidates[spec.host] = spec.port

    # URL、host:port 本身已经表达了连接目标，不依赖额外中文标签。
    for value in _DECLARED_URL.findall(text):
        add(value)
    for value in _DECLARED_HOST_PORT.findall(text):
        add(value)

    labelled_lines_remaining = 0
    for line in text.splitlines():
        is_labelled = bool(_DECLARED_TARGET_LABEL.search(line))
        if is_labelled:
            labelled_lines_remaining = 2
        if is_labelled or labelled_lines_remaining:
            for value in _DECLARED_IPV4.findall(line):
                add(value)
            for value in _DECLARED_HOSTNAME.findall(line):
                add(value)
        if labelled_lines_remaining:
            labelled_lines_remaining -= 1
    return sorted(
        f"{host}:{port}" if port is not None else host
        for host, port in candidates.items()
    )


async def run_mission(
    target: str,
    goal: str,
    model_ver: str = "Min",
    provider: str = "deepseek",
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
    session_id: str = "",
    input_queue: asyncio.Queue | None = None,
    initial_context: str | None = None,
    agent_tasks: set[asyncio.Task[Any]] | None = None,
    steering_state: dict[str, Any] | None = None,
    nss_context: dict[str, Any] | None = None,
    authorization_source: str = "cli",
) -> MissionState:
    """执行一次有明确授权范围的安全测试任务（核心工作流）。

    整体流程（详见各阶段注释）:
      1. 解析并规范化目标（normalize_target）
      2. 准备工作目录（归档目标安全解压）
      3. 初始题型分类（classify，供 Brain 与 Attack 参考）
      4. 初始化运行时配置与任务状态，持久化到 .TaskMemory/
      5. 创建模型与基础 Agent（Brain / Analysis）
      6. 按目标类型路由创建 Recon（网络侦察 或 文件 triage）
      7. Brain 制定战略计划（可提出题型修正建议，但无权修改）
      8. 延迟创建 Attack（等待可能的 reclassify 结果）
      9. Orchestrator 主循环调度，直至任务进入终态

    Args:
        target: 授权目标，支持 IP / IP:端口 / 主机名 / 文件路径等
        goal: 任务目标描述（默认“获取 Flag”）
        model_ver: 模型思考级别，Low(快速) / Min(默认) / Max(深度推理)
        provider: 模型提供商，deepseek 或 qwen
        event_callback: 可选事件回调，用于向外部（如 UI）转发 Agent 事件
        session_id: 会话标识符，由 API 层分配；CLI 模式下默认为空字符串
        input_queue: 用户消息输入队列，支持对话式交互；CLI 模式下默认为 None
        initial_context: 前次任务上下文摘要（"再打一次"重跑时由 API 层注入）
        agent_tasks: 当前会话活跃的 Agent reply task 注册表
        steering_state: 运行时追加指令共享状态 {"pending": str|None, "processed": bool}
        authorization_source: 审计记录中的授权入口来源（CLI 或 Agent Service）

    Returns:
        最终任务状态 MissionState（含 plan / flag / success 等）
    """
    # ── 1. 解析目标 ──
    # normalize_target 负责把原始输入规范化为 TargetSpec，
    # 自动识别类型（network/archive/single_file/directory）并校验授权范围。
    print(f"[系统] 解析目标: {target}")
    target_spec = normalize_target(target)
    print(f"[系统] 目标类型: {target_spec.kind}")

    # ── 2. 准备工作目录（文件目标则安全解压）──
    # 返回: 规范化目标字符串、工作目录路径、归档清单（非归档为 None）
    target_str, workdir, manifest = _prepare_workspace(target_spec)

    # ── 3. 初始题型分类 ──
    # classify 基于目标类型 + 目标描述 + 归档清单做启发式判断，
    # 输出 primary 题型、候选题型、置信度、证据与所属阶段，
    # 供后续 Brain 规划与 Attack 技能加载使用。
    goal_text = goal.strip() or "获取 Flag"  # 空目标时兜底默认
    category_decision = classify(target_spec, goal_text, manifest)
    # 用户在任务说明中明确声明的服务器 IP / 域名也属于初始授权输入。
    # 典型场景：上传的应急响应任务书列出 SSH 目标与端口。对纯文本附件
    # 一并检查，避免前端只上传任务书、未将其全文复制到“任务目标”时漏掉授权。
    declared_authorization_text = goal_text
    if target_spec.kind == "single_file" and target_spec.original_path is not None:
        try:
            raw_task_file = target_spec.original_path.read_bytes()[:256 * 1024]
            if b"\x00" not in raw_task_file:
                declared_authorization_text += "\n" + raw_task_file.decode("utf-8", errors="ignore")
        except OSError:
            pass
    declared_network_targets = _extract_declared_network_targets(declared_authorization_text)

    # 打印分类结果（主题型 / 候选 / 证据），方便人工审计
    print(
        f"[系统] 初始分类: primary={category_decision.primary} "
        f"(置信度={category_decision.confidence:.0%})"
    )
    if category_decision.secondary:
        print(f"[系统]   候选: {', '.join(category_decision.secondary)}")
    for ev in category_decision.evidence:
        print(f"[系统]   证据: {ev}")

    # ── 4. 运行时配置与任务状态初始化 ──
    # RuntimeConfig 从环境变量读取（API Key、命令超时等）
    runtime = RuntimeConfig.from_env()
    project_dir = Path(__file__).resolve().parent
    # 任务状态持久化：有 session_id 时使用独立会话路径，否则使用默认路径
    if session_id:
        store = MissionStore.for_session(session_id, base_dir=project_dir / ".TaskMemory" / "sessions")
    else:
        store = MissionStore(project_dir / ".TaskMemory" / "current_mission.json")

    # 构建任务状态对象：记录授权信息、目标规格与分类结果
    mission = MissionState(
        session_id=session_id,
        target=target_str,
        goal=goal_text,
        authorized=True,  # 系统默认所有操作均需授权
        target_spec={
            "kind": target_spec.kind,
            "host": target_spec.host,
            "port": target_spec.port,
            "original_input": target_spec.original_input,
            "authorization_scope": target_spec.authorization_scope,
            "declared_network_targets": declared_network_targets,
        },
        category_decision={
            "primary": category_decision.primary,
            "secondary": category_decision.secondary,
            "confidence": category_decision.confidence,
            "scores": category_decision.scores,
            "evidence": category_decision.evidence,
            "stage": category_decision.stage,
        },
        authorization_evidence={
            "source": authorization_source,
            "scope": target_spec.authorization_scope,
            "operator_confirmation": True,  # 操作员已确认
            "declared_network_targets": declared_network_targets,
            "declared_targets_auto_trusted": bool(declared_network_targets),
        },
    )
    # 记录任务创建事件并立即持久化（防止后续异常丢失状态）
    mission.record("system", "mission_created", model=f"{provider}/{model_ver}")
    if event_callback is not None:
        mission.bind_phase_callback(
            lambda previous, current, reason: event_callback(
                "phase_change",
                phase=current.value,
                previous_phase=previous.value,
                reason=reason,
                agent="system",
            ),
        )
    store.save(mission)

    # ── 动态授权范围注册表 ──
    scope_registry = ScopeRegistry()
    # 从持久化恢复（崩溃恢复场景）
    if mission.authorized_scope:
        scope_registry.restore(mission.authorized_scope)
    # 注册初始目标
    if target_spec.host:
        scope_registry.add_base_target(target_spec.host)
    for declared_target in declared_network_targets:
        # 只注册 host，端口信息仍在审计记录中；scoped_shell 以 host/IP
        # 作为网络范围判断依据，命令本身必须显式写出实际访问对象。
        declared_spec = normalize_target(declared_target)
        if declared_spec.host:
            scope_registry.add_base_target(declared_spec.host)
    # 持久化初始快照
    mission.authorized_scope = scope_registry.snapshot()
    store.save(mission)

    # ── 人工审批协调器（首次进入攻击阶段前的人工闸门） ──
    approval_broker = _ApprovalBroker(event_callback, input_queue)

    def _push_target_info(extra: dict | None = None) -> None:
        """向 SSE 订阅者推送靶机信息快照。"""
        if event_callback is not None:
            payload = {
                "target": mission.target,
                "goal": mission.goal,
                "phase": mission.phase.value,
                "exploitation_approved": mission.exploitation_approved,
                "findings_count": len(mission.findings),
                "flag": mission.flag,
            }
            if extra:
                payload.update(extra)
            event_callback("target_info", **payload)

    # ── 输入队列消费者（API 模式下处理用户实时指令） ──
    steering = steering_state if steering_state is not None else {"pending": None, "processed": False, "queue": []}
    steering.setdefault("queue", [])

    def _next_steering_input() -> str | None:
        queue = steering.setdefault("queue", [])
        if queue:
            value = str(queue.pop(0))
            steering["pending"] = queue[0] if queue else None
            steering["processed"] = True
            return value
        pending = steering.get("pending")
        if pending and not steering.get("processed"):
            steering["pending"] = None
            steering["processed"] = True
            return str(pending)
        return None

    async def input_hook(user_input: str) -> None:
        """运行时追加指令入口：写入 steering_state 供主循环消费。"""
        queue = steering.setdefault("queue", [])
        queue.append(user_input)
        steering["pending"] = queue[0]
        steering["processed"] = False

    consumer_task: asyncio.Task | None = None
    if input_queue is not None:
        async def _poll_input_queue() -> None:
            """持续轮询 input_queue，每 2 秒检查一次新消息。"""
            try:
                while True:
                    try:
                        user_input = await asyncio.wait_for(
                            input_queue.get(), timeout=2.0,
                        )
                        # 若正挂起人工审批，该输入是对审批的答复
                        if approval_broker.feed(user_input):
                            continue
                        # 缓存未被审批消费的消息（审批挂起时可回看）
                        approval_broker.stash_input(user_input)
                        await input_hook(user_input)
                    except asyncio.TimeoutError:
                        continue  # 无新消息，继续轮询
            except asyncio.CancelledError:
                pass  # 任务被取消，正常退出

        consumer_task = asyncio.create_task(_poll_input_queue())

    process_tracker, process_tracker_token = bind_process_tracker()
    active_agent_tasks = agent_tasks if agent_tasks is not None else set()
    agent_tasks_token = bind_agent_tasks(active_agent_tasks)
    expert_roster_token = None
    reserve = None
    try:
        # ── 5. 模型与基础 Agent ──
        # 创建共享的 LLM 模型实例（DeepSeek 0.7，Qwen 0.3 避免工具调用退化）
        qwen_temp = 0.3 if provider == "qwen" else 0.7
        model = create_model(provider=provider, Ver=model_ver, temperature=qwen_temp, config=runtime)
        # Brain 通过 AddPlan 工具登记结构化计划条目（origin="brain"），
        # 每次登记都会持久化并推送 plan_updated 事件到前端。
        rag_service = get_rag_service(project_dir)
        await rag_service.start()
        brain = create_brain_agent(
            model,
            tools=[create_add_plan_tool(mission, store, event_callback, default_origin="brain")],
            max_iters=_iter_budget(target_spec.kind, "brain", model_ver),
            rag_middleware=rag_service.middleware(),
        )
        analysis = create_analysis_agent(model)  # 漏洞研判专家（纯推理）

        # ── 6. Recon / Triage 路由 ──
        # 按目标类型选择侦察方式：
        #   network    → 端口/服务/指纹扫描（scoped_shell）
        #   file/归档  → 文件静态研判（triage）
        if target_spec.kind == "network":
            recon = create_network_recon_agent(
                model, target_str, project_dir, runtime.command_timeout,
                scope_registry=scope_registry,
                max_iters=_iter_budget(target_spec.kind, "recon", model_ver),
            )
        else:
            recon = create_artifact_triage_agent(
                model, workdir, project_dir, runtime.command_timeout,
                max_iters=_iter_budget(target_spec.kind, "recon", model_ver),
            )

        # ── 7. Brain 战略规划（包含分类结果）──
        # 把授权目标、任务目标与初始分类打包成提示词，交给 Brain 制定阶段计划。
        # 设计要点：Brain 只能「建议」修正题型（proposed_category + reason），
        # 最终修正需由 Orchestrator 审批，防止单一 Agent 越权篡改任务类型。
        plan_prompt = (
            f"授权目标：{mission.target}\n"
            f"任务目标：{mission.goal}\n\n"
            f"## 题型分析（系统初步分类）\n"
            f"目标类型：{target_spec.kind}\n"
            f"初步题型：{category_decision.primary}\n"
            f"置信度：{category_decision.confidence:.0%}\n"
            f"证据：{'; '.join(category_decision.evidence)}\n"
        )
        if declared_network_targets:
            plan_prompt += (
                "用户任务说明中明确声明并已自动授权的网络目标："
                f"{', '.join(declared_network_targets)}\n"
            )
        if category_decision.secondary:
            plan_prompt += f"候选题型：{', '.join(category_decision.secondary)}\n"
        if initial_context:
            plan_prompt += (
                f"\n## 前次任务上下文（同一目标重跑，供参考以避开失败路径）\n"
                f"{initial_context}\n"
            )
        plan_prompt += (
            "\n你的任务：\n"
            "基于上述事实制定可审计的阶段计划。\n"
            "先用 AddPlan 工具逐条登记结构化计划条目，再输出计划正文。\n"
            "若证据不足，请在计划中加入「重新分类检查点」。\n"
            "若你认为题型需要修正，请输出结构化建议（proposed_category + reason）。\n"
            "不得擅自修改正式题型，修正需由 Orchestrator 审批。"
        )

        # 流式调用 Brain，实时打印前缀 [Brain] 并转发事件。
        # Brain 通过 AddPlan 工具直接登记 plan_items（每次登记即持久化并推送前端）。
        # 规划阶段同样允许操作员插话：不能因为此时尚未进入 Orchestrator
        # 循环，就让新情报被取消事件吞掉。
        while True:
            try:
                plan_result = await run_interruptible_agent_reply(
                    brain,
                    UserMsg(name="user", content=plan_prompt),
                    prefix="[Brain] ",
                    on_event=event_callback,
                )
                break
            except asyncio.CancelledError:
                if steering.get("cancel_requested"):
                    raise
                new_intel = _next_steering_input()
                if not new_intel:
                    raise
                plan_prompt += (
                    "\n\n## 操作员中途补充的新情报\n"
                    f"{new_intel}\n"
                    "请立即基于此情报更新后续计划；已有计划条目无需重复登记。"
                )
                if event_callback is not None:
                    event_callback(
                        "message",
                        content="已接收操作员新情报，正在据此更新战略计划。",
                        agent=brain.name,
                        event_type="agent_acknowledged",
                    )
        # 保存计划文本（无输出时回退到内置四阶段计划）
        mission.plan = plan_result.get_text_content() or "使用内置四阶段计划"
        phase_experts, expert_section = build_expert_assignments(
            category_decision.primary,
            target_spec.kind,
            mission.plan,
            recon.name,
        )
        mission.plan = f"{mission.plan.rstrip()}\n\n{expert_section}"
        for item in mission.plan_items:
            item["expert"] = phase_experts.get(
                str(item.get("phase") or ""),
                "Alex - 行动指挥专家",
            )
        mission.title = prefix_session_title(
            mission.session_id,
            build_mission_title(
                category_decision.primary,
                target_spec.kind,
                mission.goal,
                mission.plan,
            ),
        )
        mission.record("Brain", "plan_created", plan_items_count=len(mission.plan_items))
        mission.record("Brain", "session_title_created", title=mission.title)
        if event_callback is not None:
            event_callback("session_title", title=mission.title, agent="Brain")
            event_callback("message", content=expert_section, agent=brain.name)
            push_plan_update(mission, event_callback)
        # Brain 完成作战计划后再启用专家名册；后续角色首次调用时加入专家团。
        expert_roster_token = bind_expert_roster()
        # 状态机：PLANNING → RECON（非法转型会被状态机拒绝）
        mission.transition(Phase.RECON, "战略计划已制定")
        store.save(mission)  # 每步都持久化，保证崩溃可恢复
        _push_target_info()   # 首次推送靶机信息
        print(f"[Brain] 作战计划\n{mission.plan}\n")

        # ── 8. Attack 延迟创建（Recon 后可能会 reclassify）──
        # 传入当前任务携带的分类结果；若后续 Recon 触发重分类，
        # Orchestrator 会更新 mission.category_decision，Attack 据此动态加载 Skill。
        attack = await create_attack_agent(
            model,
            analysis,
            mission.target,
            project_dir,
            runtime.command_timeout,
            category_decision=mission.category_decision,
            scope_registry=scope_registry,
            max_iters=_iter_budget(target_spec.kind, "attack", model_ver, len(mission.plan_items)),
            rag_middleware=rag_service.middleware(),
            expert_context=mission.plan,
            event_callback=event_callback,
        )

        reserve = await create_reverse_agent(
            model,
            analysis,
            mission.target,
            project_dir,
            runtime.command_timeout,
            category_decision=mission.category_decision,
            scope_registry=scope_registry,
            max_iters=_iter_budget(target_spec.kind, "reserve", model_ver, len(mission.plan_items)),
            event_callback=event_callback,
        )

        scope_auditor = create_scope_auditor_agent(model)

        # ── 9. Orchestrator 主循环 ──
        # 战术调度核心：持有 recon/attack/state/store 的唯一调度者，
        # 负责推进阶段、调度侦察与攻击、处理重分类、最终调用 complete_mission 收尾。
        orchestrator = create_orchestrator_agent(
            model=model,
            recon_agent=recon,
            attack_agent=attack,
            reserve_agent=reserve,
            mission=mission,
            store=store,
            event_callback=event_callback,
            approval_callback=approval_broker.request,
            scope_registry=scope_registry,
            scope_auditor=scope_auditor,
            steering_state=steering,
            nss_context=nss_context,
        )
        # 结构化计划清单文本（Orchestrator 需要知道条目 id 才能用 UpdatePlan 等工具维护）
        plan_items_text = "\n".join(
            f"  {item['id']} [{item['phase']}] {item['content']}"
            for item in mission.plan_items
        ) or "  （Brain 未登记结构化计划，可用 AddPlan 自行建立清单）"
        orch_context = ""
        if initial_context:
            orch_context = (
                f"\n\n## 前次任务上下文（同一目标重跑，供参考以避开失败路径）\n"
                f"{initial_context}\n"
                f"若前次已取得可利用通道（如已确认的 RCE/文件读取），应直接复用并精简命令，"
                f"避免重复完整攻击链。"
            )
            mission.record("system", "context_injected", source="rerun")
        # ── Orchestrator 主循环（steering 由 dispatcher 层 + 此处兜底处理） ──
        orch_content = (
            f"执行以下已授权任务。\n目标：{mission.target}\n目标要求：{mission.goal}\n\n"
            f"Brain 计划：\n{mission.plan}\n\n"
            f"结构化计划清单（执行中用 UpdatePlan/AddPlan/DeletePlan/ListPlan 维护）：\n{plan_items_text}\n\n"
            "从侦察开始，以工具证据推进；结束时必须调用 complete_mission。"
            f"{orch_context}"
        )
        # P5 熔断重试预算：Orchestrator 输出残缺 <tool_call>/空回答时重新注入
        malformed_retry_budget = 2
        while True:
            try:
                final_result = await run_interruptible_agent_reply(
                    orchestrator,
                    UserMsg(name="user", content=orch_content),
                    prefix="[Orchestrator] ",
                    on_event=event_callback,
                )
                # AgentScope 可能以 INTERRUPTED 正常返回（取消被并发工具路径
                # 吞掉时），还原为 CancelledError 走统一清理与 cancelled 终态。
                if (
                    getattr(final_result, "finished_reason", None)
                    == ReplyFinishedReason.INTERRUPTED
                ):
                    raise asyncio.CancelledError()
                # P5：残缺工具调用/空回答熔断——模型输出未闭合 <tool_call> 标签
                # 或整段为空时，AgentScope 会当作文本直接结束，导致任务无进展。
                txt = final_result.get_text_content() or ""
                stripped = txt.strip()
                if (
                    malformed_retry_budget > 0
                    and (
                        not stripped
                        or stripped == "<tool_call>"
                        or stripped == "<tool_call></tool_call>"
                        or stripped.startswith("<tool_call>") and stripped.endswith("</tool_call>") and len(stripped) < 40
                    )
                ):
                    malformed_retry_budget -= 1
                    orch_content = (
                        "你上一条回复只输出了残缺的 <tool_call> 标签，未实际调用工具。"
                        "请直接调用 dispatch_recon / dispatch_attack 等工具推进任务，"
                        "或调用 complete_mission 如实收尾。"
                    )
                    continue
                # Agent 正常结束时，若用户在回复末尾追加了情报，也无需等待
                # 下一次工具调用，立即开启新一轮 Orchestrator 回复。
                pending = _next_steering_input()
                if pending:
                    orch_content = (
                        f"[用户中途指令] {pending}\n\n"
                        "请立即确认已收到该新情报，并基于已有证据调整行动方向。"
                        "无需重复已完成的侦察步骤。"
                    )
                    continue
                break
            except AgentMaxIterationsError as exc:
                # P1：Orchestrator 自身超迭代 → 确定性收敛 FAILED，避免静默失败
                mission.record("system", "orchestrator_max_iters_exceeded", error=str(exc))
                if mission.phase not in {Phase.COMPLETED, Phase.FAILED}:
                    mission.success = False
                    mission.summary = (
                        f"Orchestrator 在 {mission.phase.value} 阶段达到最大迭代次数，"
                        f"未能完成任务。原因：{exc}"
                    )
                    mission.transition(
                        Phase.FAILED, "Orchestrator 达到最大迭代次数，任务未完成",
                    )
                    for item in mission.plan_items:
                        if item.get("status") == "in_progress":
                            item["status"] = "failed"
                        elif item.get("status") == "pending":
                            item["status"] = "skipped"
                    store.save(mission)
                    push_plan_update(mission, event_callback)
                print(f"[系统] Orchestrator 超迭代，任务已收敛为失败：{exc}")
                final_result = None
                break
            except asyncio.CancelledError:
                # 区分三种中断来源：
                #  1) 用户中途指令（steering，pending 未消费）→ 注入后重启 reply
                #  2) steering 已被 dispatch_* 工具快速路径消费但 Orchestrator
                #     自身 reply 仍被打断 → 仅恢复，继续推进
                #  3) 真正的停止请求 → re-raise 让外层 finally 处理清理
                if steering.get("cancel_requested"):
                    raise
                pending = _next_steering_input()
                if pending:
                    # 兜底注入：dispatch 工具未消费（Orchestrator 不在工具内），
                    # 主循环直接把指令作为新一轮输入。
                    orch_content = (
                        f"[用户中途指令] {pending}\n\n"
                        f"请立即确认已收到该新情报，并基于已有侦察证据调整行动方向。"
                        f"无需重复已完成的侦察步骤。"
                    )
                    continue
                if steering.get("processed"):
                    # 指令已被 dispatch 工具消费并注入，仅恢复 Orchestrator 执行。
                    orch_content = (
                        f"继续执行当前任务，基于已有证据推进，"
                        f"结束前必须调用 complete_mission。"
                    )
                    continue
                raise
        if final_result is not None:
            print(f"\n[系统] Orchestrator 最终响应:\n{final_result.get_text_content() or '未返回文本结果'}\n")

        # ── 10. 结果收尾 ──
        # 检查任务是否到达终态（COMPLETED / FAILED）：
        # 若 Orchestrator 中途停止（超时/异常/未调用 complete_mission），
        # 记录事件以便审计，并提示人工介入。
        if mission.phase not in {Phase.COMPLETED, Phase.FAILED}:
            mission.record("system", "orchestrator_stopped_without_terminal_state")
            store.save(mission)
            print(f"[系统] 本轮在 {mission.phase.value} 阶段停止，任务尚未被标记完成。")
        else:
            mission.title = build_final_mission_title(mission)
            mission.record("system", "session_title_finalized", title=mission.title)
            store.save(mission)
            if event_callback is not None:
                event_callback("session_title", title=mission.title, agent="system")
            print(f"[系统] 任务结束: success={mission.success}, flag={mission.flag or '未发现'}")
            if mission.flag and event_callback:
                event_callback("flag_found", flag=mission.flag)
        _push_target_info()
        return mission

    finally:
        # AgentScope 官方方式：取消直接承载 reply_stream 的 task。
        await cancel_agent_tasks(active_agent_tasks)
        await close_reverse_agent(reserve)
        reset_agent_tasks(agent_tasks_token)
        if expert_roster_token is not None:
            reset_expert_roster(expert_roster_token)
        # 停止本任务启动的所有命令及后台子进程，避免取消后继续运行。
        await process_tracker.terminate_all()
        reset_process_tracker(process_tracker_token)
        # 确保输入队列消费者在任务结束（无论正常/异常）后都被清理
        if consumer_task is not None and not consumer_task.done():
            consumer_task.cancel()
            try:
                await consumer_task
            except asyncio.CancelledError:
                pass


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器。

    支持参数:
      --target / -t   授权目标（必填）: IP / IP:端口 / 主机名 / 文件路径
      --goal / -g     任务目标描述，默认"获取 Flag"
      --provider / -p 模型提供商: deepseek(默认) 或 qwen
      --model / -m    思考级别: Low(快速) / Min(默认) / Max(深度推理)
    """
    parser = argparse.ArgumentParser(
        description="灵枢 — AgentScope 2.x 多智能体授权安全测试系统",
    )
    parser.add_argument(
        "--target", "-t", required=True,
        help="单个授权 IP / IP:端口 / 主机名 / 文件路径(.zip/.tar.gz/.pcapng等)",
    )
    parser.add_argument("--goal", "-g", default="获取 Flag", help="任务目标")
    parser.add_argument(
        "--provider", "-p",
        default="deepseek",
        choices=["deepseek", "qwen"],
        help="模型提供商（deepseek 或 qwen）",
    )
    parser.add_argument(
        "--model", "-m",
        default="Min",
        choices=["Low", "Min", "Max"],
        help="思考级别：Low(快速) / Min(默认) / Max(深度推理)",
    )
    return parser


def main() -> None:
    """CLI 入口：解析参数 → 运行异步任务。

    使用 asyncio.run 启动事件循环驱动整个多智能体流程；
    配置类错误（ValueError/RuntimeError）会被包装成 SystemExit 以非零码退出。
    """
    args = build_parser().parse_args()
    try:
        asyncio.run(
            run_mission(args.target, args.goal, args.model, args.provider),
        )
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(f"[配置错误] {exc}") from exc


if __name__ == "__main__":
    main()
