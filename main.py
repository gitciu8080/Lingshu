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
import os  # 环境变量与路径操作
import sys  # 修改模块搜索路径，确保能 import 本目录下的包
from collections.abc import Callable  # 回调类型注解
from pathlib import Path  # 跨平台路径对象
from typing import Any  # 通用任意类型注解

# 将本文件所在目录加入模块搜索路径，
# 这样无论从哪里启动 main.py 都能正确导入 config / LLM / agent 等兄弟模块。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentscope.message import UserMsg  # AgentScope 用户消息封装

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
from agent.Reserve import create_reverse_agent  # 逆向分析 Agent（IDA MCP）
from agent.ScopeAuditor import create_scope_auditor_agent  # IP 授权审核 Agent
from Tools.Plan import create_add_plan_tool  # Brain 登记计划条目的工具
from Tools.ScopeRegistry import ScopeRegistry  # 动态授权范围注册表
from Tools.target import TargetSpec, normalize_target  # 目标规范化
from Tools.tooling import stream_agent_reply  # 流式获取 Agent 回复并转发事件


# ── 工作目录规划 ──
# 所有网络任务的工作目录统一放在本文件同级目录下的 WorkDir/ 中，
# 文件/归档任务则在其下按「文件名_sha256前12位」建立独立子目录。
_WORKDIR_ROOT = Path(__file__).resolve().parent / "WorkDir"


# 肯定的审批答复（其余一律视为拒绝，安全默认）
_APPROVAL_YES = {"y", "yes", "ok", "approve", "approved", "是", "批准", "同意"}


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
        self._pending: asyncio.Future[bool] | None = None
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

    async def request(self, reason: str, scan_summary: dict | None = None) -> bool:
        """发起一次攻击阶段审批请求，返回是否批准。

        Args:
            reason: LLM 写的攻击理由
            scan_summary: 可选的结构化扫描摘要（目标/侦察发现/作战计划等）
        """
        if self._input_queue is None:
            return await self._ask_cli(reason, scan_summary)
        return await self._ask_api(reason, scan_summary)

    async def _ask_cli(self, reason: str, scan_summary: dict | None = None) -> bool:
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
        print(f"[攻击理由] {reason}")
        print(f"{'='*60}")
        loop = asyncio.get_running_loop()
        try:
            answer = await loop.run_in_executor(
                None, input, "[人工审批] 是否批准？(y/n): ",
            )
        except (EOFError, KeyboardInterrupt):
            print("\n[人工审批] 输入中断，视为拒绝。")
            return False
        approved = answer.strip().lower() in _APPROVAL_YES
        print(f"[人工审批] 操作员{'批准' if approved else '拒绝'}了攻击阶段授权。")
        return approved

    async def _ask_api(self, reason: str, scan_summary: dict | None = None) -> bool:
        """API 通道：推送 approval_required 事件，挂起等待用户答复。"""
        if self.waiting:
            return False  # 防御：已有待处理审批，本次视为拒绝
        # 推送审批事件到 SSE
        payload: dict[str, Any] = {"reason": reason, "agent": "Orchestrator"}
        if scan_summary:
            payload["scan_summary"] = scan_summary
        if self._event_callback is not None:
            self._event_callback("approval_required", **payload)
        # 回看近期缓存：若用户在审批请求到达前已发送了答复，直接消费
        for recent in self._recent_inputs:
            if self.feed(recent):
                self._recent_inputs.clear()
                return self._pending is None  # feed 已 resolve pending
        self._recent_inputs.clear()
        loop = asyncio.get_running_loop()
        self._pending = loop.create_future()
        try:
            return await self._pending
        finally:
            self._pending = None

    def feed(self, user_input: str) -> bool:
        """处理 input_queue 收到的用户消息；返回 True 表示已被审批消费。
        支持三态决策：批准 / 补充侦察（视为拒绝但语义保留）/ 拒绝。
        """
        if not self.waiting:
            return False
        lower = user_input.strip().lower()
        approved = lower in _APPROVAL_YES
        if self._event_callback is not None:
            self._event_callback(
                "approval_resolved",
                approved=approved,
                decision=user_input.strip(),
                agent="Orchestrator",
            )
        self._pending.set_result(approved)
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


async def run_mission(
    target: str,
    goal: str,
    model_ver: str = "Min",
    provider: str = "deepseek",
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
    session_id: str = "",
    input_queue: asyncio.Queue | None = None,
    initial_context: str | None = None,
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
            "source": "cli",  # 授权来源：命令行用户确认
            "scope": target_spec.authorization_scope,
            "operator_confirmation": True,  # 操作员已确认
        },
    )
    # 记录任务创建事件并立即持久化（防止后续异常丢失状态）
    mission.record("system", "mission_created", model=f"{provider}/{model_ver}")
    store.save(mission)

    # ── 动态授权范围注册表 ──
    scope_registry = ScopeRegistry()
    # 从持久化恢复（崩溃恢复场景）
    if mission.authorized_scope:
        scope_registry.restore(mission.authorized_scope)
    # 注册初始目标
    if target_spec.host:
        scope_registry.add_base_target(target_spec.host)
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
    async def input_hook(user_input: str) -> None:
        """处理来自 API 层的用户实时输入。

        当前为占位实现：记录日志；后续迭代将转发给 Orchestrator
        以支持对话式交互（如中途调整目标、追加指令等）。
        """
        print(f"[系统] 收到用户输入: {user_input}")

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

    try:
        # ── 5. 模型与基础 Agent ──
        # 创建共享的 LLM 模型实例（temperature=0.7 兼顾稳定与发散）
        model = create_model(provider=provider, Ver=model_ver, temperature=0.7, config=runtime)
        # Brain 通过 AddPlan 工具登记结构化计划条目（origin="brain"），
        # 每次登记都会持久化并推送 plan_updated 事件到前端。
        brain = create_brain_agent(
            model,
            tools=[create_add_plan_tool(mission, store, event_callback, default_origin="brain")],
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
            )
        else:
            recon = create_artifact_triage_agent(
                model, workdir, project_dir, runtime.command_timeout,
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
        plan_result = await stream_agent_reply(
            brain,
            UserMsg(name="user", content=plan_prompt),
            prefix="[Brain] ",
            on_event=event_callback,
        )
        # 保存计划文本（无输出时回退到内置四阶段计划）
        mission.plan = plan_result.get_text_content() or "使用内置四阶段计划"
        mission.record("Brain", "plan_created", plan_items_count=len(mission.plan_items))
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
        )

        reserve = await create_reverse_agent(
            model,
            analysis,
            mission.target,
            project_dir,
            runtime.command_timeout,
            category_decision=mission.category_decision,
            scope_registry=scope_registry,
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
        final_result = await stream_agent_reply(
            orchestrator,
            UserMsg(
                name="user",
                content=(
                    f"执行以下已授权任务。\n目标：{mission.target}\n目标要求：{mission.goal}\n\n"
                    f"Brain 计划：\n{mission.plan}\n\n"
                    f"结构化计划清单（执行中用 UpdatePlan/AddPlan/DeletePlan/ListPlan 维护）：\n{plan_items_text}\n\n"
                    "从侦察开始，以工具证据推进；结束时必须调用 complete_mission。"
                    f"{orch_context}"
                ),
            ),
            prefix="[Orchestrator] ",
            on_event=event_callback,
        )
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
            print(f"[系统] 任务结束: success={mission.success}, flag={mission.flag or '未发现'}")
            if mission.flag and event_callback:
                event_callback("flag_found", flag=mission.flag)
        _push_target_info()
        return mission

    finally:
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
