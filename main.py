#!/usr/bin/env python3
"""灵枢：基于 AgentScope 2.x 的多智能体授权安全测试入口。

v0.2.0 数据流:
  parse_target() → prepare_workspace() → initial_classify()
  → Brain(含分类结果) → Orchestrator(根据 kind 路由 Recon/Triage)
  → post_recon_classify() → 创建 Attack(动态加载 Skill) → Writeup
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentscope.message import UserMsg

from config import RuntimeConfig, validate_target
from LLM.model import create_model
from TaskState import MissionState, MissionStore, Phase
from agent.Analysis import create_analysis_agent
from agent.archive import safe_extract, SafeExtractError
from agent.Attack import create_attack_agent
from agent.Brain import create_brain_agent
from agent.categorize import CategoryDecision, classify, reclassify
from agent.Orchestrator import create_orchestrator_agent
from agent.Recon import (
    create_artifact_triage_agent,
    create_network_recon_agent,
    create_recon_agent,
)
from agent.target import TargetSpec, normalize_target
from agent.tooling import stream_agent_reply


# ── 工作目录规划 ──
_WORKDIR_ROOT = Path(__file__).resolve().parent / "WorkDir"


def _prepare_workspace(target_spec: TargetSpec) -> tuple[str, Path, dict | None]:
    """为文件/归档目标准备工作目录。

    Returns:
        (target_string, workspace_path, manifest_dict|None)
    """
    if target_spec.kind == "network":
        host = target_spec.host or target_spec.original_input
        if target_spec.port is not None:
            return f"{host}:{target_spec.port}", _WORKDIR_ROOT, None
        return host, _WORKDIR_ROOT, None

    if target_spec.kind == "archive" and target_spec.original_path is not None:
        sha256 = target_spec.sha256 or "unknown"
        workdir = _WORKDIR_ROOT / f"{target_spec.original_path.stem}_{sha256[:12]}"
        print(f"[系统] 安全解压: {target_spec.original_path.name} → {workdir}")
        try:
            manifest = safe_extract(target_spec.original_path, workdir, sha256)
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
            raise SystemExit(f"[安全错误] 解压失败: {exc}") from exc

    if target_spec.kind == "single_file" and target_spec.original_path is not None:
        workdir = target_spec.original_path.parent
        return str(target_spec.original_path), workdir, None

    if target_spec.kind == "directory" and target_spec.workspace is not None:
        return str(target_spec.workspace), target_spec.workspace, None

    raise SystemExit(f"无法处理目标类型: {target_spec.kind}")


async def run_mission(
    target: str,
    goal: str,
    model_ver: str = "Min",
    provider: str = "deepseek",
) -> MissionState:
    """执行一次有明确授权范围的安全测试任务。"""
    # ── 1. 解析目标 ──
    print(f"[系统] 解析目标: {target}")
    target_spec = normalize_target(target)
    print(f"[系统] 目标类型: {target_spec.kind}")

    # ── 2. 准备工作目录（文件目标则安全解压）──
    target_str, workdir, manifest = _prepare_workspace(target_spec)

    # ── 3. 初始题型分类 ──
    goal_text = goal.strip() or "获取 Flag"
    category_decision = classify(target_spec, goal_text, manifest)

    print(
        f"[系统] 初始分类: primary={category_decision.primary} "
        f"(置信度={category_decision.confidence:.0%})"
    )
    if category_decision.secondary:
        print(f"[系统]   候选: {', '.join(category_decision.secondary)}")
    for ev in category_decision.evidence:
        print(f"[系统]   证据: {ev}")

    # ── 4. 运行时配置 ──
    runtime = RuntimeConfig.from_env()
    project_dir = Path(__file__).resolve().parent
    store = MissionStore(project_dir / ".TaskMemory" / "current_mission.json")

    mission = MissionState(
        target=target_str,
        goal=goal_text,
        authorized=True,
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
            "source": "cli",
            "scope": target_spec.authorization_scope,
            "operator_confirmation": True,
        },
    )
    mission.record("system", "mission_created", model=f"{provider}/{model_ver}")
    store.save(mission)

    print(
        "\n灵枢安全智能体系统 (AgentScope 2.x) v0.2.0\n"
        f"目标: {mission.target}\n任务: {mission.goal}\n"
        f"模型: {provider}/{model_ver}\n"
        f"题型: {category_decision.primary}\n",
    )

    # ── 5. 模型与基础 Agent ──
    model = create_model(provider=provider, Ver=model_ver, temperature=0.7, config=runtime)
    brain = create_brain_agent(model)
    analysis = create_analysis_agent(model)

    # ── 6. Recon / Triage 路由 ──
    if target_spec.kind == "network":
        recon = create_network_recon_agent(
            model, target_str, project_dir, runtime.command_timeout,
        )
    else:
        recon = create_artifact_triage_agent(
            model, workdir, project_dir, runtime.command_timeout,
        )

    # ── 7. Brain 战略规划（包含分类结果）──
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
    plan_prompt += (
        "\n你的任务：\n"
        "基于上述事实制定可审计的阶段计划。\n"
        "若证据不足，请在计划中加入「重新分类检查点」。\n"
        "若你认为题型需要修正，请输出结构化建议（proposed_category + reason）。\n"
        "不得擅自修改正式题型，修正需由 Orchestrator 审批。"
    )

    plan_result = await stream_agent_reply(
        brain,
        UserMsg(name="user", content=plan_prompt),
        prefix="[Brain] ",
    )
    mission.plan = plan_result.get_text_content() or "使用内置四阶段计划"
    mission.record("Brain", "plan_created")
    mission.transition(Phase.RECON, "战略计划已制定")
    store.save(mission)
    print(f"[Brain] 作战计划\n{mission.plan}\n")

    # ── 8. Attack 延迟创建（Recon 后可能会 reclassify）──
    attack = create_attack_agent(
        model,
        analysis,
        mission.target,
        project_dir,
        runtime.command_timeout,
        category_decision=mission.category_decision,
    )

    # ── 9. Orchestrator 主循环 ──
    orchestrator = create_orchestrator_agent(model, recon, attack, mission, store)
    final_result = await stream_agent_reply(
        orchestrator,
        UserMsg(
            name="user",
            content=(
                f"执行以下已授权任务。\n目标：{mission.target}\n目标要求：{mission.goal}\n\n"
                f"Brain 计划：\n{mission.plan}\n\n"
                "从侦察开始，以工具证据推进；结束时必须调用 complete_mission。"
            ),
        ),
        prefix="[Orchestrator] ",
    )
    print(f"\n[系统] Orchestrator 最终响应:\n{final_result.get_text_content() or '未返回文本结果'}\n")

    if mission.phase not in {Phase.COMPLETED, Phase.FAILED}:
        mission.record("system", "orchestrator_stopped_without_terminal_state")
        store.save(mission)
        print(f"[系统] 本轮在 {mission.phase.value} 阶段停止，任务尚未被标记完成。")
    else:
        print(f"[系统] 任务结束: success={mission.success}, flag={mission.flag or '未发现'}")
    return mission


def build_parser() -> argparse.ArgumentParser:
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
    args = build_parser().parse_args()
    try:
        asyncio.run(
            run_mission(args.target, args.goal, args.model, args.provider),
        )
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(f"[配置错误] {exc}") from exc


if __name__ == "__main__":
    main()
