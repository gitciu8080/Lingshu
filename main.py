#!/usr/bin/env python3
"""灵枢：基于 AgentScope 2.x 的多智能体授权安全测试入口。"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentscope.message import UserMsg

from config import RuntimeConfig, validate_target
from LLM.model import DeepSeek
from TaskState import MissionState, MissionStore, Phase
from agent.Analysis import create_analysis_agent
from agent.Attack import create_attack_agent
from agent.Brain import create_brain_agent
from agent.Orchestrator import create_orchestrator_agent
from agent.Recon import create_recon_agent
from agent.tooling import stream_agent_reply


async def run_mission(
    target: str,
    goal: str,
    model_ver: str = "Flash",
) -> MissionState:
    """执行一次有明确授权范围的安全测试任务。"""
    normalized_target = validate_target(target)
    runtime = RuntimeConfig.from_env()
    project_dir = Path(__file__).resolve().parent
    store = MissionStore(project_dir / ".TaskMemory" / "current_mission.json")
    mission = MissionState(
        target=normalized_target,
        goal=goal.strip() or "获取 Flag",
        authorized=True,
    )
    mission.record("system", "mission_created", model=model_ver)
    store.save(mission)

    print(
        "\n灵枢安全智能体系统 (AgentScope 2.x)\n"
        f"目标: {mission.target}\n任务: {mission.goal}\n模型: {model_ver}\n",
    )

    model = DeepSeek(Ver=model_ver, think=True, temperature=0.7, config=runtime)
    brain = create_brain_agent(model)
    analysis = create_analysis_agent(model)
    recon = create_recon_agent(
        model,
        mission.target,
        project_dir,
        runtime.command_timeout,
    )
    attack = create_attack_agent(
        model,
        analysis,
        mission.target,
        project_dir,
        runtime.command_timeout,
    )

    plan_result = await stream_agent_reply(
        brain,
        UserMsg(
            name="user",
            content=(
                f"授权目标：{mission.target}\n任务目标：{mission.goal}\n"
                "请制定可审计的阶段计划，并明确各阶段退出条件和回退路径。"
            ),
        ),
        prefix="[Brain] ",
    )
    mission.plan = plan_result.get_text_content() or "使用内置四阶段计划"
    mission.record("Brain", "plan_created")
    mission.transition(Phase.RECON, "战略计划已制定")
    store.save(mission)
    print(f"[Brain] 作战计划\n{mission.plan}\n")

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
    parser.add_argument("--target", "-t", required=True, help="单个授权 IP 或主机名")
    parser.add_argument("--goal", "-g", default="获取 Flag", help="任务目标")
    parser.add_argument(
        "--model",
        "-m",
        default="Flash",
        choices=["Flash", "Pro", "chat"],
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        asyncio.run(
            run_mission(args.target, args.goal, args.model),
        )
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(f"[配置错误] {exc}") from exc


if __name__ == "__main__":
    main()
