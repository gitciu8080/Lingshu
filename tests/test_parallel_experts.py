"""快速模式并行/后台专家派工测试 + 技能渐进加载锁定。"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from core.TaskState import MissionState, MissionStore, Phase
from main import _fast_pending_report_hint


def _chunk_text(chunk) -> str:
    content = getattr(chunk, "content", chunk)
    if isinstance(content, str):
        return content
    return "".join(getattr(b, "text", str(b)) for b in content)


def _fake_expert(name: str) -> SimpleNamespace:
    inner = SimpleNamespace(name=name)
    return SimpleNamespace(name=name, get=AsyncMock(return_value=inner))


def _mission() -> MissionState:
    mission = MissionState(target="challenge.zip", goal="获取 Flag", authorized=True)
    mission.transition(Phase.RECON, "fast")
    mission.transition(Phase.ANALYSIS, "fast")
    return mission


class ParallelExpertsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "mission.json")
        self.mission = _mission()
        self.experts = {
            "attack": _fake_expert("Mike - 网络渗透专家"),
            "reverse": _fake_expert("Ryan - 逆向程序专家"),
            "triage": _fake_expert("Iris - 文件分析专家"),
            "recon": _fake_expert("Ethan - 网络侦察专家"),
            "analysis": _fake_expert("Nora - 漏洞研判专家"),
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _captain(self):
        from agent.Captain import create_fast_captain_agent

        captain = create_fast_captain_agent(
            model=SimpleNamespace(),
            experts=self.experts,
            mission=self.mission,
            store=self.store,
            event_callback=None,
            target="127.0.0.1",
            workdir=self.temp.name,
            timeout=5,
            max_iters=15,
        )
        self.bg = captain._lingshu_bg
        return captain

    def _tool(self, captain, name: str):
        return asyncio.run(captain.toolkit.get_tool(name))

    def test_background_spawn_returns_handle_immediately(self) -> None:
        captain = self._captain()
        spawn = self._tool(captain, "spawn_expert")

        async def run() -> str:
            return _chunk_text(await spawn.call(
                role="reverse", objective="逆向分析", background=True,
            ))

        with patch(
            "agent.Captain.run_expert_reply_with_continuation",
            new=AsyncMock(return_value="分析完成"),
        ):
            result = asyncio.run(run())
        self.assertIn("reverse#", result)
        self.assertIn("后台", result)
        # 收尾（否则 tearDown 时任务仍挂起）
        check = self._tool(captain, "check_experts")
        asyncio.run(check.call(wait=True, timeout=5))

    def test_same_role_busy_rejected_other_role_parallel_ok(self) -> None:
        captain = self._captain()
        spawn = self._tool(captain, "spawn_expert")

        async def run() -> None:
            released = asyncio.Event()
            started = asyncio.Event()

            async def slow_expert(*args, **kwargs):
                started.set()
                await released.wait()
                return "慢速报告"

            with patch(
                "agent.Captain.run_expert_reply_with_continuation",
                new=slow_expert,
            ):
                first = _chunk_text(await spawn.call(
                    role="reverse", objective="A", background=True,
                ))
                self.assertIn("reverse#", first)
                await asyncio.wait_for(started.wait(), 2)
                # 同 role 再派（同步或后台）→ 忙碌拒绝
                busy_bg = _chunk_text(await spawn.call(
                    role="reverse", objective="B", background=True,
                ))
                self.assertIn("正在执行", busy_bg)
                busy_sync = _chunk_text(await spawn.call(
                    role="reverse", objective="C",
                ))
                self.assertIn("正在执行", busy_sync)
                # 异 role 可并行
                other = _chunk_text(await spawn.call(
                    role="triage", objective="D", background=True,
                ))
                self.assertIn("triage#", other)
                released.set()

        asyncio.run(run())

    def test_background_concurrency_cap(self) -> None:
        captain = self._captain()
        spawn = self._tool(captain, "spawn_expert")

        async def run() -> None:
            released = asyncio.Event()

            async def slow(*args, **kwargs):
                await released.wait()
                return "r"

            with patch(
                "agent.Captain.run_expert_reply_with_continuation", new=slow,
            ):
                for role, obj in (("reverse", "1"), ("recon", "2")):
                    ok = _chunk_text(await spawn.call(
                        role=role, objective=obj, background=True,
                    ))
                    self.assertIn("后台", ok)
                third = _chunk_text(await spawn.call(
                    role="triage", objective="3", background=True,
                ))
                self.assertIn("并发上限", third)
                released.set()

        asyncio.run(run())

    def test_check_experts_collect_and_clear(self) -> None:
        captain = self._captain()
        spawn = self._tool(captain, "spawn_expert")
        check = self._tool(captain, "check_experts")

        async def run() -> None:
            with patch(
                "agent.Captain.run_expert_reply_with_continuation",
                new=AsyncMock(return_value="报告：flag{bg_ok}"),
            ):
                await spawn.call(role="attack", objective="取 flag", background=True)
                result = _chunk_text(await check.call(wait=True, timeout=5))
            self.assertIn("flag{bg_ok}", result)
            self.assertIn("attack", result)
            # 取走即清空；无运行中无待收 → 提示
            again = _chunk_text(await check.call(wait=False))
            self.assertIn("没有后台专家任务", again)

        asyncio.run(run())
        # 后台路径 flag 提取 + 两条审计事件
        actions = [str(e.action) for e in self.mission.events]
        self.assertIn("expert_dispatched", actions)
        self.assertIn("expert_completed", actions)
        self.assertTrue(any(
            "flag{bg_ok}" in str(f.content) for f in self.mission.facts
        ))

    def test_pending_report_hint(self) -> None:
        self.assertIsNone(_fast_pending_report_hint(SimpleNamespace()))
        self.assertIsNone(
            _fast_pending_report_hint(SimpleNamespace(_lingshu_bg={"ready": []})),
        )
        hint = _fast_pending_report_hint(SimpleNamespace(_lingshu_bg={
            "ready": [{"role": "recon", "objective": "x", "report": "r"}],
        }))
        self.assertIsNotNone(hint)
        self.assertIn("check_experts", hint)
        self.assertIn("1 份", hint)


class ProgressiveSkillsTest(unittest.TestCase):
    """锁定框架原生渐进加载：提示只含索引，正文经 Skill 工具按需读取。"""

    def test_skill_index_only_and_viewer_tool(self) -> None:
        import asyncio as aio

        from agentscope.tool import ToolGroup

        from Tools.tooling import SKILL_INSTRUCTION_TEMPLATE, StrictJSONToolkit

        toolkit = StrictJSONToolkit(tool_groups=[
            ToolGroup(
                name="task_skills", description="题库",
                skills_or_loaders=["Skills/ctf-skills/ctf-web"],
            ),
        ])
        instruction = aio.run(toolkit.get_skill_instructions(["task_skills"]))
        # 索引包含技能名与截断后的描述，不含 references 正文
        self.assertIn("ctf-web", instruction)
        self.assertLess(len(instruction), 2000)
        reference = Path("Skills/ctf-skills/ctf-web/auth-jwt.md")
        if reference.is_file():
            self.assertNotIn(reference.read_text(encoding="utf-8")[:200], instruction)
        # Skill 查看工具在可用集中
        names = {
            schema["function"]["name"]
            for schema in aio.run(toolkit.get_tool_schemas(["task_skills"]))
        }
        self.assertIn("Skill", names)

    def test_description_truncated_in_template(self) -> None:
        from jinja2 import Template

        from Tools.tooling import SKILL_INSTRUCTION_TEMPLATE

        class _Skill:
            name = "long-skill"
            dir = "/skills/long"
            description = "x" * 300

        rendered = Template(SKILL_INSTRUCTION_TEMPLATE).render(
            skills=[_Skill()], skill_viewer="Skill",
        )
        self.assertIn("x" * 240, rendered)
        self.assertNotIn("x" * 241, rendered.replace("…", ""))
        self.assertEqual(rendered.count("…"), 1)


if __name__ == "__main__":
    unittest.main()
