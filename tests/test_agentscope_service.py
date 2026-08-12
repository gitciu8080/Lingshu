"""Contract tests for the Lingshu Agent Service bridge."""

from __future__ import annotations

import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from agentscope.message import AssistantMsg, UserMsg
from agentscope.credential import OpenAICredential
from pydantic import SecretStr

import integrations.agentscope_service.facade as facade_module
from TaskState import MissionState, Phase
from LLM.model import DeepSeekResponsesModel
from main import build_final_mission_title, build_mission_title, prefix_session_title
from agent.experts import REVERSE_EXPERT, attack_expert_name, build_expert_assignments
from agent.Reserve import _IDA_READ_ONLY_TOOLS, RESERVE_SYS_PROMPT
from Tools.tooling import bind_expert_roster, reset_expert_roster, stream_agent_reply
from integrations.agentscope_service.account_events import (
    publish_account_event,
    subscribe_account,
    unsubscribe_account,
)
from integrations.agentscope_service.events import EventTranslator
from integrations.agentscope_service.facade import LingshuMissionAgent
from integrations.agentscope_service.history import RoleHistoryRecorder
from integrations.agentscope_service.runtime import get_runtime


class EventTranslatorTest(unittest.TestCase):
    def test_events_rebuild_a_message(self) -> None:
        translator = EventTranslator("reply-1")
        events = [
            translator.translate("text_start", {"agent": "Brain"}),
            translator.translate("text_delta", {"agent": "Brain", "delta": "计划"}),
            translator.translate("text_end", {"agent": "Brain"}),
            translator.translate("plan_updated", {"items": [], "phase": "planning"}),
        ]
        message = AssistantMsg(name="Lingshu", content=[], id="reply-1")
        for event in events:
            message.append_event(event)

        self.assertEqual(message.get_text_content(), "计划")
        self.assertEqual(events[-1].name, "lingshu.plan.updated")
        self.assertEqual(events[0].metadata["agent"], "Brain")
        self.assertTrue(message.content[0].id.startswith("lingshu.QnJhaW4.text."))

    def test_same_raw_tool_id_is_scoped_by_agent(self) -> None:
        translator = EventTranslator("reply-1")
        brain = translator.translate(
            "tool_call_start",
            {"agent": "Brain", "tool_call_id": "call-1", "tool_name": "plan"},
        )
        recon = translator.translate(
            "tool_call_start",
            {"agent": "Recon", "tool_call_id": "call-1", "tool_name": "scan"},
        )
        self.assertNotEqual(brain.tool_call_id, recon.tool_call_id)


class DeepSeekResponsesModelTest(unittest.IsolatedAsyncioTestCase):
    async def test_reasoning_text_delta_is_parsed_as_thinking(self) -> None:
        model = DeepSeekResponsesModel(
            credential=OpenAICredential(api_key=SecretStr("test")),
            model="deepseek-v4-flash",
        )

        async def response():
            yield SimpleNamespace(
                type="response.reasoning_text.delta",
                delta="推理内容",
            )

        chunks = [
            chunk
            async for chunk in model._parse_stream_response(
                datetime.now(),
                response(),
            )
        ]

        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].content[0].type, "thinking")
        self.assertEqual(chunks[0].content[0].thinking, "推理内容")


class RoleHistoryRecorderTest(unittest.TestCase):
    @patch("integrations.agentscope_service.history.session_store.delete_stream_snapshot")
    @patch("integrations.agentscope_service.history.session_store.upsert_stream_snapshot")
    @patch("integrations.agentscope_service.history.session_store.update_session")
    @patch("integrations.agentscope_service.history.session_store.add_message")
    @patch("integrations.agentscope_service.history.session_store.get_session")
    def test_role_text_is_incremental_and_final_message_is_not_duplicated(
        self,
        get_session,
        add_message,
        _update_session,
        _upsert_snapshot,
        _delete_snapshot,
    ) -> None:
        get_session.return_value = {"id": "session-1"}
        recorder = RoleHistoryRecorder("session-1")
        recorder.record("text_start", {"agent": "Recon"})
        recorder.record("text_delta", {"agent": "Recon", "delta": "端口"})
        recorder.record("text_delta", {"agent": "Recon", "delta": "开放"})
        recorder.record("text_end", {"agent": "Recon"})
        recorder.record("message", {"agent": "Recon", "content": "端口开放"})

        add_message.assert_called_once_with(
            "session-1",
            "agent",
            "端口开放",
            "text_end",
            "Recon",
            "",
        )

    @patch("integrations.agentscope_service.history.session_store.update_session")
    @patch("integrations.agentscope_service.history.session_store.add_message")
    @patch("integrations.agentscope_service.history.session_store.get_session")
    def test_equal_independent_messages_are_preserved(
        self,
        get_session,
        add_message,
        _update_session,
    ) -> None:
        get_session.return_value = {"id": "session-1"}
        recorder = RoleHistoryRecorder("session-1")
        recorder.record("message", {"agent": "Analysis", "content": "重复结论"}, "m1")
        recorder.record("message", {"agent": "Analysis", "content": "重复结论"}, "m2")
        self.assertEqual(add_message.call_count, 2)

    @patch("integrations.agentscope_service.history.publish_account_event")
    @patch("integrations.agentscope_service.history.session_store.update_session")
    @patch("integrations.agentscope_service.history.session_store.add_message")
    @patch("integrations.agentscope_service.history.session_store.get_session")
    def test_phase_is_persisted_and_broadcast_to_account(
        self,
        get_session,
        add_message,
        update_session,
        publish,
    ) -> None:
        get_session.return_value = {"id": "session-1", "user_id": 7}
        recorder = RoleHistoryRecorder("session-1")
        recorder.record(
            "phase_change",
            {
                "agent": "system",
                "phase": "recon",
                "previous_phase": "planning",
                "reason": "计划完成",
            },
            "event-1",
        )

        add_message.assert_called_once_with(
            "session-1", "system", "recon", "phase_change", "system", "event-1",
        )
        update_session.assert_called_once_with("session-1", phase="recon")
        publish.assert_called_once_with(
            7,
            "account_phase_change",
            session_id="session-1",
            phase="recon",
            previous_phase="planning",
            reason="计划完成",
            source_id="event-1",
        )


class PhaseTransitionTest(unittest.TestCase):
    def test_legal_transition_publishes_runtime_callback(self) -> None:
        mission = MissionState(target="127.0.0.1", goal="test", authorized=True)
        received = []
        mission.bind_phase_callback(
            lambda previous, current, reason: received.append((previous, current, reason)),
        )

        mission.transition(Phase.RECON, "计划完成")

        self.assertEqual(received, [(Phase.PLANNING, Phase.RECON, "计划完成")])
        self.assertNotIn("_phase_callback", mission.to_dict())


class MissionTitleTest(unittest.TestCase):
    def test_title_uses_category_and_goal_without_target(self) -> None:
        title = build_mission_title(
            "unknown",
            "network",
            "获取 Flag",
            "侦察 HTTP 路由并分析 Web 漏洞",
        )
        self.assertEqual(title, "Web 安全 - Flag 获取")
        self.assertNotIn("http-ctf", title)

    def test_file_task_title_uses_known_category(self) -> None:
        title = build_mission_title(
            "reverse",
            "single_file",
            "分析程序并恢复密钥",
            "/tmp/challenge.exe",
        )
        self.assertEqual(title, "逆向分析 - 密钥恢复")

    def test_session_id_is_prefixed_once(self) -> None:
        self.assertEqual(
            prefix_session_title("1234567890abcdef", "Web 安全 - Flag 获取"),
            "[12345678] Web 安全 - Flag 获取",
        )

    def test_final_title_uses_attack_evidence_and_outcome(self) -> None:
        mission = MissionState(
            session_id="1234567890abcdef",
            target="example.invalid",
            goal="获取 Flag",
            authorized=True,
            category_decision={"primary": "web"},
            target_spec={"kind": "network"},
            attack_chain=[{"objective": "验证", "report": "确认存在 SQL 注入"}],
            success=True,
            flag="flag{test}",
        )
        self.assertEqual(
            build_final_mission_title(mission),
            "[12345678] Web 安全 - SQL 注入 - Flag 获取成功",
        )


class ExpertRosterTest(unittest.IsolatedAsyncioTestCase):
    def test_reverse_expert_name(self) -> None:
        self.assertEqual(REVERSE_EXPERT, "Ryan - 逆向程序专家")

    async def test_expert_joins_once_after_roster_is_enabled(self) -> None:
        async def reply_stream(**_kwargs):
            yield AssistantMsg(name="Mike - WEB渗透专家", content="完成")

        agent = SimpleNamespace(
            name="Mike - WEB渗透专家",
            reply_stream=reply_stream,
        )
        events = []

        await stream_agent_reply(agent, on_event=lambda event, **data: events.append((event, data)))
        self.assertNotIn("expert_joined", [event for event, _ in events])
        events.clear()

        token = bind_expert_roster()
        try:
            await stream_agent_reply(agent, on_event=lambda event, **data: events.append((event, data)))
            await stream_agent_reply(agent, on_event=lambda event, **data: events.append((event, data)))
        finally:
            reset_expert_roster(token)

        joined = [data for event, data in events if event == "expert_joined"]
        self.assertEqual(len(joined), 1)
        self.assertEqual(joined[0]["expert_name"], "Mike - WEB渗透专家")
        first_join = next(i for i, (event, _) in enumerate(events) if event == "expert_joined")
        first_expert_output = next(
            i
            for i, (event, data) in enumerate(events)
            if event == "message" and data.get("agent") == "Mike - WEB渗透专家"
        )
        self.assertLess(first_join, first_expert_output)

    def test_web_plan_selects_web_attack_expert(self) -> None:
        self.assertEqual(
            attack_expert_name("unknown", "network", "枚举 HTTP 路由并验证 Web 漏洞"),
            "Mike - WEB渗透专家",
        )

    def test_plan_assigns_an_expert_to_each_phase(self) -> None:
        owners, section = build_expert_assignments(
            "web",
            "network",
            "HTTP 路由与漏洞验证",
            "Ethan - 网络侦察专家",
        )
        self.assertEqual(owners["recon"], "Ethan - 网络侦察专家")
        self.assertEqual(owners["exploitation"], "Mike - WEB渗透专家")
        self.assertIn("## 专家分工", section)
        self.assertIn("Mike - WEB渗透专家", section)


class IdaMcpConfigurationTest(unittest.TestCase):
    def test_ida_tools_are_restricted_to_analysis_and_lifecycle(self) -> None:
        self.assertIn("idb_open", _IDA_READ_ONLY_TOOLS)
        self.assertIn("survey_binary", _IDA_READ_ONLY_TOOLS)
        self.assertIn("decompile", _IDA_READ_ONLY_TOOLS)
        self.assertNotIn("patch", _IDA_READ_ONLY_TOOLS)
        self.assertNotIn("patch_asm", _IDA_READ_ONLY_TOOLS)
        self.assertNotIn("set_type", _IDA_READ_ONLY_TOOLS)

    def test_reverse_prompt_uses_database_session_workflow(self) -> None:
        self.assertIn("ida_open_binary", RESERVE_SYS_PROMPT)
        self.assertIn("database", RESERVE_SYS_PROMPT)
        self.assertIn("严禁手动启动 idat", RESERVE_SYS_PROMPT)


class AccountEventFanoutTest(unittest.IsolatedAsyncioTestCase):
    async def test_event_only_reaches_matching_account(self) -> None:
        matching = subscribe_account(7)
        other = subscribe_account(8)
        try:
            event = publish_account_event(
                7,
                "account_phase_change",
                session_id="session-1",
                phase="analysis",
            )
            self.assertEqual(await matching.get(), event)
            self.assertTrue(other.empty())
        finally:
            unsubscribe_account(7, matching)
            unsubscribe_account(8, other)


class MissionFacadeTest(unittest.IsolatedAsyncioTestCase):
    async def test_mission_is_one_outer_reply(self) -> None:
        async def fake_run_mission(**kwargs):
            callback = kwargs["event_callback"]
            callback("text_start", agent="Brain")
            callback("text_delta", agent="Brain", delta="ok")
            callback("text_end", agent="Brain")
            return SimpleNamespace(
                summary="完成",
                phase=SimpleNamespace(value="completed"),
                success=True,
                flag="flag{test}",
            )

        original = facade_module.run_mission
        facade_module.run_mission = fake_run_mission
        try:
            with patch.object(facade_module, "RoleHistoryRecorder") as recorder_cls:
                recorder_cls.return_value.enabled = True
                agent = SimpleNamespace(
                    name="Lingshu",
                    state=SimpleNamespace(session_id="session-test", reply_id=""),
                )
                user_message = UserMsg(
                    name="user",
                    content="获取 Flag",
                    metadata={"lingshu": {"target": "127.0.0.1"}},
                )
                event_types = []
                async for event in LingshuMissionAgent.reply_stream(agent, user_message):
                    event_types.append(event.type)
        finally:
            facade_module.run_mission = original

        self.assertEqual(event_types.count("REPLY_START"), 1)
        self.assertEqual(event_types.count("REPLY_END"), 1)
        self.assertIn("CUSTOM", event_types)
        self.assertIn("TEXT_BLOCK_DELTA", event_types)

    async def test_closing_after_reply_start_unregisters_runtime(self) -> None:
        agent = SimpleNamespace(
            name="Lingshu",
            state=SimpleNamespace(session_id="session-close-test", reply_id=""),
        )
        user_message = UserMsg(
            name="user",
            content="获取 Flag",
            metadata={"lingshu": {"target": "127.0.0.1"}},
        )
        stream = LingshuMissionAgent.reply_stream(agent, user_message)
        first = await anext(stream)
        self.assertEqual(first.type, "REPLY_START")
        self.assertIsNotNone(await get_runtime("session-close-test"))

        await stream.aclose()

        self.assertIsNone(await get_runtime("session-close-test"))


if __name__ == "__main__":
    unittest.main()
