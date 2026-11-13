"""上下文压缩自愈回归（61aebfeb / a89f9761 复盘）。

根因：agent/context.py 自定义 SUMMARY_SCHEMA 但未替换 summary_template，
框架默认模板引用 {task_overview} 等字段——任何 agent 触发压缩时
format(**res.content) 必然 KeyError，专家回复死亡并被误判为协议错误。
"""

import unittest
from types import SimpleNamespace

from LLM.model import GatewayChatModel
from Tools.tooling import reset_expert_context
from agent.context import (
    SUMMARY_SCHEMA,
    SUMMARY_TEMPLATE,
    build_agent_context_config,
)
from agent.Orchestrator import COMPRESSION_SUMMARY_FIELDS


def _content_from_schema(schema: dict) -> dict:
    """按 schema required+properties 构造一份合法内容。"""
    content: dict = {}
    for name in schema.get("required") or []:
        prop = (schema.get("properties") or {}).get(name) or {}
        prop_type = prop.get("type")
        if prop_type == "array":
            content[name] = ["x"]
        elif prop_type == "object":
            content[name] = {"k": "v"}
        else:
            content[name] = "x"
    return content


class TestSummaryTemplateAlignment(unittest.TestCase):
    """模板与 Schema 字段必须对齐：压缩渲染不得再抛 KeyError。"""

    def test_template_formats_with_schema_fields(self):
        content = _content_from_schema(SUMMARY_SCHEMA)
        rendered = SUMMARY_TEMPLATE.format(**content)
        self.assertIn("x", rendered)
        self.assertIn("Authorized Scope", rendered)

    def test_template_mentions_every_required_field(self):
        for name in SUMMARY_SCHEMA["required"]:
            self.assertIn("{" + name + "}", SUMMARY_TEMPLATE)

    def test_context_config_carries_custom_template(self):
        for role in ("attack", "orchestrator", "recon", ""):
            config = build_agent_context_config(role)
            self.assertEqual(config.summary_template, SUMMARY_TEMPLATE)
            self.assertEqual(config.summary_schema, SUMMARY_SCHEMA)

    def test_compression_fields_cover_both_schemas(self):
        # 默认 SummarySchema 五字段 + 本项目 SUMMARY_SCHEMA 七字段
        for name in (
            "task_overview", "current_state", "important_discoveries",
            "next_steps", "context_to_preserve",
        ):
            self.assertIn(name, COMPRESSION_SUMMARY_FIELDS)
        for name in SUMMARY_SCHEMA["required"]:
            self.assertIn(name, COMPRESSION_SUMMARY_FIELDS)


class TestStructuredOutputBackfill(unittest.TestCase):
    """本地小模型结构化输出缺字段时按 schema 回填空值。"""

    SCHEMA = {
        "type": "object",
        "properties": {
            "note": {"type": "string"},
            "items": {"type": "array"},
            "meta": {"type": "object"},
        },
        "required": ["note", "items", "meta"],
    }

    def test_backfill_missing_fields_by_type(self):
        content = {"note": "x"}
        filled = GatewayChatModel._backfill_structured_fields(content, self.SCHEMA)
        self.assertEqual(filled, 2)
        self.assertEqual(content["items"], [])
        self.assertEqual(content["meta"], {})

    def test_backfill_noop_when_complete(self):
        content = _content_from_schema(self.SCHEMA)
        self.assertEqual(
            GatewayChatModel._backfill_structured_fields(content, self.SCHEMA), 0)

    def test_backfill_rejects_non_dict_content(self):
        self.assertEqual(
            GatewayChatModel._backfill_structured_fields(None, self.SCHEMA), 0)

    def test_backfill_supports_pydantic_schema(self):
        from pydantic import BaseModel

        class Demo(BaseModel):
            name: str
            tags: list

        content: dict = {}
        GatewayChatModel._backfill_structured_fields(content, Demo)
        self.assertEqual(content, {"name": "", "tags": []})


class TestResetExpertContext(unittest.TestCase):
    """压缩失败后的专家上下文自愈重置。"""

    def test_reset_clears_summary_and_context(self):
        state = SimpleNamespace(summary="旧的压缩摘要", context=[1, 2, 3])
        agent = SimpleNamespace(name="Ryan", state=state)
        self.assertTrue(reset_expert_context(agent))
        self.assertEqual(state.summary, "")
        self.assertEqual(state.context, [])

    def test_reset_tolerates_missing_state(self):
        self.assertFalse(reset_expert_context(SimpleNamespace(name="x")))

    def test_reset_tolerates_readonly_state(self):
        class Frozen:
            name = "frozen"

            @property
            def state(self):
                raise RuntimeError("readonly")

        self.assertFalse(reset_expert_context(Frozen()))


if __name__ == "__main__":
    unittest.main()
