"""冷热长期记忆归档的回归测试。"""
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from Tools import AgenticMemory
except ModuleNotFoundError as exc:
    # 记忆归档是纯文件逻辑；允许在未安装 AgentScope 的轻量 CI 中独立回归。
    if exc.name not in {"jsonschema", "agentscope"}:
        raise
    tooling_stub = types.ModuleType("Tools.tooling")
    tooling_stub.AllowedFunctionTool = object
    sys.modules["Tools.tooling"] = tooling_stub
    from Tools import AgenticMemory


class AgenticMemoryArchiveTests(unittest.TestCase):
    def test_overflow_becomes_sanitized_rag_card(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            memory_file = root / "agentic_memory.json"
            archive_dir = root / ".RAG" / "long-memory"
            missions = [
                {
                    "timestamp": f"2026-01-01T00:00:{index:02d}",
                    "target": f"10.0.0.{index}",
                    "goal": f"检查 http://target{index}.example.test 的 CVE-2024-12345",
                    "plan": "验证 CVE-2024-12345",
                    "attack_chain": [{"service": "Apache", "cve": "CVE-2024-12345"}],
                    "success": True,
                    "summary": "flag{must-not-be-indexed}",
                    "flag": "flag{must-not-be-indexed}",
                }
                for index in range(50)
            ]
            memory_file.write_text(json.dumps({"missions": missions, "techniques": {}}), encoding="utf-8")
            with patch.object(AgenticMemory, "_MEMORY_FILE", str(memory_file)), patch.object(
                AgenticMemory, "_RAG_ARCHIVE_DIR", archive_dir,
            ):
                AgenticMemory.save_mission(
                    target="192.168.1.1",
                    goal="new task",
                    plan="new plan",
                    attack_chain=[],
                    success=False,
                    summary="new summary",
                    flag="flag{new-secret}",
                )

            stored = json.loads(memory_file.read_text(encoding="utf-8"))
            self.assertEqual(len(stored["missions"]), 50)
            cards = list(archive_dir.glob("*.md"))
            self.assertEqual(len(cards), 1)
            card = cards[0].read_text(encoding="utf-8")
            self.assertIn("CVE-2024-12345", card)
            self.assertNotIn("10.0.0.0", card)
            self.assertNotIn("flag{must-not-be-indexed}", card)
            self.assertNotIn("http://target0.example.test", card)


class ExtractLessonsTests(unittest.TestCase):
    """P0-D：任务后反思沉淀 — extract_lessons 与 lessons 归档。"""

    def test_extract_lessons_from_failed_paths(self) -> None:
        failed = [
            {"failure_type": "transient", "failure_reason": "连接 10.0.0.5:8080 超时"},
            {"failure_type": "transient", "failure_reason": "连接 10.0.0.5:8080 超时"},  # 去重
            {"failure_type": "parameter", "failure_reason": "payload 格式错误"},
        ]
        lessons = AgenticMemory.extract_lessons(failed_paths=failed, success=False)
        self.assertEqual(len(lessons), 2)  # 去重后 2 条
        self.assertIn("临时性失败", lessons[0])
        self.assertIn("参数错误", lessons[1])
        # 脱敏：不泄露目标 IP
        self.assertNotIn("10.0.0.5", " ".join(lessons))

    def test_extract_lessons_accepts_records(self) -> None:
        class FakeRecord:
            failure_type = "method"
            failure_reason = "超迭代无有效结果"

        lessons = AgenticMemory.extract_lessons(failed_paths=[FakeRecord()])
        self.assertEqual(lessons, ["方法失效: 超迭代无有效结果"])

    def test_extract_lessons_success_path(self) -> None:
        lessons = AgenticMemory.extract_lessons(
            failed_paths=[],
            attack_chain=[{"service": "Apache", "cve": "CVE-2021-41773"}],
            success=True,
        )
        self.assertTrue(any("成功路径: Apache" in line for line in lessons))
        self.assertTrue(any("CVE-2021-41773" in line for line in lessons))

    def test_save_mission_persists_lessons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            memory_file = root / "agentic_memory.json"
            with patch.object(AgenticMemory, "_MEMORY_FILE", str(memory_file)):
                AgenticMemory.save_mission(
                    target="192.168.1.1",
                    goal="test goal",
                    plan="plan",
                    attack_chain=[],
                    success=False,
                    summary="summary",
                    flag=None,
                    lessons=["临时性失败: 连接超时", "方法失效: 超迭代"],
                )
            stored = json.loads(memory_file.read_text(encoding="utf-8"))
            self.assertEqual(stored["missions"][-1]["lessons"], [
                "临时性失败: 连接超时", "方法失效: 超迭代",
            ])

    def test_archive_card_contains_sanitized_lessons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            memory_file = root / "agentic_memory.json"
            archive_dir = root / ".RAG" / "long-memory"
            missions = [
                {
                    "timestamp": f"2026-02-01T00:00:{index:02d}",
                    "target": f"10.0.0.{index}",
                    "goal": "验证",
                    "plan": "p",
                    "attack_chain": [],
                    "success": False,
                    "summary": "s",
                    "lessons": [f"失败路径: 连接 10.0.0.{index} 超时"],
                }
                for index in range(50)
            ]
            memory_file.write_text(
                json.dumps({"missions": missions, "techniques": {}}),
            )
            with patch.object(AgenticMemory, "_MEMORY_FILE", str(memory_file)), patch.object(
                AgenticMemory, "_RAG_ARCHIVE_DIR", archive_dir,
            ):
                AgenticMemory.save_mission(
                    target="192.168.1.1", goal="new", plan="p",
                    attack_chain=[], success=True, summary="s",
                    lessons=["成功路径: Nginx 可利用 CVE-2024-99999"],
                )
            cards = list(archive_dir.glob("*.md"))
            self.assertEqual(len(cards), 1)
            card = cards[0].read_text(encoding="utf-8")
            self.assertIn("lessons:", card)
            # 归档的是最旧的一条预置任务，其 lessons 经防御性脱敏
            self.assertIn("失败路径: 连接 [已脱敏目标] 超时", card)
            self.assertNotIn("10.0.0.0", card)
            # 新任务的 lessons 保留在热记忆中
            stored = json.loads(memory_file.read_text(encoding="utf-8"))
            self.assertEqual(stored["missions"][-1]["lessons"], [
                "成功路径: Nginx 可利用 CVE-2024-99999",
            ])


if __name__ == "__main__":
    unittest.main()
