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


if __name__ == "__main__":
    unittest.main()
