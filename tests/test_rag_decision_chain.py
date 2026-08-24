"""RAG 决策链的纯代码级契约测试，不访问 Embedding 或外部目标。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.TaskState import FactRecord, MissionState, MissionStore, Phase
from Tools.KnowledgeBase import RAGService, build_retrieval_request


class RetrievalRequestTest(unittest.TestCase):
    def test_clear_simple_task_does_not_retrieve(self) -> None:
        mission = MissionState("example", "确认服务信息", True)
        mission.complexity = "simple"
        mission.phase = Phase.ANALYSIS
        mission.category_decision = {
            "primary": "web", "secondary": [], "confidence": 0.95,
        }
        mission.facts = [
            FactRecord("f1", "已确认 HTTP 服务", "Recon"),
            FactRecord("f2", "已确认服务版本", "Recon"),
        ]

        request = build_retrieval_request(
            mission, consumer="Brain", focus="制定下一步计划",
        )

        self.assertFalse(request["needed"])
        self.assertNotIn("完整历史", request["query"])

    def test_complex_sparse_task_retrieves_and_query_is_bounded(self) -> None:
        mission = MissionState("example", "分析未知归档中的技术路线", True)
        mission.complexity = "complex"
        mission.category_decision = {
            "primary": "unknown", "secondary": ["reverse"], "confidence": 0.4,
        }

        request = build_retrieval_request(
            mission, consumer="Brain", focus="根据首轮 Recon 补齐知识缺口",
        )

        self.assertTrue(request["needed"])
        self.assertIn("知识缺口", request["query"])
        self.assertLess(len(request["query"]), 3000)

    def test_same_state_and_focus_share_cache_key_between_consumers(self) -> None:
        mission = MissionState("example", "分析 CVE-2021-41773", True)
        mission.category_decision = {
            "primary": "web", "secondary": [], "confidence": 0.9,
        }
        brain = build_retrieval_request(
            mission, consumer="Brain", focus="CVE-2021-41773 验证条件",
        )
        attack = build_retrieval_request(
            mission, consumer="Attack", focus="CVE-2021-41773 验证条件",
        )
        self.assertEqual(brain["cache_key"], attack["cache_key"])

    def test_knowledge_context_round_trips_without_becoming_fact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MissionStore(Path(temporary) / "mission.json")
            mission = MissionState("example", "分析任务", True)
            mission.knowledge_context = {
                "status": "ready", "query": "当前知识缺口", "context": "[K1] 参考",
                "sources": ["one.md"], "cache_key": "abc",
            }
            store.save(mission)
            loaded = store.load()

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.knowledge_context["context"], "[K1] 参考")
        self.assertEqual(loaded.facts, [])
        self.assertEqual(loaded.evidence_records, [])


class RetrievalFilteringTest(unittest.IsolatedAsyncioTestCase):
    async def test_filter_dedup_and_context_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service = RAGService(Path(temporary))

            async def fake_search(query: str, top_k: int = 5):
                del query, top_k
                duplicate = "A" * 1000
                return [
                    {"score": 0.91, "source": "one.md", "snippet": duplicate},
                    {"score": 0.90, "source": "copy.md", "snippet": duplicate},
                    {"score": 0.10, "source": "noise.md", "snippet": "低相关噪声"},
                    {"score": 0.80, "source": "two.md", "snippet": "有效参考二"},
                ]

            service.search = fake_search  # type: ignore[method-assign]
            result = await service.retrieve_context(
                "query", context_k=3, max_item_chars=100, max_context_chars=220,
            )

        self.assertEqual(result["result_count"], 4)
        self.assertEqual(result["filtered_count"], 2)
        self.assertLessEqual(len(result["context"]), 220)
        self.assertEqual(result["sources"], ["one.md", "two.md"])


if __name__ == "__main__":
    unittest.main()
