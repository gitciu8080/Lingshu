"""Token 用量统计回归：存储聚合 + 模型实例钩子（非流式/流式路径）。"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentscope.model import ChatResponse, ChatUsage

from core import auth
from core import token_usage as tu
from LLM import model as model_factory


def _usage(inp: int, out: int) -> ChatUsage:
    return ChatUsage(input_tokens=inp, output_tokens=out, time=0.0)


class _FakeModel:
    """模拟 ChatModelBase 的两种返回形态（await 后 ChatResponse/生成器）。"""

    def __init__(self, *, stream_usage=(11, 7), plain_usage=(5, 3)) -> None:
        self.model = "fake-model"
        self.stream_usage = stream_usage
        self.plain_usage = plain_usage

    async def __call__(self, *args, stream: bool = True, **kwargs):
        if stream:
            async def gen():
                yield ChatResponse(content=[], is_last=False)
                yield ChatResponse(
                    content=[], is_last=True,
                    usage=_usage(*self.stream_usage),
                )
            return gen()
        return ChatResponse(
            content=[], is_last=True, usage=_usage(*self.plain_usage),
        )


class TokenUsageTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(auth, "DB_PATH", Path(self.temp.name) / "users.db")
        self.db_patch.start()
        auth.init_db()
        # token_usage 模块的 record/summary 直接调用 auth.get_db（函数引用），
        # auth.DB_PATH patch 后 get_db 已指向临时库，无需额外处理。
        tu._init_table()
        # 重置 hook 的失败告警标记，避免用例间串扰
        model_factory._USAGE_WRITE_FAILED["warned"] = False
        # 造两个用户供平台视图 JOIN
        conn = auth.get_db()
        try:
            for name in ("u1", "u2"):
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, 'x')",
                    (name,),
                )
            conn.commit()
            self.user1, self.user2 = [
                row["id"] for row in conn.execute(
                    "SELECT id FROM users WHERE username IN ('u1','u2') ORDER BY id",
                )
            ]
        finally:
            conn.close()

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.temp.cleanup()


class TokenUsageStorageTest(TokenUsageTestBase):
    def test_table_idempotent_and_zero_rows_skipped(self) -> None:
        tu._init_table()  # 幂等
        tu.record_token_usage(
            user_id=self.user1, session_id="s1", role="main",
            provider="我的DeepSeek", model_name="glm-5.3",
            input_tokens=0, output_tokens=0,
        )
        self.assertEqual(tu.user_usage_summary(self.user1, days=0)["calls"], 0)

    def test_user_summary_aggregates(self) -> None:
        tu.record_token_usage(
            user_id=self.user1, session_id="s1", role="main",
            provider="我的DeepSeek", model_name="glm-5.3", input_tokens=100, output_tokens=50,
        )
        tu.record_token_usage(
            user_id=self.user1, session_id="s1", role="attack",
            provider="我的DeepSeek", model_name="glm-5.3", input_tokens=30, output_tokens=20,
        )
        tu.record_token_usage(
            user_id=self.user1, session_id="s2", role="vision",
            provider="平台视觉", model_name="vision-x", input_tokens=10, output_tokens=5,
        )
        tu.record_token_usage(  # 其他用户不串
            user_id=self.user2, session_id="s3", role="main",
            provider="p2", model_name="m2", input_tokens=999, output_tokens=999,
        )
        summary = tu.user_usage_summary(self.user1, days=0)
        self.assertEqual(summary["calls"], 3)
        self.assertEqual(summary["input_tokens"], 140)
        self.assertEqual(summary["output_tokens"], 75)
        self.assertEqual(summary["by_provider"][0]["key"], "我的DeepSeek")
        sessions = {row["key"]: row["calls"] for row in summary["by_session"]}
        self.assertEqual(sessions, {"s1": 2, "s2": 1})

    def test_platform_summary_groups_by_user_with_cli_bucket(self) -> None:
        tu.record_token_usage(
            user_id=self.user1, session_id="", role="main",
            provider="我的DeepSeek", model_name="glm-5.3", input_tokens=100, output_tokens=50,
        )
        tu.record_token_usage(  # CLI（user_id=None）
            user_id=None, session_id="", role="main",
            provider="CLI配置", model_name="qwen3", input_tokens=10, output_tokens=5,
        )
        platform = tu.platform_usage_summary(days=0)
        self.assertEqual(platform["calls"], 2)
        self.assertEqual(platform["input_tokens"], 110)
        buckets = {row["key"]: row for row in platform["by_user"]}
        self.assertIn("u1", buckets)
        self.assertIn("本地 CLI", buckets)
        self.assertEqual(buckets["本地 CLI"]["user_id"], 0)


class UsageHookTest(TokenUsageTestBase):
    def test_hook_subclass_preserves_instance(self) -> None:
        original = _FakeModel()
        tracked = model_factory.enable_usage_tracking(original, "测试配置", "fake-model")
        self.assertIs(tracked, original)
        self.assertIsInstance(tracked, _FakeModel)  # 子类继承原类
        self.assertEqual(tracked.model, "fake-model")
        # 二次 enable 幂等（不重复包一层类）
        again = model_factory.enable_usage_tracking(tracked, "x", "y")
        self.assertIs(again, tracked)
        self.assertIs(type(again), type(tracked))

    def test_hook_records_stream_and_plain_paths(self) -> None:
        model = model_factory.enable_usage_tracking(_FakeModel(), "测试配置", "fake-model")

        async def run() -> None:
            # 未设置归属上下文：不记录
            result = await model(stream=False)
            self.assertEqual(result.usage.input_tokens, 5)
            async for _ in await model():
                pass
            await asyncio.sleep(0.05)
            self.assertEqual(tu.user_usage_summary(self.user1, days=0)["calls"], 0)
            # 设置上下文后：非流式 + 流式各记一行（异步落库）
            model_factory.set_usage_context(model, self.user1, "sess-1", "main")
            await model(stream=False)
            async for _ in await model():
                pass
            await asyncio.sleep(0.15)
            summary = tu.user_usage_summary(self.user1, days=0)
            self.assertEqual(summary["calls"], 2)
            self.assertEqual(summary["input_tokens"], 16)
            self.assertEqual(summary["output_tokens"], 10)
            self.assertEqual(summary["by_provider"][0]["key"], "测试配置")

        asyncio.run(run())

    def test_hook_survives_write_failure(self) -> None:
        model = model_factory.enable_usage_tracking(_FakeModel(), "测试配置", "fake-model")
        model_factory.set_usage_context(model, self.user1, "sess-1", "main")

        async def run() -> None:
            with patch.object(
                tu, "record_token_usage", side_effect=RuntimeError("db down"),
            ):
                result = await model(stream=False)  # 不应抛错
            self.assertEqual(result.usage.input_tokens, 5)

        asyncio.run(run())

    def test_cli_context_records_null_user(self) -> None:
        model = model_factory.enable_usage_tracking(_FakeModel(), "CLI配置", "fake-model")
        model_factory.set_usage_context(model, None, "", "main")

        async def run() -> None:
            await model(stream=False)
            await asyncio.sleep(0.1)

        asyncio.run(run())
        platform = tu.platform_usage_summary(days=0)
        self.assertEqual(platform["calls"], 1)
        self.assertEqual(platform["by_user"][0]["key"], "本地 CLI")


if __name__ == "__main__":
    unittest.main()
