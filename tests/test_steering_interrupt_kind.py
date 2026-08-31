"""steering 中断三态分类回归测试（cf6adcd1 复盘）。

故障机制：操作员在 bootstrap 侦察阶段发送情报消息 → api steering 路径
写入 queue/pending 并中断 Agent → bootstrap 的 CancelledError 处理器
无条件 re-raise → run_mission 无外层 CancelledError 处理器 → api 层
一律记"任务已被用户取消"。

`_steering_interrupt_kind` 对 CancelledError 来源做无副作用分类，
bootstrap 处理器据其三态决策：stop/unknown → re-raise，intel → 降级继续。
"""

from __future__ import annotations

import unittest

from main import _steering_interrupt_kind


class SteeringInterruptKindTest(unittest.TestCase):
    def test_stop_when_cancel_requested(self) -> None:
        # cancel 端点：cancel_requested=True 且清空队列
        state = {
            "cancel_requested": True,
            "pending": None,
            "processed": False,
            "queue": [],
        }
        self.assertEqual(_steering_interrupt_kind(state), "stop")

    def test_intel_when_queue_has_items(self) -> None:
        # send_message 路径：queue 追加情报，从不写 cancel_requested
        state = {
            "pending": "密码是5位数字组成的",
            "processed": False,
            "queue": ["密码是5位数字组成的"],
        }
        self.assertEqual(_steering_interrupt_kind(state), "intel")

    def test_intel_when_pending_unconsumed(self) -> None:
        state = {"pending": "webshell 在 /tmp", "processed": False, "queue": []}
        self.assertEqual(_steering_interrupt_kind(state), "intel")

    def test_unknown_when_queue_empty_and_pending_consumed(self) -> None:
        state = {"pending": None, "processed": True, "queue": []}
        self.assertEqual(_steering_interrupt_kind(state), "unknown")

    def test_unknown_when_pending_consumed_even_with_value(self) -> None:
        # processed=True 表示 pending 已被消费过，不能再当作未读情报
        state = {"pending": "旧情报", "processed": True, "queue": []}
        self.assertEqual(_steering_interrupt_kind(state), "unknown")

    def test_unknown_for_missing_or_invalid_state(self) -> None:
        self.assertEqual(_steering_interrupt_kind(None), "unknown")
        self.assertEqual(_steering_interrupt_kind({}), "unknown")
        self.assertEqual(_steering_interrupt_kind({"queue": []}), "unknown")

    def test_queue_takes_precedence_over_stale_processed_pending(self) -> None:
        state = {"pending": "旧", "processed": True, "queue": ["新情报"]}
        self.assertEqual(_steering_interrupt_kind(state), "intel")


if __name__ == "__main__":
    unittest.main()
