"""锁定 MissionState.record() 调用契约：details 为 **kwargs，禁止位置传参。

498e11b4 复盘：``mission.record("Orchestrator", "evt", {...})`` 以位置传 dict 会
TypeError（takes 3 positional arguments but 4 were given）。异常从 dispatch_attack
后处理段逃逸后 attempt 卡 running 态，同签名重派被 Action Dedup 的 already_running
永久阻断，任务无法推进直至被取消。本测试用 AST 扫描锁定两层契约：
1. TaskState.record 的 details 必须保持 **kwargs（keyword-only）；
2. 全库 mission.record 调用点位置参数不得超过 2 个（actor, action）。
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _iter_target_files():
    yield ROOT / "main.py"
    yield ROOT / "api.py"
    for folder in ("agent", "core", "Tools"):
        yield from sorted((ROOT / folder).glob("*.py"))


class RecordCallContractTest(unittest.TestCase):
    def test_record_signature_keeps_details_keyword_only(self):
        tree = ast.parse(
            (ROOT / "core" / "TaskState.py").read_text(encoding="utf-8"),
        )
        records = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "record"
        ]
        self.assertTrue(records, "core/TaskState.py 中未找到 record 定义")
        for node in records:
            self.assertIsNotNone(
                node.args.kwarg,
                "record 的 details 必须保持 **kwargs（keyword-only），"
                "否则位置传参 dict 的历史调用会静默变更语义",
            )
            self.assertLessEqual(
                len(node.args.args), 3,
                "record 位置参数应为 (self, actor, action)，详情一律走 **details",
            )

    def test_no_positional_details_in_mission_record_calls(self):
        offenders: list[str] = []
        for path in _iter_target_files():
            if not path.is_file():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "record"
                ):
                    continue
                receiver = ast.unparse(node.func.value)
                if "mission" not in receiver:
                    continue
                # record(actor, action, **details) -> 调用方最多 2 个位置参数
                if len(node.args) > 2:
                    offenders.append(f"{path.name}:{node.lineno}")
        self.assertFalse(
            offenders,
            "以下 mission.record() 调用把详情按位置传入（会触发 "
            "'takes 3 positional arguments but 4 were given'，使派遣 attempt 卡 "
            "running 态并被 Action Dedup 阻断），必须改为 **{...} 关键字展开："
            + ", ".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
