#!/usr/bin/env python3
"""
AutoTest 自动打靶 — 主脚本

用法:
    python -m Lingshu.AutoTest.auto_pwn --list
    python -m Lingshu.AutoTest.auto_pwn --count 10
    python -m Lingshu.AutoTest.auto_pwn --count 20 --category web
    python -m Lingshu.AutoTest.auto_pwn --count 5 --difficulty easy --timeout 1200
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# 支持两种运行方式: python -m Lingshu.AutoTest.auto_pwn 或直接 python auto_pwn.py
if __name__ == "__main__" and __package__ is None:
    _proj_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(_proj_root))
    from AutoTest.config import (
        DEFAULT_COUNT, DEFAULT_TIMEOUT, REPORT_DIR, GOAL,
    )
    from AutoTest.ctf2_client import CTF2Client, CTF2Error
    from AutoTest.picker import ChallengePicker, ChallengeInfo
    from AutoTest.runner import run_with_fallback, LingshuResult
else:
    from .config import (
        DEFAULT_COUNT, DEFAULT_TIMEOUT, REPORT_DIR, GOAL,
    )
    from .ctf2_client import CTF2Client, CTF2Error
    from .picker import ChallengePicker, ChallengeInfo
    from .runner import run_with_fallback, LingshuResult

# ---------- 日志 ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("auto_pwn")


# ====================================================================
# 主函数
# ====================================================================
async def main(args: argparse.Namespace):
    if args.platform == "bugku":
        await _run_bugku(args)
    else:
        await _run_ctf2(args)


async def _run_ctf2(args: argparse.Namespace):
    """CTF2 平台流程"""
    client = CTF2Client()
    picker = ChallengePicker(client)

    # ---------- 1. 收集并选题 ----------
    logger.info("=" * 50)
    logger.info("正在收集题目...")

    if args.file:
        # 从文件加载题目列表
        picker.load_from_file(args.file)
    else:
        picker.collect()

    selected = picker.random_pick(
        count=args.count,
        exclude_solved=not args.include_solved,
        category=args.category[0] if args.category else None,
        difficulty=args.difficulty,
    )

    if not selected:
        logger.error("没有可选的题目！")
        return

    logger.info("已选取 %d 道题目，开始逐题打靶", len(selected))
    for i, ch in enumerate(selected, 1):
        logger.info("  %2d. [%s] %s (%s/%s)", i, ch.category, ch.title, ch.difficulty, "已解" if ch.solved else "未解")

    # ---------- 2. 逐题打靶 ----------
    results: list[TaskResult] = []
    total = len(selected)

    for idx, challenge in enumerate(selected, 1):
        logger.info("=" * 50)
        logger.info("[%d/%d] 开始: [%s] %s", idx, total, challenge.category, challenge.title)

        tr = await process_one(
            client=client,
            challenge=challenge,
            timeout=args.timeout,
            goal=args.goal,
            practice_id=args.practice_id,
            attachments_dir=args.attachments_dir,
        )
        results.append(tr)
        logger.info("结果: %s", tr.brief())

        # 每题间短暂休息，避免触发限流
        if idx < total:
            await asyncio.sleep(3)

    # ---------- 3. 汇总报告 ----------
    _print_summary(results)
    _save_report(results, args)


# ====================================================================
# 单题处理
# ====================================================================
async def process_one(
    client: CTF2Client,
    challenge: ChallengeInfo,
    timeout: int,
    goal: str,
    practice_id: str | None = None,
    attachments_dir: str | None = None,
) -> TaskResult:
    """处理单道题目：启动靶机（或使用附件）→ 打靶 → 提交 flag"""
    start_time = time.monotonic()
    cid = challenge.challenge_id
    pid = practice_id or challenge.source_id  # 优先用显式指定的 practice_id

    tr = TaskResult(
        challenge=challenge,
        start_time=datetime.now(timezone.utc),
    )
    target_addr: str | None = None

    # ---------- 优先使用本地附件 ----------
    if challenge.file_names and attachments_dir:
        for fname in challenge.file_names:
            local_path = Path(attachments_dir) / fname
            if local_path.exists():
                target_addr = str(local_path)
                logger.info("  使用本地附件: %s", local_path)
                break
        if not target_addr:
            logger.warning("  附件未找到，期望目录: %s", attachments_dir)

    # ---------- 如果无附件，尝试启动靶机 ----------
    if not target_addr and challenge.has_container:
        try:
            env = client.start_environment(pid, cid)
            target_addr = _extract_target(env)
            if target_addr:
                logger.info("  靶机地址: %s", target_addr)
                tr.environment = env
            else:
                logger.warning("  无法从环境信息提取目标地址")
        except CTF2Error as e:
            logger.warning("  启动环境失败 (source=%s): %s，尝试在练习场列表中查找...", pid, e)
            found_pid = _find_practice_for_challenge(client, cid)
            if found_pid and found_pid != pid:
                try:
                    env = client.start_environment(found_pid, cid)
                    target_addr = _extract_target(env)
                    if target_addr:
                        logger.info("  在 practice=%s 中找到靶机: %s", found_pid, target_addr)
                        pid = found_pid
                        tr.environment = env
                    else:
                        target_addr = None
                except CTF2Error as e2:
                    logger.warning("  回退也失败: %s", e2)
                    tr.environment_error = f"{e} | fallback: {e2}"
            else:
                tr.environment_error = str(e)

    # ---------- 无靶机且无附件：使用虚拟目标 ----------
    if not target_addr:
        target_addr = f"challenge://{pid}/{cid}"
        if challenge.file_names:
            logger.info("  附件需手动下载到 %s，当前使用虚拟目标", attachments_dir or "attachments/")
        else:
            logger.info("  无靶机无附件，使用虚拟目标: %s", target_addr)

    # ---------- Lingshu 打靶 ----------
    try:
        ling_result = await run_with_fallback(
            target=target_addr,
            goal=goal,
            timeout=timeout,
        )
        tr.lingshu = ling_result

        if ling_result.flag:
            logger.info("  获取到 flag: %s", ling_result.flag)

            # ---------- 提交 flag ----------
            try:
                submit_result = client.submit_flag(pid, cid, ling_result.flag)
                tr.submitted = True
                tr.submit_result = submit_result
                logger.info("  flag 已提交")
            except CTF2Error as e:
                logger.error("  提交 flag 失败: %s", e)
                tr.submit_error = str(e)
        else:
            logger.warning("  未获取到 flag")
    except Exception as e:
        logger.exception("  Lingshu 调用异常: %s", e)
        tr.lingshu_error = str(e)

    tr.elapsed = time.monotonic() - start_time
    return tr


def _find_practice_for_challenge(client: CTF2Client, challenge_id: str) -> str | None:
    """在所有练习场中查找包含该 challenge 的 practice_id，逐个尝试"""
    practices = client.get_practices()
    for p in practices:
        pid = p.get("id", "")
        if not pid:
            continue
        try:
            client.get_challenge(pid, challenge_id)
            return pid  # 找到了
        except CTF2Error:
            continue
    return None


def _extract_target(env: dict) -> str | None:
    """
    从 environment 返回中提取目标地址

    支持多种字段名：host/ip、port、url、address
    """
    if not env:
        return None

    # 直接字段
    host = env.get("host") or env.get("ip") or env.get("address") or env.get("url")
    port = env.get("port")

    if host:
        if port and ":" not in str(host):
            return f"{host}:{port}"
        return str(host)

    # 嵌套在 services 或 connections 中
    for key in ("services", "connections", "endpoints"):
        items = env.get(key, [])
        if isinstance(items, list) and items:
            first = items[0]
            if isinstance(first, dict):
                h = first.get("host") or first.get("ip") or first.get("address") or first.get("url")
                p = first.get("port")
                if h:
                    if p and ":" not in str(h):
                        return f"{h}:{p}"
                    return str(h)

    # 递归搜索任意包含 host 的子对象
    return _deep_search_host(env)


def _deep_search_host(obj, depth=0) -> str | None:
    """递归搜索嵌套对象中的 host/port 字段"""
    if depth > 3 or not isinstance(obj, dict):
        return None
    if "host" in obj or "ip" in obj:
        h = obj.get("host") or obj.get("ip")
        p = obj.get("port")
        if h:
            if p and ":" not in str(h):
                return f"{h}:{p}"
            return str(h)
    for v in obj.values():
        if isinstance(v, dict):
            r = _deep_search_host(v, depth + 1)
            if r:
                return r
    return None


# ====================================================================
# Bugku 平台流程
# ====================================================================
async def _run_bugku(args: argparse.Namespace):
    """Bugku 自动打靶流程"""
    if __name__ == "__main__" and __package__ is None:
        from AutoTest.bugku_client import BugkuClient
        from AutoTest.bugku_picker import BugkuPicker, ChallengeInfo as BugkuChallengeInfo
        from AutoTest.runner import run_with_fallback
        from AutoTest.config import ATTACHMENTS_DIR, BUGKU_PHPSESSID
    else:
        from .bugku_client import BugkuClient
        from .bugku_picker import BugkuPicker, ChallengeInfo as BugkuChallengeInfo
        from .runner import run_with_fallback
        from .config import ATTACHMENTS_DIR, BUGKU_PHPSESSID

    client = BugkuClient(args.bugku_session or BUGKU_PHPSESSID)
    picker = BugkuPicker(client)

    # 1. 选题
    logger.info("=" * 50)
    logger.info("正在收集 Bugku 题目...")
    categories = args.category if args.category else None
    picker.collect(categories=categories, max_pages=args.max_pages, free_only=True)

    selected = picker.random_pick(
        count=args.count,
        exclude_solved=not args.include_solved,
        category=None,  # collect 阶段已按 category 过滤
    )

    if not selected:
        logger.error("没有可选的题目！")
        return

    # 补充附件/靶机信息
    logger.info("正在获取题目详情...")
    picker.enrich_details(selected)

    logger.info("已选取 %d 道题目", len(selected))
    for i, ch in enumerate(selected, 1):
        extra = ""
        if ch.has_attachment:
            extra += " 📎附件"
        if ch.has_scene:
            extra += " 🖥️靶机"
        logger.info("  %2d. [%s] %s%s gold=%d %s",
                     i, ch.category, ch.title, extra, ch.gold,
                     "已解" if ch.solved else "")

    # 2. 逐题打靶
    results = []
    total = len(selected)

    for idx, ch in enumerate(selected, 1):
        logger.info("=" * 50)
        logger.info("[%d/%d] [%s] %s", idx, total, ch.category, ch.title)

        tr = await _process_bugku_one(client, ch, args)
        results.append(tr)
        logger.info("结果: %s", _bugku_brief(tr))

        if idx < total:
            await asyncio.sleep(2)

    # 3. 汇总
    _print_bugku_summary(results)
    _save_bugku_report(results, args)


async def _process_bugku_one(
    client: "BugkuClient",
    challenge: "BugkuChallengeInfo",
    args: argparse.Namespace,
) -> dict:
    """Bugku 单题处理"""
    if __name__ == "__main__" and __package__ is None:
        from AutoTest.runner import run_with_fallback
        from AutoTest.config import ATTACHMENTS_DIR
    else:
        from .runner import run_with_fallback
        from .config import ATTACHMENTS_DIR

    start_time = time.monotonic()
    result = {
        "challenge": challenge,
        "lingshu": None,
        "target": None,
        "flag_submitted": False,
        "submit_response": None,
        "elapsed": 0.0,
        "error": None,
    }

    # 确定 target
    target = None

    # 如果有附件，下载
    if challenge.has_attachment:
        try:
            saved = client.download_attachment(
                challenge.challenge_id, str(ATTACHMENTS_DIR)
            )
            if saved:
                target = str(saved)
                logger.info("  附件: %s", saved.name)
        except Exception as e:
            logger.warning("  附件下载失败: %s", e)

    # 如果需要靶机但无附件
    if not target and challenge.has_scene:
        logger.warning("  需要靶机但广告系统暂停中，跳过")
        result["error"] = "靶机广告系统暂停"
        result["elapsed"] = time.monotonic() - start_time
        return result

    # 如果既无附件也无靶机，用虚拟目标
    if not target:
        target = f"challenge://bugku/{challenge.challenge_id}"
        logger.info("  无附件无靶机，使用虚拟目标")

    result["target"] = target

    # Lingshu 打靶
    try:
        ling = await run_with_fallback(
            target=target,
            goal=args.goal,
            timeout=args.timeout,
        )
        result["lingshu"] = ling

        if ling.flag:
            logger.info("  获取到 flag: %s", ling.flag)
            # 提交 flag
            try:
                submit_resp = client.submit_flag(challenge.challenge_id, ling.flag)
                result["submit_response"] = submit_resp
                msg = submit_resp.get("msg", "")
                if "不正确" not in msg and "Error" not in msg:
                    result["flag_submitted"] = True
                    logger.info("  flag 提交成功: %s", msg)
                else:
                    logger.warning("  flag 提交结果: %s", msg)
            except Exception as e:
                logger.error("  提交失败: %s", e)
                result["error"] = str(e)
        else:
            logger.warning("  未获取到 flag")
    except Exception as e:
        logger.exception("  Lingshu 异常: %s", e)
        result["error"] = str(e)

    result["elapsed"] = time.monotonic() - start_time
    return result


def _bugku_brief(result: dict) -> str:
    """Bugku 结果简要描述"""
    parts = []
    ling = result.get("lingshu")
    if ling:
        if ling.flag:
            parts.append(f"flag={ling.flag}")
        parts.append(f"模型={ling.model_ver}")
        if ling.fallback_used:
            parts.append("(降级)")
        parts.append(f"耗时={result['elapsed']:.0f}s")
    else:
        parts.append("Lingshu未运行")
    if result.get("flag_submitted"):
        parts.append("已提交")
    if result.get("error"):
        parts.append(f"错误: {result['error'][:60]}")
    return " | ".join(parts)


def _print_bugku_summary(results: list[dict]):
    """Bugku 汇总输出"""
    total = len(results)
    flag_count = sum(1 for r in results if r.get("lingshu") and r["lingshu"].flag)
    submitted = sum(1 for r in results if r.get("flag_submitted"))
    fallback = sum(1 for r in results if r.get("lingshu") and r["lingshu"].fallback_used)
    skipped = sum(1 for r in results if r.get("error") and "靶机" in str(r.get("error", "")))

    logger.info("=" * 50)
    logger.info("Bugku 汇总报告")
    logger.info("=" * 50)
    logger.info("  总题数:        %d", total)
    logger.info("  获取 flag:     %d", flag_count)
    logger.info("  已提交:        %d", submitted)
    logger.info("  Flash→Pro降级: %d", fallback)
    logger.info("  跳过(需靶机):  %d", skipped)
    logger.info("  总耗时:        %.0fs", sum(r.get("elapsed", 0) for r in results))

    for i, r in enumerate(results, 1):
        ch = r["challenge"]
        logger.info("  %2d. [%s] %s → %s", i, ch.category, ch.title, _bugku_brief(r))


def _save_bugku_report(results: list[dict], args: argparse.Namespace):
    """保存 Bugku JSON 报告"""
    if __name__ == "__main__" and __package__ is None:
        from AutoTest.config import REPORT_DIR
    else:
        from .config import REPORT_DIR
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORT_DIR / f"bugku_pwn_{ts}.json"

    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "platform": "bugku",
        "args": {
            "count": args.count,
            "category": args.category,
            "timeout": args.timeout,
        },
        "summary": {
            "total": len(results),
            "flag_obtained": sum(1 for r in results if r.get("lingshu") and r["lingshu"].flag),
            "submitted": sum(1 for r in results if r.get("flag_submitted")),
            "fallback_used": sum(1 for r in results if r.get("lingshu") and r["lingshu"].fallback_used),
            "total_elapsed_s": sum(r.get("elapsed", 0) for r in results),
        },
        "results": [
            {
                "challenge_id": r["challenge"].challenge_id,
                "title": r["challenge"].title,
                "category": r["challenge"].category,
                "flag": r["lingshu"].flag if r.get("lingshu") else None,
                "submitted": r.get("flag_submitted", False),
                "model_fallback": r["lingshu"].fallback_used if r.get("lingshu") else False,
                "elapsed_s": r.get("elapsed", 0),
                "error": r.get("error"),
            }
            for r in results
        ],
    }

    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("详细报告已保存: %s", report_path)


# ====================================================================
# 汇总报告
# ====================================================================
def _print_summary(results: list[TaskResult]):
    """控制台汇总输出"""
    total = len(results)
    success = sum(1 for r in results if r.success)
    flag_count = sum(1 for r in results if r.lingshu and r.lingshu.flag)
    submitted = sum(1 for r in results if r.submitted)
    fallback = sum(1 for r in results if r.lingshu and r.lingshu.fallback_used)

    logger.info("=" * 50)
    logger.info("汇总报告")
    logger.info("=" * 50)
    logger.info("  总题数:        %d", total)
    logger.info("  Lingshu 成功:  %d", success)
    logger.info("  获取 flag:     %d", flag_count)
    logger.info("  已提交:        %d", submitted)
    logger.info("  Flash→Pro降级: %d", fallback)
    logger.info("  总耗时:        %.0fs", sum(r.elapsed for r in results))

    for i, r in enumerate(results, 1):
        logger.info("  %2d. [%s] %s → %s", i,
                     r.challenge.category,
                     r.challenge.title,
                     r.brief())


def _save_report(results: list[TaskResult], args: argparse.Namespace):
    """保存 JSON 报告到文件"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORT_DIR / f"auto_pwn_{ts}.json"

    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "args": {
            "count": args.count,
            "category": args.category,
            "difficulty": args.difficulty,
            "timeout": args.timeout,
        },
        "summary": {
            "total": len(results),
            "success": sum(1 for r in results if r.success),
            "flag_obtained": sum(1 for r in results if r.lingshu and r.lingshu.flag),
            "submitted": sum(1 for r in results if r.submitted),
            "fallback_used": sum(1 for r in results if r.lingshu and r.lingshu.fallback_used),
            "total_elapsed_s": sum(r.elapsed for r in results),
        },
        "results": [
            {
                "challenge": {
                    "source_id": r.challenge.source_id,
                    "challenge_id": r.challenge.challenge_id,
                    "title": r.challenge.title,
                    "category": r.challenge.category,
                    "difficulty": r.challenge.difficulty,
                },
                "lingshu_success": r.success,
                "flag": r.lingshu.flag if r.lingshu else None,
                "submitted": r.submitted,
                "model_fallback": r.lingshu.fallback_used if r.lingshu else False,
                "elapsed_s": r.elapsed,
                "environment_error": r.environment_error,
                "submit_error": r.submit_error,
                "lingshu_error": r.lingshu_error,
            }
            for r in results
        ],
    }

    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("详细报告已保存: %s", report_path)


# ====================================================================
# 结果类型
# ====================================================================
class TaskResult:
    """单题处理结果"""

    def __init__(self, challenge: ChallengeInfo, start_time: datetime):
        self.challenge = challenge
        self.start_time = start_time
        self.lingshu: LingshuResult | None = None
        self.environment: dict | None = None
        self.submitted = False
        self.submit_result: dict | None = None
        self.elapsed: float = 0.0
        self.environment_error: str | None = None
        self.submit_error: str | None = None
        self.lingshu_error: str | None = None

    @property
    def success(self) -> bool:
        if self.lingshu and self.lingshu.success:
            return True
        return False

    def brief(self) -> str:
        parts = []
        if self.lingshu:
            if self.lingshu.flag:
                parts.append(f"flag={self.lingshu.flag}")
            parts.append(f"模型={self.lingshu.model_ver}")
            if self.lingshu.fallback_used:
                parts.append("(降级)")
            parts.append(f"耗时={self.elapsed:.0f}s")
        else:
            parts.append("Lingshu未运行")
        if self.submitted:
            parts.append("已提交")
        if self.environment_error:
            parts.append(f"环境错误: {self.environment_error}")
        if self.lingshu_error:
            parts.append(f"错误: {self.lingshu_error[:80]}")
        return " | ".join(parts)


# ====================================================================
# CLI
# ====================================================================
def _build_parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AutoTest 自动打靶 — CTF2 + Bugku 联动",
    )
    parser.add_argument(
        "--platform", "-P", type=str, default="ctf2",
        choices=["ctf2", "bugku"],
        help="平台选择（默认 ctf2）",
    )
    parser.add_argument(
        "--count", "-n", type=int, default=DEFAULT_COUNT,
        help=f"随机选题数（默认 {DEFAULT_COUNT}）",
    )
    parser.add_argument(
        "--category", "-c", type=str, default=None, nargs="+",
        help="限定题型（如 web pwn reverse crypto misc forensics），可多个",
    )
    parser.add_argument(
        "--difficulty", "-d", type=str, default=None,
        help="限定难度（如 easy/medium/hard）",
    )
    parser.add_argument(
        "--timeout", "-T", type=int, default=DEFAULT_TIMEOUT,
        help=f"每题超时秒数（默认 {DEFAULT_TIMEOUT}）",
    )
    parser.add_argument(
        "--goal", "-g", type=str, default=GOAL,
        help=f"任务目标（默认: {GOAL}）",
    )
    parser.add_argument(
        "--include-solved", action="store_true",
        help="包含已解题目（默认排除）",
    )
    parser.add_argument(
        "--practice-id", type=str, default=None,
        help="覆盖题目的 practice_id（用于 competition 题目需要靶机时）",
    )
    parser.add_argument(
        "--file", "-f", type=str, default=None,
        help="从 JSON 文件加载题目列表",
    )
    parser.add_argument(
        "--attachments-dir", "-A", type=str, default=None,
        help="附件本地目录（题目附件需手动从 CTF2 网页下载到此目录）",
    )
    parser.add_argument(
        "--list", "-l", action="store_true",
        help="仅列出可选题目，不执行打靶",
    )
    # Bugku 专属
    parser.add_argument(
        "--bugku-session", type=str, default=None,
        help="Bugku PHPSESSID cookie（默认用环境变量 BUGKU_PHPSESSID）",
    )
    parser.add_argument(
        "--max-pages", type=int, default=None,
        help="Bugku 每题型最大抓取页数（默认全部）",
    )
    return parser.parse_args()


# ====================================================================
# 入口
# ====================================================================
if __name__ == "__main__":
    args = _build_parser()

    if args.list:
        if args.platform == "bugku":
            from AutoTest.bugku_client import BugkuClient
            from AutoTest.bugku_picker import BugkuPicker
            from AutoTest.config import BUGKU_PHPSESSID
            client = BugkuClient(args.bugku_session or BUGKU_PHPSESSID)
            picker = BugkuPicker(client)
            picker.collect(categories=args.category if args.category else None,
                           max_pages=args.max_pages, free_only=True)
            for i, ch in enumerate(picker.collected, 1):
                tag = " [已解]" if ch.solved else ""
                logger.info("%3d. [%s] %s gold=%d%s", i, ch.category, ch.title, ch.gold, tag)
        else:
            client = CTF2Client()
            picker = ChallengePicker(client)
            picker.collect()
            for i, ch in enumerate(picker.collected, 1):
                tag = " [已解]" if ch.solved else ""
                extra = ""
                if ch.file_names:
                    extra = f" 📎{len(ch.file_names)}个附件"
                if ch.has_container:
                    extra += " 🖥️容器"
                logger.info("%3d. [%s] %s (%s)%s%s", i, ch.category, ch.title, ch.difficulty, tag, extra)
    else:
        asyncio.run(main(args))
