"""
随机选题模块 — 从 CTF2 收集题目并随机选取

数据来源优先级：
  1. competitions → stages → challenges（已验证可行）
  2. submissions 记录中提取未解题目
  3. 手动指定 JSON 文件
"""
from __future__ import annotations

import random
import json
import logging
from pathlib import Path
from typing import NamedTuple

from .ctf2_client import CTF2Client, CTF2Error
from .config import DEFAULT_COUNT

logger = logging.getLogger(__name__)


class ChallengeInfo(NamedTuple):
    """题目简化信息"""
    source_id: str       # 来源 ID（practice_id / competition_id）
    challenge_id: str
    title: str
    category: str        # web / pwn / reverse / crypto / misc
    difficulty: str      # easy / medium / hard
    solved: bool
    has_container: bool = False   # 是否需要靶机
    file_names: tuple[str, ...] = ()  # 附件文件名列表

    # 启动靶机时需要 practice_id（competition 的题目可能也在 practice 下有副本）
    competition_id: str = ""


class ChallengePicker:
    """题目收集与随机选取"""

    def __init__(self, client: CTF2Client):
        self.client = client
        self._collected: list[ChallengeInfo] = []
        self._solved_ids: set[str] = set()  # challenge_id

    # ------------------------------------------------------------------
    # 收集
    # ------------------------------------------------------------------
    def collect(self) -> list[ChallengeInfo]:
        """收集所有可用题目"""
        self._collected.clear()
        self._load_solved()

        # 1. 从 competitions → stages → challenges 收集
        self._collect_from_competitions()

        # 2. 从 submissions 补充未收录的题目
        self._collect_from_submissions()

        logger.info("共收集 %d 道题目（已解 %d 道）",
                     len(self._collected), len(self._solved_ids))
        return self._collected

    def _collect_from_competitions(self):
        """从比赛 → 阶段 → 题目链收集"""
        try:
            competitions = self.client._get("/competitions/", {"limit": 50})
            comps = competitions.get("data", {}).get("items", [])
        except CTF2Error as e:
            logger.warning("获取比赛列表失败: %s", e)
            return

        for comp in comps:
            comp_id = comp.get("id", "")
            comp_name = comp.get("name", "???")
            if not comp_id:
                continue

            # 获取 stages
            try:
                stages_resp = self.client._get(
                    f"/competitions/{comp_id}/stages/", {"limit": 50}
                )
                stages = stages_resp.get("data", {}).get("items", [])
            except CTF2Error:
                continue

            for stage in stages:
                stage_id = stage.get("id", "")
                if not stage_id:
                    continue

                # 获取 challenges
                try:
                    ch_resp = self.client._get(
                        f"/stages/{stage_id}/challenges/", {"limit": 200}
                    )
                    challenges = ch_resp.get("data", {}).get("items", [])
                except CTF2Error:
                    continue

                for ch in challenges:
                    cid = str(ch.get("id", ""))
                    if not cid:
                        continue
                    files = ch.get("files", [])
                    file_names = tuple(
                        f.get("file", {}).get("original_name", "")
                        for f in files
                    )
                    self._add_challenge(
                        source_id=comp_id,
                        challenge_id=cid,
                        title=ch.get("name") or ch.get("title", "???"),
                        category=str(ch.get("category", "unknown")),
                        difficulty=str(ch.get("difficulty", "unknown")),
                        competition_id=comp_id,
                        has_container=bool(ch.get("has_container", False)),
                        file_names=file_names,
                    )

            logger.debug("  比赛 [%s]: %d 题", comp_name, len(self._collected))

    def _collect_from_submissions(self):
        """从提交记录中提取题目信息（补充未收录的）"""
        existing_ids = {c.challenge_id for c in self._collected}
        try:
            subs = self.client.get_submissions()
        except CTF2Error:
            return

        for sub in subs:
            ch = sub.get("challenge", {})
            cid = str(ch.get("id", "") or sub.get("challenge_id", ""))
            if not cid or cid in existing_ids:
                continue
            existing_ids.add(cid)
            self._add_challenge(
                source_id=sub.get("practice_id") or sub.get("competition_id") or "",
                challenge_id=cid,
                title=ch.get("name") or ch.get("title", "???"),
                category=str(ch.get("category", "unknown")),
                difficulty=str(ch.get("difficulty", "unknown")),
            )

    def load_from_file(self, path: str | Path):
        """从 JSON 文件加载题目列表"""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        items = data if isinstance(data, list) else data.get("challenges", [])
        for item in items:
            cid = str(item.get("challenge_id", item.get("id", "")))
            self._add_challenge(
                source_id=str(item.get("practice_id", item.get("source_id", ""))),
                challenge_id=cid,
                title=item.get("title") or item.get("name", "???"),
                category=str(item.get("category", "unknown")),
                difficulty=str(item.get("difficulty", "unknown")),
            )
        logger.info("从文件加载 %d 题", len(items))

    def _add_challenge(self, source_id: str, challenge_id: str,
                       title: str, category: str, difficulty: str,
                       competition_id: str = "",
                       has_container: bool = False,
                       file_names: tuple[str, ...] = ()):
        solved = challenge_id in self._solved_ids
        info = ChallengeInfo(
            source_id=source_id,
            challenge_id=challenge_id,
            title=title,
            category=category.lower(),
            difficulty=difficulty.lower(),
            solved=solved,
            competition_id=competition_id or source_id,
            has_container=has_container,
            file_names=file_names,
        )
        self._collected.append(info)

    def _load_solved(self):
        """从提交记录加载已解题目 ID"""
        self._solved_ids.clear()
        try:
            for sub in self.client.get_submissions():
                if sub.get("is_correct"):
                    self._solved_ids.add(str(sub.get("challenge_id", "")))
        except Exception:
            logger.debug("加载提交记录失败", exc_info=True)

    # ------------------------------------------------------------------
    # 选取
    # ------------------------------------------------------------------
    def random_pick(self, count: int = DEFAULT_COUNT,
                    exclude_solved: bool = True,
                    category: str | None = None,
                    difficulty: str | None = None) -> list[ChallengeInfo]:
        """随机选取 count 道题"""
        pool = list(self._collected)

        if exclude_solved:
            pool = [c for c in pool if not c.solved]

        if category:
            pool = [c for c in pool if c.category.lower() == category.lower()]

        if difficulty:
            pool = [c for c in pool if c.difficulty.lower() == difficulty.lower()]

        if len(pool) <= count:
            logger.info("可选题目 %d ≤ 需要数 %d，全部选取", len(pool), count)
            return pool

        selected = random.sample(pool, count)
        logger.info("从 %d 题中随机选取 %d 题", len(pool), count)
        return selected

    @property
    def collected(self) -> list[ChallengeInfo]:
        return self._collected
