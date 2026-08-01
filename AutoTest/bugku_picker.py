"""
Bugku 题目收集与随机选取

从列表页 HTML 解析题目卡片，支持分页、分类过滤、免费筛选
"""
from __future__ import annotations

import random
import re
import logging
from dataclasses import dataclass, field
from typing import NamedTuple

from .bugku_client import BugkuClient
from .config import DEFAULT_COUNT

logger = logging.getLogger(__name__)

# 题型 tid 映射
CATEGORY_TID = {
    "web": 1,
    "misc": 4,
    "crypto": 6,
    "reverse": 7,
    "pwn": 8,
    "forensics": 10,
}
TID_CATEGORY = {v: k for k, v in CATEGORY_TID.items()}


class ChallengeInfo(NamedTuple):
    """Bugku 题目信息"""
    challenge_id: int
    title: str
    category: str          # web/misc/crypto/reverse/pwn/forensics
    tags: str              # 如 "SusCTF-2017"
    gold: int              # 金币数（0 = 免费）
    solved: bool           # 是否已解决
    has_attachment: bool = False
    has_scene: bool = False  # 是否需要靶机


class BugkuPicker:
    """Bugku 题目收集器"""

    def __init__(self, client: BugkuClient):
        self.client = client
        self._collected: list[ChallengeInfo] = []
        self._pages_per_category: dict[int, int] = {}  # tid -> 总页数

    # ------------------------------------------------------------------
    # 收集
    # ------------------------------------------------------------------
    def collect(self, categories: list[str] | None = None,
                max_pages: int | None = None,
                free_only: bool = True) -> list[ChallengeInfo]:
        """
        收集题目

        Args:
            categories: 限定题型列表，None 表示全部
            max_pages: 每题型最大抓取页数，None 表示全部
            free_only: 仅免费题目
        """
        self._collected.clear()

        tids = [CATEGORY_TID[c] for c in categories] if categories else list(CATEGORY_TID.values())

        for tid in tids:
            cat_name = TID_CATEGORY.get(tid, str(tid))
            self._collect_category(tid, cat_name, max_pages or 999, free_only)

        free_count = sum(1 for c in self._collected if c.gold == 0)
        solved_count = sum(1 for c in self._collected if c.solved)
        logger.info("共收集 %d 道题目（免费 %d，已解 %d）",
                     len(self._collected), free_count, solved_count)
        return self._collected

    def _collect_category(self, tid: int, cat_name: str,
                          max_pages: int, free_only: bool):
        """抓取单个分类的所有页面"""
        page = 1
        while page <= max_pages:
            html = self.client.get_challenge_list(page=page, category_tid=tid)
            cards = _parse_challenge_cards(html)

            if not cards:
                logger.debug("[%s] 第 %d 页无题目，停止", cat_name, page)
                break

            for card in cards:
                # 免费筛选
                if free_only and card["gold"] != 0:
                    continue
                # 补充分类
                if not card.get("category"):
                    card["category"] = cat_name

                info = ChallengeInfo(
                    challenge_id=card["challenge_id"],
                    title=card["title"],
                    category=card.get("category", cat_name),
                    tags=card.get("tags", ""),
                    gold=card.get("gold", 0),
                    solved=card.get("solved", False),
                    has_attachment=False,  # 后续从详情页补充
                    has_scene=False,
                )
                self._collected.append(info)

            logger.debug("[%s] 第 %d 页: %d 题 (累计 %d)",
                         cat_name, page, len(cards), len(self._collected))
            page += 1

        self._pages_per_category[tid] = page - 1

    def enrich_details(self, challenges: list[ChallengeInfo] | None = None):
        """为题目补充附件和靶机信息（从详情页获取）"""
        targets = challenges or self._collected
        for i, ch in enumerate(targets):
            try:
                html = self.client.get_challenge_detail(ch.challenge_id)
                has_attach = "/attachment/download/file/" in html
                has_scene = "createScene" in html or "启动场景" in html
                # 更新（ChallengeInfo 是 NamedTuple 不可变，需要重建）
                if has_attach != ch.has_attachment or has_scene != ch.has_scene:
                    new_ch = ch._replace(
                        has_attachment=has_attach,
                        has_scene=has_scene,
                    )
                    if challenges:
                        challenges[i] = new_ch
                    else:
                        self._collected[i] = new_ch
            except Exception:
                logger.debug("获取题目 %d 详情失败，跳过", ch.challenge_id)

    # ------------------------------------------------------------------
    # 选取
    # ------------------------------------------------------------------
    def random_pick(self, count: int = DEFAULT_COUNT,
                    exclude_solved: bool = True,
                    category: str | None = None,
                    has_attachment: bool | None = None,
                    free_only: bool = True) -> list[ChallengeInfo]:
        """随机选取 count 道题"""
        pool = list(self._collected)

        if free_only:
            pool = [c for c in pool if c.gold == 0]
        if exclude_solved:
            pool = [c for c in pool if not c.solved]
        if category:
            pool = [c for c in pool if c.category.lower() == category.lower()]
        if has_attachment is not None:
            pool = [c for c in pool if c.has_attachment == has_attachment]

        if len(pool) <= count:
            logger.info("可选题目 %d ≤ 需要数 %d，全部选取", len(pool), count)
            return pool

        selected = random.sample(pool, count)
        logger.info("从 %d 题中随机选取 %d 题", len(pool), count)
        return selected

    @property
    def collected(self) -> list[ChallengeInfo]:
        return self._collected


# ------------------------------------------------------------------
# HTML 解析
# ------------------------------------------------------------------
def _parse_challenge_cards(html: str) -> list[dict]:
    """
    从题目列表页 HTML 解析题目卡片

    每个卡片结构:
    <a href="/challenges/detail/id/{id}.html">
      <div class="card ...">
        [<div class="aman-card-tag">已解决</div>]
        <h6 ...>标题</h6>
        <h4>金币数</h4><small>金币</small>
        <h4>分数</h4><small>分数</small>
        <h4>解决数</h4><small>解决</small>
        <footer>[tag] [category]</footer>
    """
    cards = []

    # 用 detail/id/xxx.html 作为锚点，向前后扩展提取完整卡片
    for m in re.finditer(r'/challenges/detail/id/(\d+)\.html', html):
        challenge_id = int(m.group(1))
        # 取卡片上下文 (~1500 字符)
        start = max(0, m.start() - 1200)
        end = min(len(html), m.end() + 500)
        ctx = html[start:end]

        # 标题
        title = ""
        tm = re.search(r'<h6[^>]*title="([^"]*)"', ctx)
        if tm:
            title = tm.group(1)
        else:
            tm2 = re.search(r'<h6[^>]*>([^<]+)</h6>', ctx)
            if tm2:
                title = tm2.group(1).strip()

        # 已解决
        solved = "已解决" in ctx or "aman-card-tag" in ctx

        # 金币
        gold = 0
        gm = re.search(r'<h4[^>]*>(\d+)</h4>\s*<small>\s*金币', ctx)
        if gm:
            gold = int(gm.group(1))

        # 分类和标签 [tag] [category]
        tags = ""
        category = ""
        fm = re.search(r'<footer[^>]*>.*?\[([^\]]+)\]\s*\[([^\]]+)\]', ctx, re.DOTALL)
        if fm:
            tags = fm.group(1).strip()
            category = fm.group(2).strip().lower()

        cards.append({
            "challenge_id": challenge_id,
            "title": title,
            "category": category,
            "tags": tags,
            "gold": gold,
            "solved": solved,
        })

    return cards
