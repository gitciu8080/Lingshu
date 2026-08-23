"""系统提示词加载器。

所有 Agent 的系统提示词统一存放在 ``agent/Prompt/*.md``，
通过本模块按名字读取，避免提示词散落在各 Python 文件中。
"""
from __future__ import annotations

from pathlib import Path

_PROMPT_DIR = Path(__file__).resolve().parent / "Prompt"


def load_prompt(name: str) -> str:
    """读取 ``Prompt/{name}.md`` 的 UTF-8 文本作为系统提示词。

    Args:
        name: 提示词文件名（不含 ``.md`` 后缀），如 ``BRAIN``、``ATTACK``。

    Returns:
        提示词原文。
    """
    return (_PROMPT_DIR / f"{name}.md").read_text(encoding="utf-8")
