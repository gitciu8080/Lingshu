"""
Lingshu 调用封装 — subprocess 调用 + flag 提取 + Flash→Pro 模型降级
"""
from __future__ import annotations

import asyncio
import logging
import re
import sys
from pathlib import Path

from .config import (
    LINGSHU_DIR,
    LINGSHU_MAIN,
    FLASH_MODEL,
    PRO_MODEL,
    GOAL,
    DEFAULT_TIMEOUT,
    PYTHON_BIN,
)

logger = logging.getLogger(__name__)

# flag 正则：匹配 flag{...} 或 ctf{...} 等常见格式
FLAG_PATTERN = re.compile(
    r"(?:flag|ctf)\{[^\s]{3,}\}",
    re.IGNORECASE,
)


def extract_flag(text: str) -> str | None:
    """从文本中提取第一个 flag"""
    m = FLAG_PATTERN.search(text)
    return m.group(0) if m else None


async def run_lingshu(
    target: str,
    model_ver: str = FLASH_MODEL,
    goal: str = GOAL,
    timeout: int = DEFAULT_TIMEOUT,
) -> LingshuResult:
    """
    通过 subprocess 异步调用 Lingshu/main.py

    返回 LingshuResult，含输出、flag、成功状态、耗时
    """
    cmd = [
        PYTHON_BIN,                               # 优先使用 venv Python
        str(LINGSHU_MAIN),
        "-t", target,
        "-m", model_ver,
        "-g", goal,
    ]
    logger.info("启动 Lingshu [%s]: %s", model_ver, " ".join(cmd[2:]))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(LINGSHU_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        stdout_bytes, _ = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("Lingshu 超时 (%ds)，强制终止", timeout)
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return LingshuResult(
            model_ver=model_ver,
            success=False,
            flag=None,
            output="[TIMEOUT]",
            elapsed=timeout,
        )

    output = stdout_bytes.decode("utf-8", errors="replace")
    flag = extract_flag(output)
    success = flag is not None

    return LingshuResult(
        model_ver=model_ver,
        success=success,
        flag=flag,
        output=output,
        elapsed=timeout,  # 近似值，后续可用 time.monotonic 精确计时
    )


async def run_with_fallback(
    target: str,
    goal: str = GOAL,
    timeout: int = DEFAULT_TIMEOUT,
) -> LingshuResult:
    """
    Flash 模型优先，失败则降级到 Pro 模型

    返回最终结果（Flash 或 Pro 中成功的那个，或最后一次失败的）
    """
    # 第一轮：Flash
    result = await run_lingshu(target, model_ver=FLASH_MODEL, goal=goal, timeout=timeout)

    if result.success:
        logger.info("Flash 模型成功，flag = %s", result.flag)
        return result

    logger.warning("Flash 模型失败，降级到 Pro 模型重试...")

    # 第二轮：Pro
    pro_result = await run_lingshu(target, model_ver=PRO_MODEL, goal=goal, timeout=timeout)

    if pro_result.success:
        logger.info("Pro 模型成功，flag = %s", pro_result.flag)
    else:
        logger.error("两轮模型均未拿到 flag")

    # 合并结果
    pro_result.fallback_used = True
    pro_result.flash_result = result
    return pro_result


# ------------------------------------------------------------------
# 结果类型
# ------------------------------------------------------------------
class LingshuResult:
    """Lingshu 单次运行结果"""

    def __init__(
        self,
        model_ver: str,
        success: bool,
        flag: str | None,
        output: str,
        elapsed: float,
    ):
        self.model_ver = model_ver
        self.success = success
        self.flag = flag
        self.output = output
        self.elapsed = elapsed
        self.fallback_used = False
        self.flash_result: LingshuResult | None = None

    @property
    def total_elapsed(self) -> float:
        if self.flash_result:
            return self.flash_result.elapsed + self.elapsed
        return self.elapsed

    def summary(self) -> str:
        base = (
            f"模型={self.model_ver} "
            f"成功={'是' if self.success else '否'} "
            f"flag={self.flag or '无'} "
            f"耗时={self.elapsed:.0f}s"
        )
        if self.fallback_used:
            base += f" (Flash失败后降级, 总耗时={self.total_elapsed:.0f}s)"
        return base
