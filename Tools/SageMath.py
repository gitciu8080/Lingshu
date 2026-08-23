# Tools/SageMath.py
"""SageMath 执行工具 - 用于密码学、数论、符号计算等 CTF 场景

执行位置与 scoped_shell / OCR 保持一致：
代码 base64 编码后写入会话 Docker 工作区容器内执行，使用镜像内的
/usr/local/bin/sage（kali-full v3.0 起为 /opt/miniconda3/envs/sage）。
"""
from __future__ import annotations

import base64
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from Tools.tooling import AllowedFunctionTool

logger = logging.getLogger(__name__)

SAGE_TIMEOUT = int(os.getenv("LINGSHU_SAGE_TIMEOUT", "180"))

# 安全检查：禁止危险操作
FORBIDDEN_PATTERNS = ["os.system", "subprocess", "__import__", "open(", "eval(", "exec("]


def create_sagemath_tool(
    allowed_root: str | Path = "",
    timeout: int | None = None,
    *,
    executor: Any,
) -> AllowedFunctionTool:
    """创建 SageMath 代码执行工具（在 Docker 容器内执行）。

    Args:
        allowed_root: 授权工作区根目录（保留参数，当前实现不限制代码内容，
            仅用于未来扩展）。
        timeout: 默认超时秒数；None 时使用 LINGSHU_SAGE_TIMEOUT。
        executor: LingshuDockerExecutor 实例。SageMath 在会话 Docker 容器内
            执行（Agent 工作区镜像自带 sage）。
    """
    default_timeout = timeout if timeout is not None else SAGE_TIMEOUT

    async def execute_sagemath(code: str, timeout: int | None = None) -> str:
        """在隔离 SageMath 环境中执行数学/密码学计算代码。

        适用场景：RSA/ECC/离散对数等密码学计算、大数运算、模逆、中国剩余定理、
        符号方程求解、多项式因式分解、矩阵运算、格密码 (LLL)、Coppersmith 等。

        Args:
            code: 合法的 SageMath/Python 代码。必须用 print() 输出结果。
                  每次调用都是全新会话，变量不持久化。
            timeout: 超时秒数，默认由服务端配置决定。

        Returns:
            str: 执行结果（stdout）或错误信息（stderr）。
        """
        for pattern in FORBIDDEN_PATTERNS:
            if pattern in code:
                return f"[BLOCKED] 代码包含禁止的模式: {pattern}"

        effective = timeout if timeout is not None else default_timeout
        effective = max(10, int(effective))
        return await _run_in_container(code, effective, executor)

    async def _run_in_container(code: str, seconds: int, exe: Any) -> str:
        """把代码 base64 编码后送入容器 /tmp 执行，避免 shell 注入与编码问题。"""
        b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
        tmp = f"/tmp/lingshu_sage_{uuid.uuid4().hex}.sage"
        cmd = (
            f"printf %s '{b64}' | base64 -d > '{tmp}' && "
            f"sage '{tmp}'; rc=$?; rm -f '{tmp}'; exit $rc"
        )
        outcome = await exe.exec_shell(cmd, timeout=seconds)
        stdout = outcome.stdout.decode("utf-8", errors="replace").strip()
        stderr = outcome.stderr.decode("utf-8", errors="replace").strip()

        if outcome.timed_out:
            return (
                f"[SageMath Timeout] 执行超过 {seconds} 秒被强制终止，"
                f"请优化算法或减少计算量。\n\n[已有输出]\n{stdout}" if stdout
                else f"[SageMath Timeout] 执行超过 {seconds} 秒被强制终止，请优化算法或减少计算量"
            )
        # GNU timeout: 126/127 表示命令不存在
        if outcome.exit_code in (126, 127):
            return f"[SageMath Error] 容器内找不到 sage 命令。\n{stderr}"
        if outcome.exit_code != 0:
            if stdout:
                return f"[SageMath Error]\n{stderr}\n\n[Stdout]\n{stdout}"
            return f"[SageMath Error]\n{stderr}"
        return stdout or "[SageMath] 执行成功但无输出（请检查是否使用了 print()）"

    return AllowedFunctionTool(execute_sagemath, is_read_only=True)
