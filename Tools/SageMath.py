# Tools/SageMath.py
"""SageMath 跨环境执行工具 - 用于密码学、数论、符号计算等 CTF 场景"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# ⚠️ 根据实际部署环境调整
CONDA_CMD = os.getenv("LINGSHU_CONDA_CMD", "conda")
SAGE_ENV_NAME = os.getenv("LINGSHU_SAGE_ENV", "sage")
SAGE_TIMEOUT = int(os.getenv("LINGSHU_SAGE_TIMEOUT", "120"))


def execute_sagemath(code: str, timeout: int | None = None) -> str:
    """在独立 Sage conda 环境中执行 SageMath 代码。

    适用场景：
    - RSA/ECC/离散对数等密码学计算
    - 大数运算、模逆、中国剩余定理
    - 符号方程求解、多项式因式分解
    - 矩阵运算、线性代数
    - 数论函数（欧拉函数、原根、二次剩余等）

    Args:
        code: 合法的 SageMath/Python 代码。必须用 print() 输出结果。
              每次调用都是全新会话，变量不持久化。
        timeout: 超时秒数，默认使用环境变量 LINGSHU_SAGE_TIMEOUT

    Returns:
        str: 执行结果（stdout）或错误信息（stderr）
    """
    if timeout is None:
        timeout = SAGE_TIMEOUT

    # 安全检查：禁止危险操作
    forbidden = ["os.system", "subprocess", "__import__", "open(", "eval(", "exec("]
    for pattern in forbidden:
        if pattern in code:
            return f"[BLOCKED] 代码包含禁止的模式: {pattern}"

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sage", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            f.flush()
            tmp_path = f.name

        cmd = [
            CONDA_CMD, "run",
            "-n", SAGE_ENV_NAME,
            "sage", tmp_path,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode == 0:
            return stdout if stdout else "[SageMath] 执行成功但无输出（请检查是否使用了 print()）"
        else:
            # 返回 stderr 帮助 Agent 自我修正
            return f"[SageMath Error]\n{stderr}\n\n[Stdout]\n{stdout}" if stdout else f"[SageMath Error]\n{stderr}"

    except subprocess.TimeoutExpired:
        return f"[SageMath Timeout] 执行超过 {timeout} 秒，请优化算法或减少计算量"
    except FileNotFoundError:
        return (
            f"[SageMath Config Error] 找不到 '{CONDA_CMD}'，"
            f"请检查 LINGSHU_CONDA_CMD 环境变量或 conda 安装"
        )
    except Exception as e:
        logger.exception("SageMath execution failed")
        return f"[SageMath Exception] {type(e).__name__}: {e}"
    finally:
        if tmp_path and Path(tmp_path).exists():
            Path(tmp_path).unlink(missing_ok=True)