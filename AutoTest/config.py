"""
AutoTest 自动打靶 — 配置模块
"""
import os
from pathlib import Path

# ---------- CTF2 API 配置 ----------
CTF2_BASE_URL = os.getenv("CTF2_BASE_URL", "https://ctf2.dasctf.com")
CTF2_API_KEY = os.getenv(
    "CTF2_API_KEY",
    "ctf2_e74f30dbd1342eae8d56ba5cf2455dfcf34fcd05011b46b66113ba0c99428083",
)
CTF2_API_PREFIX = "/api/open/v1/user"

# ---------- Bugku 平台配置 ----------
BUGKU_PHPSESSID = os.getenv(
    "BUGKU_PHPSESSID",
    "dde7d7d37fa94a8bea718b59adea3ca2",
)

# ---------- Lingshu 路径 ----------
AUTOTEST_DIR = Path(__file__).resolve().parent          # AutoTest/
LINGSHU_DIR = AUTOTEST_DIR.parent                         # Lingshu/
LINGSHU_MAIN = LINGSHU_DIR / "main.py"                   # Lingshu 入口
ATTACHMENTS_DIR = AUTOTEST_DIR / "attachments"            # 附件下载目录

# 优先使用 venv 中的 Python
_VENV_PYTHON = LINGSHU_DIR.parent.parent / "venv" / "bin" / "python"
PYTHON_BIN = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else "python3"

# ---------- 打靶配置 ----------
DEFAULT_COUNT = 10           # 默认随机选题数
DEFAULT_TIMEOUT = 1800       # 每题超时（秒），30 分钟
FLASH_MODEL = "Min"          # Flash + 思考链
PRO_MODEL = "Max"            # Pro 深度推理
GOAL = "获取 Flag"           # 默认任务目标

# ---------- 输出 ----------
REPORT_DIR = AUTOTEST_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)
ATTACHMENTS_DIR.mkdir(exist_ok=True)
