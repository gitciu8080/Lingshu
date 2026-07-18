"""灵枢运行配置与目标范围校验。"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(dotenv_path: str | Path = ".env") -> None:
    """加载 .env 文件到 os.environ（不覆盖已有的环境变量）。"""
    path = Path(dotenv_path).resolve()
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip("\"'")
            if key and key not in os.environ:
                os.environ[key] = val


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
)


def validate_target(target: str) -> str:
    """验证并规范化单个 IP 或主机名目标。"""
    value = target.strip().rstrip(".")
    if not value or any(char in value for char in "/\\:@?#[]"):
        raise ValueError("目标必须是单个 IP 地址或主机名，不能包含 URL、端口或路径")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not _HOSTNAME_RE.fullmatch(value):
            raise ValueError(f"无效的目标地址: {target!r}") from None
        return value.lower()


@dataclass(frozen=True)
class RuntimeConfig:
    """从环境变量加载的模型与运行配置。"""

    api_key: str
    base_url: str = "https://api.deepseek.com"
    model_flash: str = "deepseek-v4-flash"
    model_pro: str = "deepseek-v4-pro"
    model_chat: str = "deepseek-chat"
    command_timeout: int = 300

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        _load_dotenv()
        api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError(
                "缺少 DEEPSEEK_API_KEY。请先在 Kali 环境中设置该环境变量。",
            )
        return cls(
            api_key=api_key,
            base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/"),
            model_flash=os.getenv("DEEPSEEK_MODEL_FLASH", "deepseek-v4-flash"),
            model_pro=os.getenv("DEEPSEEK_MODEL_PRO", "deepseek-v4-pro"),
            model_chat=os.getenv("DEEPSEEK_MODEL_CHAT", "deepseek-chat"),
            command_timeout=max(10, min(int(os.getenv("LINGSHU_COMMAND_TIMEOUT", "300")), 600)),
        )

    def model_name(self, version: str) -> str:
        mapping = {
            "Flash": self.model_flash,
            "Pro": self.model_pro,
            "chat": self.model_chat,
        }
        try:
            return mapping[version]
        except KeyError as exc:
            raise ValueError(f"不支持的模型版本: {version}") from exc
