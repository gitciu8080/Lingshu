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
    """从环境变量加载的模型与运行配置。

    同时支持 DeepSeek 和 Qwen (OpenAI 兼容 API) 两个提供商。
    通过 --provider 参数在运行时选择。
    """

    # ── DeepSeek ──
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model_low: str = "deepseek-v4-flash"       # 低推理（chat 已弃用合并为 flash）
    deepseek_model_min: str = "deepseek-v4-flash"       # 默认
    deepseek_model_max: str = "deepseek-v4-pro"         # 深度推理

    # ── Qwen (llama.cpp OpenAI 兼容) ──
    qwen_api_key: str = ""
    qwen_base_url: str = "http://10.8.128.108:8200/v1"
    qwen_model: str = "/mnt/nvme0n1p1/llama.cppModels/Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf"

    command_timeout: int = 300

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        _load_dotenv()
        return cls(
            # DeepSeek
            deepseek_api_key=os.getenv("DEEPSEEK_API_KEY", "").strip(),
            deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/"),
            deepseek_model_low=os.getenv("DEEPSEEK_MODEL_LOW", "deepseek-v4-flash"),
            deepseek_model_min=os.getenv("DEEPSEEK_MODEL_MIN", "deepseek-v4-flash"),
            deepseek_model_max=os.getenv("DEEPSEEK_MODEL_MAX", "deepseek-v4-pro"),
            # Qwen
            qwen_api_key=os.getenv("QWEN_API_KEY", "sk-placeholder").strip(),
            qwen_base_url=os.getenv("QWEN_BASE_URL", "http://10.8.128.108:8200/v1").rstrip("/"),
            qwen_model=os.getenv(
                "QWEN_MODEL",
                "/mnt/nvme0n1p1/llama.cppModels/Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf",
            ),
            # 通用
            command_timeout=max(10, min(int(os.getenv("LINGSHU_COMMAND_TIMEOUT", "300")), 600)),
        )

    def model_name(self, version: str, provider: str = "deepseek") -> str:
        """根据提供商和思考级别返回模型名称。"""
        if provider == "qwen":
            return self.qwen_model  # 单一模型，不随级别变化
        mapping = {
            "Low": self.deepseek_model_low,
            "Min": self.deepseek_model_min,
            "Max": self.deepseek_model_max,
        }
        try:
            return mapping[version]
        except KeyError as exc:
            raise ValueError(f"不支持的思考级别: {version}，可选 Low/Min/Max") from exc

    def get_api_key(self, provider: str) -> str:
        """返回对应提供商的 API Key。"""
        if provider == "qwen":
            return self.qwen_api_key
        return self.deepseek_api_key

    def get_base_url(self, provider: str) -> str:
        """返回对应提供商的 Base URL。"""
        if provider == "qwen":
            return self.qwen_base_url
        return self.deepseek_base_url
