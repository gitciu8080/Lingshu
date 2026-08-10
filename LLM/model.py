"""AgentScope 2.x 模型工厂 — DeepSeek + Qwen (llama.cpp 兼容)。

思考级别:
  Low → 快速响应 / 低推理深度
  Min → 默认平衡（默认）
  Max → 深度推理 / 强思考链
"""
from agentscope.credential import DeepSeekCredential, OpenAICredential
from agentscope.model import DeepSeekChatModel, OpenAIChatModel
from pydantic import SecretStr

from config import RuntimeConfig


def DeepSeek(
        Ver: str = "Min",
        think: bool = True,
        temperature: float = 0.7,
        config: RuntimeConfig | None = None,
) -> DeepSeekChatModel:
    """创建 AgentScope 2.x 原生 DeepSeek 模型。

    Args:
        Ver: 思考级别（Low/Min/Max）。
        think: 是否启用思考链（Low 时为 False）。
        temperature: 温度参数。
        config: 运行时配置。
    """
    runtime = config or RuntimeConfig.from_env()
    _reasoning_effort="Low"
    if Ver == "Low":
        _reasoning_effort="Low"
    elif Ver == "Min":
        _reasoning_effort="high"
    else:
        _reasoning_effort="max"
    return DeepSeekChatModel(
        credential=DeepSeekCredential(
            api_key=SecretStr(runtime.get_api_key("deepseek")),
            base_url=runtime.get_base_url("deepseek"),
        ),
        model=runtime.model_name(Ver, provider="deepseek"),
        parameters=DeepSeekChatModel.Parameters(
            thinking_enable=1,
            temperature=temperature,
            reasoning_effort=_reasoning_effort,
        ),
        stream=True,
        max_retries=3,
        client_kwargs={"timeout": 600.0},
    )


def Qwen(
        Ver: str = "Min",
        temperature: float = 0.7,
        config: RuntimeConfig | None = None,
) -> OpenAIChatModel:
    """创建 Qwen 模型（llama.cpp OpenAI 兼容 API）。

    思考级别通过 extra_body 传递给 llama.cpp 服务器:
      Low  → thinking=false (快速、低延迟)
      Min  → thinking=true  (默认平衡)
      Max  → thinking=true + max_tokens=8192 (深度推理)

    Args:
        Ver: 思考级别（Low/Min/Max）。
        temperature: 温度参数。
        config: 运行时配置。
    """
    runtime = config or RuntimeConfig.from_env()
    model_name = runtime.model_name(Ver, provider="qwen")

    # 思考级别 → 推理参数
    _think_levels = {
        "Low": {"thinking": False, "max_tokens": 2048},
        "Min": {"thinking": True,  "max_tokens": 4096},
        "Max": {"thinking": True,  "max_tokens": 8192},
    }
    level = _think_levels.get(Ver, _think_levels["Min"])

    return OpenAIChatModel(
        credential=OpenAICredential(
            api_key=SecretStr(runtime.get_api_key("qwen")),
            base_url=runtime.get_base_url("qwen"),
        ),
        model=model_name,
        parameters=OpenAIChatModel.Parameters(
            temperature=temperature,
            max_tokens=level["max_tokens"],
            extra_body={"thinking": level["thinking"]},
        ),
        stream=True,
        max_retries=3,
        client_kwargs={"timeout": 600.0},
    )


def create_model(
        provider: str = "deepseek",
        Ver: str = "Min",
        temperature: float = 0.7,
        config: RuntimeConfig | None = None,
):
    """统一的模型工厂入口。

    Args:
        provider: 提供商 — "deepseek" 或 "qwen"。
        Ver: 思考级别 — "Low" / "Min" / "Max"。
        temperature: 温度参数。
        config: 运行时配置。

    Returns:
        DeepSeekChatModel 或 OpenAIChatModel 实例。
    """
    if provider == "qwen":
        return Qwen(Ver=Ver, temperature=temperature, config=config)
    return DeepSeek(Ver=Ver, think=True, temperature=temperature, config=config)
