"""AgentScope 2.x DeepSeek 模型工厂。"""
from agentscope.credential import DeepSeekCredential
from agentscope.model import DeepSeekChatModel

from config import RuntimeConfig


def DeepSeek(
    Ver: str = "Flash",
    think: bool = True,
    temperature: float = 0.7,
    config: RuntimeConfig | None = None,
) -> DeepSeekChatModel:
    """创建 AgentScope 2.x 原生 DeepSeek 模型。"""
    runtime = config or RuntimeConfig.from_env()
    return DeepSeekChatModel(
        credential=DeepSeekCredential(
            api_key=runtime.api_key,
            base_url=runtime.base_url,
        ),
        model=runtime.model_name(Ver),
        parameters=DeepSeekChatModel.Parameters(
            thinking_enable=think,
            temperature=temperature,
            max_tokens=4096,
        ),
        stream=True,
        max_retries=3,
        client_kwargs={"timeout": 600.0},
    )
