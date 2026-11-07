"""Model identifiers are "<provider>:<model>", e.g. mock:naive, openai:gpt-4o-mini,
anthropic:claude-sonnet-5-5, ollama:llama3.1:8b."""
from __future__ import annotations

from typing import Any

import httpx

from app.config import Settings
from app.llm.base import LLMProvider, ProviderError
from app.llm.mock import MockProvider
from app.llm.remote import AnthropicProvider, OllamaProvider, OpenAICompatProvider


def split_model_id(model_id: str) -> tuple[str, str]:
    if ":" not in model_id:
        raise ProviderError(f"model id must look like provider:model, got {model_id!r}")
    provider, model = model_id.split(":", 1)
    if not model:
        raise ProviderError(f"missing model name in {model_id!r}")
    return provider, model


class ProviderRegistry:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        common = dict(timeout=settings.request_timeout_s, temperature=settings.temperature,
                      max_tokens=settings.max_tokens, transport=transport)
        self.providers: dict[str, LLMProvider] = {
            "mock": MockProvider(latency_ms=settings.mock_latency_ms),
            "openai": OpenAICompatProvider(settings.openai_api_key, settings.list_models(settings.openai_models),
                                           base_url=settings.openai_base_url, **common),
            "anthropic": AnthropicProvider(settings.anthropic_api_key, settings.list_models(settings.anthropic_models),
                                           base_url=settings.anthropic_base_url, **common),
            "ollama": OllamaProvider(settings.list_models(settings.ollama_models),
                                     base_url=settings.ollama_base_url, **common),
        }

    def get(self, model_id: str) -> tuple[LLMProvider, str]:
        provider, model = split_model_id(model_id)
        if provider not in self.providers:
            raise ProviderError(f"unknown provider {provider!r}; expected one of {sorted(self.providers)}")
        return self.providers[provider], model

    def is_mock(self, model_id: str) -> bool:
        return split_model_id(model_id)[0] == "mock"

    async def catalog(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for pname, prov in self.providers.items():
            models = await prov.list_models()
            out.append({
                "provider": pname,
                "is_mock": prov.is_mock,
                "configured": prov.configured() and (pname != "ollama" or bool(models)),
                "models": [f"{pname}:{m}" for m in models],
            })
        return out
