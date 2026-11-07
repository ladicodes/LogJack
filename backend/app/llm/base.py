from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class ProviderError(RuntimeError):
    pass


@dataclass
class LLMResponse:
    text: str
    latency_ms: float
    model: str
    provider: str
    usage: dict[str, Any] = field(default_factory=dict)


class LLMProvider:
    name: str = "base"
    is_mock: bool = False

    async def complete(self, model: str, system: str, user: str) -> LLMResponse:  # pragma: no cover
        raise NotImplementedError

    async def list_models(self) -> list[str]:  # pragma: no cover
        return []

    def configured(self) -> bool:
        return True
