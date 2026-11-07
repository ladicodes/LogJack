"""HTTP providers for real LLMs: OpenAI-compatible, Anthropic Messages API, and Ollama."""
from __future__ import annotations

import time
from typing import Any

import httpx

from app.llm.base import LLMProvider, LLMResponse, ProviderError


class _HTTPProvider(LLMProvider):
    def __init__(self, base_url: str, timeout: float, temperature: float, max_tokens: int,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.transport = transport

    def _client(self, timeout: float | None = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout or self.timeout, transport=self.transport)

    async def _post(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        async with self._client() as client:
            try:
                return await client.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                raise ProviderError(f"{self.name} request failed: {exc!r}") from exc


class OpenAICompatProvider(_HTTPProvider):
    name = "openai"

    def __init__(self, api_key: str, models: list[str], **kw: Any):
        super().__init__(**kw)
        self.api_key = api_key
        self.models = models

    def configured(self) -> bool:
        return bool(self.api_key)

    async def list_models(self) -> list[str]:
        return self.models if self.configured() else []

    async def complete(self, model: str, system: str, user: str) -> LLMResponse:
        if not self.api_key:
            raise ProviderError("LOGJACK_OPENAI_API_KEY is not set")
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        t0 = time.perf_counter()
        resp = await self._post(f"{self.base_url}/chat/completions", payload, headers)
        if resp.status_code == 400 and ("max_tokens" in resp.text or "temperature" in resp.text):
            # Some newer models only accept max_completion_tokens and the default temperature.
            payload.pop("max_tokens", None)
            payload.pop("temperature", None)
            payload["max_completion_tokens"] = self.max_tokens
            resp = await self._post(f"{self.base_url}/chat/completions", payload, headers)
        latency = (time.perf_counter() - t0) * 1000
        if resp.status_code >= 400:
            raise ProviderError(f"openai HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"unexpected openai response: {str(data)[:300]}") from exc
        return LLMResponse(text=text, latency_ms=latency, model=model, provider=self.name,
                           usage=data.get("usage") or {})


class AnthropicProvider(_HTTPProvider):
    name = "anthropic"

    def __init__(self, api_key: str, models: list[str], **kw: Any):
        super().__init__(**kw)
        self.api_key = api_key
        self.models = models

    def configured(self) -> bool:
        return bool(self.api_key)

    async def list_models(self) -> list[str]:
        return self.models if self.configured() else []

    async def complete(self, model: str, system: str, user: str) -> LLMResponse:
        if not self.api_key:
            raise ProviderError("LOGJACK_ANTHROPIC_API_KEY is not set")
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "temperature": self.temperature,
        }
        t0 = time.perf_counter()
        resp = await self._post(f"{self.base_url}/v1/messages", payload, headers)
        if resp.status_code == 400 and "temperature" in resp.text:
            payload.pop("temperature", None)
            resp = await self._post(f"{self.base_url}/v1/messages", payload, headers)
        latency = (time.perf_counter() - t0) * 1000
        if resp.status_code >= 400:
            raise ProviderError(f"anthropic HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        return LLMResponse(text=text, latency_ms=latency, model=model, provider=self.name,
                           usage=data.get("usage") or {})


class OllamaProvider(_HTTPProvider):
    name = "ollama"

    def __init__(self, models: list[str], **kw: Any):
        super().__init__(**kw)
        self.models = models

    async def list_models(self) -> list[str]:
        if self.models:
            return self.models
        try:
            async with self._client(timeout=1.5) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
            if resp.status_code == 200:
                return [m["name"] for m in resp.json().get("models", [])]
        except (httpx.HTTPError, ValueError, KeyError):
            pass
        return []

    async def complete(self, model: str, system: str, user: str) -> LLMResponse:
        payload = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": "json",
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        }
        t0 = time.perf_counter()
        resp = await self._post(f"{self.base_url}/api/chat", payload, {})
        latency = (time.perf_counter() - t0) * 1000
        if resp.status_code >= 400:
            raise ProviderError(f"ollama HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        text = (data.get("message") or {}).get("content", "")
        return LLMResponse(text=text, latency_ms=latency, model=model, provider=self.name,
                           usage={k: data.get(k) for k in ("prompt_eval_count", "eval_count") if k in data})
