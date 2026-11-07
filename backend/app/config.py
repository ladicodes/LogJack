"""Application settings, loaded from environment variables (prefix LOGJACK_) or backend/.env."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"
PROJECT_DIR = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LOGJACK_",
        env_file=str(BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Storage
    db_path: str = str(DATA_DIR / "logjack.db")
    data_dir: str = str(DATA_DIR)

    # OpenAI-compatible endpoint (OpenAI, Azure-compatible gateways, vLLM, LM Studio, ...)
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_models: str = "gpt-4o-mini"

    # Anthropic Messages API
    anthropic_api_key: str = ""
    anthropic_base_url: str = "https://api.anthropic.com"
    anthropic_models: str = "claude-sonnet-5-5,claude-haiku-5-5"

    # Ollama (local models)
    ollama_base_url: str = "http://localhost:11434"
    ollama_models: str = ""  # optional comma list; otherwise discovered via /api/tags

    # Generation settings
    temperature: float = 0.0
    max_tokens: int = 800
    request_timeout_s: float = 60.0

    # Mock provider
    mock_latency_ms: int = 2

    # Canary salt used to derive per-case canary tokens deterministically
    canary_salt: str = "logjack-local-canary-salt"

    # Serve the built frontend (frontend/dist) from the API server when present
    serve_frontend: bool = True
    frontend_dist: str = str(PROJECT_DIR / "frontend" / "dist")

    def list_models(self, raw: str) -> list[str]:
        return [m.strip() for m in raw.split(",") if m.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
