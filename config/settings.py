"""Centralised, typed application settings.

Settings are loaded from environment variables (and an optional ``.env`` file)
using ``pydantic-settings``. The whole system is designed so that it runs in a
deterministic *offline* mode when no third-party API keys are configured, and
transparently upgrades to live LLM / embeddings / web-search when keys exist.

This module is intentionally dependency-light so it can be imported from any
layer (tools, agents, UI, evals) without side effects.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

try:  # pydantic-settings is the supported path
    from pydantic_settings import BaseSettings, SettingsConfigDict

    _HAS_PYDANTIC_SETTINGS = True
except Exception:  # pragma: no cover - extremely defensive fallback
    _HAS_PYDANTIC_SETTINGS = False


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


if _HAS_PYDANTIC_SETTINGS:

    class Settings(BaseSettings):
        """Strongly-typed runtime configuration.

        All fields can be overridden via environment variables. The ``CSAI_``
        prefix namespaces our settings so they don't collide with provider
        SDK variables such as ``OPENAI_API_KEY`` (which we read explicitly).
        """

        model_config = SettingsConfigDict(
            env_file=str(PROJECT_ROOT / ".env"),
            env_file_encoding="utf-8",
            extra="ignore",
            case_sensitive=False,
        )

        # ---- Provider credentials (read with their canonical names) ----
        openai_api_key: str = ""
        tavily_api_key: str = ""

        # ---- ServiceNow CMDB (optional; offline fixture used if unset) ----
        snow_instance_url: str = ""
        snow_username: str = ""
        snow_password: str = ""

        # ---- Model selection ----
        csai_llm_model: str = "gpt-4o-mini"
        csai_embedding_model: str = "text-embedding-3-small"

        # ---- Behaviour ----
        csai_offline: bool = False
        csai_temperature: float = 0.1
        csai_index_dir: str = ".cache/faiss_index"
        csai_log_level: str = "INFO"

        # ---- Derived helpers -------------------------------------------------
        @property
        def has_openai(self) -> bool:
            return bool(self.openai_api_key) and not self.csai_offline

        @property
        def has_tavily(self) -> bool:
            return bool(self.tavily_api_key) and not self.csai_offline

        @property
        def has_servicenow(self) -> bool:
            return (
                bool(self.snow_instance_url)
                and bool(self.snow_username)
                and bool(self.snow_password)
                and not self.csai_offline
            )

        @property
        def offline(self) -> bool:
            """True when no live LLM is available (forced or no key)."""
            return self.csai_offline or not bool(self.openai_api_key)

        @property
        def index_path(self) -> Path:
            p = PROJECT_ROOT / self.csai_index_dir
            p.mkdir(parents=True, exist_ok=True)
            return p

        @property
        def data_dir(self) -> Path:
            return DATA_DIR

        def summary(self) -> dict:
            """A redacted snapshot suitable for display in the UI / logs."""
            return {
                "llm_model": self.csai_llm_model,
                "embedding_model": self.csai_embedding_model,
                "openai_configured": bool(self.openai_api_key),
                "tavily_configured": bool(self.tavily_api_key),
                "servicenow_configured": bool(self.snow_instance_url),
                "offline_mode": self.offline,
                "temperature": self.csai_temperature,
            }

else:  # pragma: no cover - fallback if pydantic-settings is unavailable

    class Settings:  # type: ignore[no-redef]
        def __init__(self) -> None:
            self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
            self.tavily_api_key = os.getenv("TAVILY_API_KEY", "")
            self.snow_instance_url = os.getenv("SNOW_INSTANCE_URL", "")
            self.snow_username = os.getenv("SNOW_USERNAME", "")
            self.snow_password = os.getenv("SNOW_PASSWORD", "")
            self.csai_llm_model = os.getenv("CSAI_LLM_MODEL", "gpt-4o-mini")
            self.csai_embedding_model = os.getenv(
                "CSAI_EMBEDDING_MODEL", "text-embedding-3-small"
            )
            self.csai_offline = os.getenv("CSAI_OFFLINE", "false").lower() == "true"
            self.csai_temperature = float(os.getenv("CSAI_TEMPERATURE", "0.1"))
            self.csai_index_dir = os.getenv("CSAI_INDEX_DIR", ".cache/faiss_index")
            self.csai_log_level = os.getenv("CSAI_LOG_LEVEL", "INFO")

        @property
        def has_openai(self) -> bool:
            return bool(self.openai_api_key) and not self.csai_offline

        @property
        def has_tavily(self) -> bool:
            return bool(self.tavily_api_key) and not self.csai_offline

        @property
        def has_servicenow(self) -> bool:
            return (
                bool(self.snow_instance_url)
                and bool(self.snow_username)
                and bool(self.snow_password)
                and not self.csai_offline
            )

        @property
        def offline(self) -> bool:
            return self.csai_offline or not bool(self.openai_api_key)

        @property
        def index_path(self) -> Path:
            p = PROJECT_ROOT / self.csai_index_dir
            p.mkdir(parents=True, exist_ok=True)
            return p

        @property
        def data_dir(self) -> Path:
            return DATA_DIR

        def summary(self) -> dict:
            return {
                "llm_model": self.csai_llm_model,
                "embedding_model": self.csai_embedding_model,
                "openai_configured": bool(self.openai_api_key),
                "tavily_configured": bool(self.tavily_api_key),
                "servicenow_configured": bool(self.snow_instance_url),
                "offline_mode": self.offline,
                "temperature": self.csai_temperature,
            }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached, process-wide :class:`Settings` instance."""
    return Settings()
