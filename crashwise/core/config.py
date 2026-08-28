# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Strongly-typed runtime configuration loaded from environment variables.

Values are sourced (in precedence order) from:
    1. Process environment.
    2. A local ``.env`` file at the project root (development only).
    3. Hard-coded defaults declared on :class:`Settings`.

All modules MUST consume configuration via :func:`get_settings` rather than
reading ``os.environ`` directly. This keeps tests deterministic and gives us
a single audit point for secrets.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Top-level CrashWise runtime configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="",
        extra="ignore",
        case_sensitive=False,
    )

    @model_validator(mode="before")
    @classmethod
    def _map_env_aliases(cls, values: Any) -> Any:
        if isinstance(values, dict):
            # Model name aliases
            if "model_name" in values and "crashwise_llm_model" not in values:
                values["crashwise_llm_model"] = values["model_name"]
            elif "model" in values and "crashwise_llm_model" not in values:
                values["crashwise_llm_model"] = values["model"]

            # Temperature aliases
            if "temperature" in values and "crashwise_llm_temperature" not in values:
                values["crashwise_llm_temperature"] = values["temperature"]

            # Max tokens aliases
            if "max_tokens" in values and "crashwise_llm_max_tokens" not in values:
                values["crashwise_llm_max_tokens"] = values["max_tokens"]

            # Reasoning effort aliases
            if "reasoning_effort" in values and "crashwise_llm_reasoning_effort" not in values:
                values["crashwise_llm_reasoning_effort"] = values["reasoning_effort"]

            # Base URL aliases
            if "openai_base_url" in values and "openai_api_base" not in values:
                values["openai_api_base"] = values["openai_base_url"]
            elif "base_url" in values and "openai_api_base" not in values:
                values["openai_api_base"] = values["base_url"]

        return values

    # ── Runtime ──────────────────────────────────────────────────────────────
    crashwise_env: str = Field(default="development", description="deployment environment label")
    log_level: str = Field(default="INFO", description="root log level")

    # ── Temporal ─────────────────────────────────────────────────────────────
    temporal_host: str = Field(default="localhost:7233")
    temporal_namespace: str = Field(default="default")
    temporal_task_queue: str = Field(default="crashwise")

    # ── API & Control Plane ──────────────────────────────────────────────────
    crashwise_api_port: int = Field(default=8000)
    crashwise_api_url: str = Field(default="http://localhost:8000")

    # ── LLM providers ────────────────────────────────────────────────────────
    openai_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=None,
    )
    anthropic_api_key: SecretStr | None = None
    google_api_key: SecretStr | None = None

    crashwise_llm_model: str = Field(default="claude-sonnet-4-5")
    crashwise_llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    crashwise_llm_max_tokens: int = Field(default=4096, ge=256, le=131072)
    crashwise_llm_reasoning_effort: str | None = Field(
        default=None,
        description="Reasoning effort for reasoning models ('low', 'medium', 'high')",
    )
    openai_api_base: str | None = Field(
        default=None,
        description="Custom OpenAI-compatible base URL (e.g. https://api.deepseek.com or http://localhost:11434/v1)",
    )

    # ── Filesystem layout ────────────────────────────────────────────────────
    crashwise_harness_dir: Path = Field(default=Path("./harnesses"))
    crashwise_corpus_dir: Path = Field(default=Path("./corpus"))
    crashwise_crash_dir: Path = Field(default=Path("./crashes"))
    crashwise_workdir: Path = Field(
        default=Path("/tmp/crashwise"),
        description="Root working directory for cloning and building targets (CRASHWISE_WORKDIR)",
    )
    crashwise_build_timeout: int = Field(
        default=900,
        description="Target build timeout in seconds (CRASHWISE_BUILD_TIMEOUT)",
    )

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./crashwise.db",
        description="SQLAlchemy async database URL",
    )

    # ── Distributed storage (Cloudflare R2 / S3-compatible) ────────────────────
    r2_account_id: str | None = Field(default=None, description="Cloudflare R2 account ID")
    r2_access_key_id: str | None = Field(default=None)
    r2_secret_access_key: SecretStr | None = Field(default=None)
    r2_bucket: str = Field(default="crashwise", description="R2 bucket name")
    r2_endpoint_url: str | None = Field(
        default=None,
        description="Custom S3-compatible endpoint (e.g. https://<account>.r2.cloudflarestorage.com)",
    )
    r2_region: str = Field(default="auto", description="S3 region for R2")
    r2_enabled: bool = Field(default=False, description="Enable R2 distributed storage")

    # ── Docker execution limits ──────────────────────────────────────────────
    docker_disk_quota: str = Field(
        default="5G",
        description="Per-container storage quota (--storage-opt size=). Requires overlay2 + xfs with pquota.",
    )

    # ── Distributed state (Redis) ────────────────────────────────────────────
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )
    redis_enabled: bool = Field(default=False, description="Enable Redis for distributed state")

    # ── Worker identity ────────────────────────────────────────────────────────
    worker_name: str = Field(
        default="crashwise-worker-0",
        description="Unique identifier for this worker replica",
    )

    # ── AI inference provider ────────────────────────────────────────────────
    ai_provider: str | None = Field(
        default=None,
        description="Inference backend: 'ollama', 'venice', 'openai_compatible', or None",
    )
    ai_api_key: str | None = Field(
        default=None,
        description="API key for cloud providers (Venice, OpenAI, etc.)",
    )
    ai_model: str | None = Field(
        default=None,
        description="Model name (e.g., 'llama3.1:8b', 'llama-3.3-70b')",
    )
    ollama_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for local Ollama instance",
    )

    # ── Notifications ────────────────────────────────────────────────────────
    notifications_enabled: bool = Field(default=False)
    webhook_url: str | None = Field(default=None)
    webhook_format: str = Field(default="slack")
    smtp_host: str | None = Field(default=None)
    smtp_port: int = Field(default=587)
    smtp_user: str | None = Field(default=None)
    smtp_password: str | None = Field(default=None)
    smtp_from: str = Field(default="crashwise@localhost")
    smtp_to: str | None = Field(default=None)
    pgp_public_key: str | None = Field(default=None)
    min_cvss_threshold: float = Field(default=7.0, ge=0.0, le=10.0)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached, immutable :class:`Settings` instance."""
    return Settings()
