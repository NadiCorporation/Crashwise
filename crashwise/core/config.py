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

from pydantic import Field, SecretStr
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

    # ── Runtime ──────────────────────────────────────────────────────────────
    crashwise_env: str = Field(default="development", description="deployment environment label")
    log_level: str = Field(default="INFO", description="root log level")

    # ── Temporal ─────────────────────────────────────────────────────────────
    temporal_host: str = Field(default="localhost:7233")
    temporal_namespace: str = Field(default="default")
    temporal_task_queue: str = Field(default="crashwise-default")

    # ── LLM providers ────────────────────────────────────────────────────────
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    google_api_key: SecretStr | None = None

    crashwise_llm_model: str = Field(default="claude-sonnet-4-5")
    crashwise_llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)

    # ── Filesystem layout ────────────────────────────────────────────────────
    crashwise_harness_dir: Path = Field(default=Path("./harnesses"))
    crashwise_corpus_dir: Path = Field(default=Path("./corpus"))
    crashwise_crash_dir: Path = Field(default=Path("./crashes"))

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
        description="Inference backend: 'ollama', 'venice', or None",
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
