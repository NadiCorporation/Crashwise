# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unified LLM provider factory — single source of truth.

Every component in CrashWise that needs an LLM client (LangGraph agents,
openhands-sdk runtime, crash triage) MUST obtain it through this module.
This guarantees that a single configuration change (model name, API key,
temperature, base URL) propagates atomically to:

* The LangChain ``ChatAnthropic`` / ``ChatOpenAI`` instance used by
  LangGraph nodes (harness synthesis, healing engine, coverage analysis).
* The ``openhands-sdk`` runtime's internal LLM layer (which drives the
  TerminalTool and FileEditorTool execution brains).

Usage::

    from crashwise.core.llm_factory import get_llm_provider

    provider = get_llm_provider()
    chat_model = provider.chat_model          # LangChain ChatModel
    oh_config  = provider.openhands_llm_config  # dict for openhands-sdk
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from crashwise.core.config import Settings, get_settings
from crashwise.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class LLMProviderConfig:
    """Resolved, immutable snapshot of the platform's LLM configuration.

    Attributes
    ----------
    provider:
        Detected backend: ``"anthropic"``, ``"openai"``, ``"openai_custom"``,
        or ``"openai_compatible"``.
    model:
        Model identifier exactly as configured (e.g. ``claude-sonnet-4-5``).
    temperature:
        Sampling temperature.
    api_key:
        Resolved secret (plain string). ``None`` when no key is configured.
    base_url:
        Custom OpenAI-compatible endpoint. ``None`` for native providers.
    max_tokens:
        Token budget per completion.
    timeout_seconds:
        Per-request wall-clock cap.
    max_retries:
        Provider-level retry cap (distinct from LangGraph/Temporal retries).
    """

    provider: str
    model: str
    temperature: float
    api_key: str | None
    base_url: str | None
    max_tokens: int = 4096
    timeout_seconds: int = 180
    max_retries: int = 2

    # ── Derived accessors ────────────────────────────────────────────────
    @property
    def chat_model(self) -> Any:
        """Lazily construct and return the LangChain chat model.

        The instance is NOT cached on the dataclass (frozen + slots
        prevents mutation). Callers that need to reuse the same instance
        across turns should hold a local reference.
        """
        if self.provider == "anthropic":
            return self._build_anthropic()
        return self._build_openai()

    @property
    def openhands_llm_config(self) -> dict[str, Any]:
        """Return a config dict consumable by ``openhands-sdk``'s LLM layer.

        The openhands-sdk ``LLM`` class (and the higher-level
        ``TerminalTool.create`` / ``FileEditorTool.create``) accept an
        ``llm_config`` keyword with the following shape::

            {
                "model": "anthropic/claude-sonnet-4-5",
                "api_key": "sk-ant-...",
                "base_url": None,
                "temperature": 0.0,
                "max_tokens": 4096,
                "timeout": 180,
            }

        The ``model`` field uses the litellm provider-prefix convention
        (``anthropic/``, ``openai/``, or bare for custom endpoints).
        """
        model_str = self._litellm_model_string()
        cfg: dict[str, Any] = {
            "model": model_str,
            "api_key": self.api_key,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout_seconds,
        }
        if self.base_url:
            cfg["base_url"] = self.base_url
        return cfg

    # ── Private builders ─────────────────────────────────────────────────
    def _build_anthropic(self) -> Any:
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=self.model,
            temperature=self.temperature,
            api_key=self.api_key,
            timeout=self.timeout_seconds,
            max_retries=self.max_retries,
            stop=None,
            max_tokens=self.max_tokens,
        )

    def _build_openai(self) -> Any:
        from langchain_openai import ChatOpenAI

        kwargs: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "api_key": self.api_key,
            "timeout": self.timeout_seconds,
            "max_retries": self.max_retries,
        }
        if self.base_url:
            kwargs["base_url"] = self.base_url
        if self.model.startswith(("gpt-4o", "gpt-4-turbo")):
            kwargs["max_tokens"] = self.max_tokens
        return ChatOpenAI(**kwargs)

    def _litellm_model_string(self) -> str:
        """Prefix the model name for litellm/openhands routing."""
        if self.provider == "anthropic":
            return f"anthropic/{self.model}"
        if self.provider == "openai":
            return f"openai/{self.model}"
        # Custom endpoints: bare model name (litellm routes via base_url).
        return self.model


# ── Public API ──────────────────────────────────────────────────────────────

_OVERRIDE: LLMProviderConfig | None = None


def set_llm_provider_override(config: LLMProviderConfig | None) -> None:
    """Install (or clear) a test override. Affects all subsequent calls."""
    global _OVERRIDE
    _OVERRIDE = config


def get_llm_provider(*, settings: Settings | None = None) -> LLMProviderConfig:
    """Resolve the platform's LLM configuration into a frozen snapshot.

    This is the **single entry point** every CrashWise subsystem uses.
    The returned :class:`LLMProviderConfig` carries both the LangChain
    chat model (via ``.chat_model``) and the openhands-sdk config dict
    (via ``.openhands_llm_config``).

    Parameters
    ----------
    settings:
        Optional override for the global :func:`get_settings` singleton.
        Used by tests that want to inject a custom ``Settings`` without
        polluting the process-wide LRU cache.
    """
    if _OVERRIDE is not None:
        return _OVERRIDE

    s = settings or get_settings()
    model = s.crashwise_llm_model
    temperature = s.crashwise_llm_temperature
    provider = _detect_provider(model, s)

    api_key: str | None = None
    if provider == "anthropic" and s.anthropic_api_key:
        api_key = s.anthropic_api_key.get_secret_value()
    elif s.openai_api_key:
        api_key = s.openai_api_key.get_secret_value()

    base_url: str | None = s.openai_api_base if provider != "anthropic" else None

    config = LLMProviderConfig(
        provider=provider,
        model=model,
        temperature=temperature,
        api_key=api_key,
        base_url=base_url,
    )

    log.info(
        "llm_factory.resolved",
        provider=provider,
        model=model,
        temperature=temperature,
        base_url=base_url or "(native)",
        has_api_key=api_key is not None,
    )

    return config


def _detect_provider(model_name: str, settings: Settings) -> str:
    """Detect which provider to use based on model name and config."""
    lower = model_name.lower()
    if lower.startswith("claude"):
        return "anthropic"
    if lower.startswith(("gpt-", "o1-", "o3-")):
        return "openai_custom" if settings.openai_api_base else "openai"
    if settings.openai_api_base:
        return "openai_compatible"
    return "openai"


__all__ = [
    "LLMProviderConfig",
    "get_llm_provider",
    "set_llm_provider_override",
]
