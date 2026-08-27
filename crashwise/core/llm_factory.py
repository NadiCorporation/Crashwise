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
        Model identifier exactly as configured (e.g. ``claude-sonnet-4-5``, ``deepseek-chat``).
    temperature:
        Sampling temperature.
    api_key:
        Resolved secret (plain string). ``None`` when no key is configured.
    base_url:
        Custom OpenAI-compatible endpoint. ``None`` for native providers.
    max_tokens:
        Token budget per completion.
    reasoning_effort:
        Optional reasoning effort level ('low', 'medium', 'high').
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
    reasoning_effort: str | None = None
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

        if not self.api_key:
            raise ValueError("No Anthropic API key configured (ANTHROPIC_API_KEY).")

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

        if not self.api_key and not self.base_url:
            raise ValueError("No OpenAI API key configured (OPENAI_API_KEY).")

        kwargs: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "api_key": self.api_key or "sk-dummy",
            "timeout": self.timeout_seconds,
            "max_retries": self.max_retries,
        }
        if self.base_url:
            kwargs["base_url"] = self.base_url.rstrip("/")
        if self.max_tokens:
            kwargs["max_tokens"] = self.max_tokens
        if self.reasoning_effort:
            kwargs["reasoning_effort"] = self.reasoning_effort

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


def get_llm_provider(
    *,
    model: str | None = None,
    temperature: float | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    max_tokens: int | None = None,
    reasoning_effort: str | None = None,
    timeout_seconds: int | None = None,
    settings: Settings | None = None,
) -> LLMProviderConfig:
    """Resolve the platform's LLM configuration into a frozen snapshot.

    This is the **single entry point** every CrashWise subsystem uses.
    The returned :class:`LLMProviderConfig` carries both the LangChain
    chat model (via ``.chat_model``) and the openhands-sdk config dict
    (via ``.openhands_llm_config``).

    Parameters
    ----------
    model:
        Optional model name override.
    temperature:
        Optional sampling temperature override.
    api_key:
        Optional API key override.
    base_url:
        Optional base URL override.
    max_tokens:
        Optional max completion tokens override.
    reasoning_effort:
        Optional reasoning effort level ('low', 'medium', 'high').
    timeout_seconds:
        Optional request timeout in seconds.
    settings:
        Optional override for the global :func:`get_settings` singleton.
        Used by tests that want to inject a custom ``Settings`` without
        polluting the process-wide LRU cache.
    """
    if _OVERRIDE is not None:
        return _OVERRIDE

    s = settings or get_settings()
    resolved_model = model or s.crashwise_llm_model
    resolved_temp = temperature if temperature is not None else s.crashwise_llm_temperature
    resolved_base_url = base_url if base_url is not None else s.openai_api_base
    provider = _detect_provider(resolved_model, resolved_base_url, s)

    resolved_api_key: str | None = api_key
    if resolved_api_key is None:
        if provider == "anthropic" and s.anthropic_api_key:
            resolved_api_key = s.anthropic_api_key.get_secret_value()
        elif s.openai_api_key:
            resolved_api_key = s.openai_api_key.get_secret_value()

    if provider == "anthropic":
        resolved_base_url = None

    resolved_max_tokens = max_tokens or getattr(s, "crashwise_llm_max_tokens", 4096)
    resolved_reasoning_effort = reasoning_effort or getattr(s, "crashwise_llm_reasoning_effort", None)
    resolved_timeout = timeout_seconds or 180

    config = LLMProviderConfig(
        provider=provider,
        model=resolved_model,
        temperature=resolved_temp,
        api_key=resolved_api_key,
        base_url=resolved_base_url,
        max_tokens=resolved_max_tokens,
        reasoning_effort=resolved_reasoning_effort,
        timeout_seconds=resolved_timeout,
    )

    log.info(
        "llm_factory.resolved",
        provider=provider,
        model=resolved_model,
        temperature=resolved_temp,
        base_url=resolved_base_url or "(native)",
        has_api_key=resolved_api_key is not None,
    )

    return config


def _detect_provider(model_name: str, base_url: str | None, settings: Settings) -> str:
    """Detect which provider to use based on model name, base URL, and config."""
    lower = model_name.lower()
    if lower.startswith("claude"):
        return "anthropic"
    if base_url or settings.openai_api_base:
        return "openai_compatible"
    if lower.startswith(("deepseek", "llama", "qwen", "mistral", "ollama", "vllm", "openrouter")):
        return "openai_compatible"
    if lower.startswith(("gpt-", "o1-", "o3-")):
        return "openai_custom" if settings.openai_api_base else "openai"
    return "openai"


__all__ = [
    "LLMProviderConfig",
    "get_llm_provider",
    "set_llm_provider_override",
]
