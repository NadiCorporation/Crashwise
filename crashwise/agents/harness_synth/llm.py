# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""LLM client factory for the harness-synthesis agent.

Operation Hydra — Frontier Upgrade: Resilient Router.

Supports:
- Anthropic: claude-3-5-sonnet, claude-sonnet-4-5, claude-* (via ANTHROPIC_API_KEY)
- OpenAI: gpt-4o, gpt-4o-mini, o1-*, gpt-* (via OPENAI_API_KEY)
- NVIDIA NIM: any model via OPENAI_API_BASE=https://integrate.api.nvidia.com/v1
- Custom OpenAI-compatible: vLLM, Together, Groq, Fireworks, Ollama (via OPENAI_API_BASE)

Rate-limit resilience is handled at the call site (nodes.py) via
exponential backoff. This module only constructs the client with
appropriate timeouts and retry configuration.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from langchain_core.messages import AIMessage

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger

log = get_logger(__name__)


@runtime_checkable
class ChatModelLike(Protocol):
    """Subset of the LangChain chat-model API the agent actually uses."""

    async def ainvoke(self, *args: Any, **kwargs: Any) -> AIMessage:
        ...


_OVERRIDE: ChatModelLike | None = None


def set_chat_model_override(model: ChatModelLike | None) -> None:
    """Install (or clear) a stub chat model. Used by tests."""
    global _OVERRIDE
    _OVERRIDE = model


def get_chat_model() -> ChatModelLike:
    """Return the configured chat model with provider-specific optimizations.

    Resolution order:
        1. Test override (set_chat_model_override).
        2. Anthropic if model starts with 'claude'.
        3. OpenAI/compatible for everything else.

    Provider detection:
        - 'claude-*' → Anthropic (needs ANTHROPIC_API_KEY)
        - 'gpt-*', 'o1-*' → OpenAI native (needs OPENAI_API_KEY)
        - Anything else + OPENAI_API_BASE set → OpenAI-compatible endpoint
        - Anything else without base → OpenAI (assumes custom model name)
    """
    if _OVERRIDE is not None:
        return _OVERRIDE

    settings = get_settings()
    model_name = settings.crashwise_llm_model
    temperature = settings.crashwise_llm_temperature

    provider = _detect_provider(model_name, settings)

    log.info(
        "harness_synth.llm.resolve",
        model=model_name,
        temperature=temperature,
        provider=provider,
    )

    if provider == "anthropic":
        return _build_anthropic(model_name, temperature, settings)
    else:
        return _build_openai(model_name, temperature, settings, provider)


def _detect_provider(model_name: str, settings: Any) -> str:
    """Detect which provider to use based on model name and config."""
    lower = model_name.lower()

    if lower.startswith("claude"):
        return "anthropic"

    if lower.startswith(("gpt-", "o1-", "o3-")):
        if settings.openai_api_base:
            return "openai_custom"
        return "openai"

    # Non-standard model name — must be a custom endpoint.
    if settings.openai_api_base:
        return "openai_compatible"

    # Fallback: try OpenAI native.
    return "openai"


def _build_anthropic(model_name: str, temperature: float, settings: Any) -> ChatModelLike:
    """Build Anthropic client with frontier-model settings."""
    from langchain_anthropic import ChatAnthropic

    api_key = (
        settings.anthropic_api_key.get_secret_value() if settings.anthropic_api_key else None
    )

    return ChatAnthropic(
        model=model_name,
        temperature=temperature,
        api_key=api_key,
        timeout=180,
        max_retries=2,
        stop=None,
        max_tokens=4096,
    )


def _build_openai(
    model_name: str, temperature: float, settings: Any, provider: str
) -> ChatModelLike:
    """Build OpenAI/compatible client with appropriate settings."""
    from langchain_openai import ChatOpenAI

    api_key = settings.openai_api_key.get_secret_value() if settings.openai_api_key else None

    kwargs: dict[str, Any] = {
        "model": model_name,
        "temperature": temperature,
        "api_key": api_key,
        "timeout": 180,
        "max_retries": 2,
    }

    # Custom base URL for NVIDIA NIM, Together, Groq, vLLM, etc.
    if settings.openai_api_base:
        kwargs["base_url"] = settings.openai_api_base

    # Frontier models support larger context.
    if model_name.startswith(("gpt-4o", "gpt-4-turbo")):
        kwargs["max_tokens"] = 4096

    return ChatOpenAI(**kwargs)


__all__ = ["ChatModelLike", "get_chat_model", "set_chat_model_override"]
