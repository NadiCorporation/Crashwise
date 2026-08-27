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


def get_chat_model(
    *,
    model: str | None = None,
    temperature: float | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    max_tokens: int | None = None,
    reasoning_effort: str | None = None,
) -> ChatModelLike:
    """Return the configured chat model via the unified LLM provider factory.

    Resolution order:
        1. Test override (set_chat_model_override).
        2. Dynamic parameters passed as keyword args.
        3. Platform-wide configuration resolved via get_llm_provider().
    """
    if _OVERRIDE is not None:
        return _OVERRIDE

    from crashwise.core.llm_factory import get_llm_provider

    provider_config = get_llm_provider(
        model=model,
        temperature=temperature,
        api_key=api_key,
        base_url=base_url,
        max_tokens=max_tokens,
        reasoning_effort=reasoning_effort,
    )
    return provider_config.chat_model


__all__ = ["ChatModelLike", "get_chat_model", "set_chat_model_override"]
