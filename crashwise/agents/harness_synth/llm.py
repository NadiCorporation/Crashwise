# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""LLM client factory for the harness-synthesis agent.

Resolves a chat model based on the ``CRASHWISE_LLM_MODEL`` setting.
Supports Anthropic (``claude-*``) and OpenAI (``gpt-*``) out of the box.
The factory is also a hook point for tests, which can override the chat
model via :func:`set_chat_model_override`.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from langchain_core.messages import AIMessage

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger

log = get_logger(__name__)


@runtime_checkable
class ChatModelLike(Protocol):
    """Subset of the LangChain chat-model API the agent actually uses.

    The signature is permissive (``*args, **kwargs``) so any real
    LangChain ``BaseChatModel`` and any narrow test stub both satisfy it.
    """

    async def ainvoke(self, *args: Any, **kwargs: Any) -> AIMessage:  # pragma: no cover
        ...


_OVERRIDE: ChatModelLike | None = None


def set_chat_model_override(model: ChatModelLike | None) -> None:
    """Install (or clear) a stub chat model. Used by tests."""
    global _OVERRIDE
    _OVERRIDE = model


def get_chat_model() -> ChatModelLike:
    """Return the configured chat model.

    Resolution order:
        1. :func:`set_chat_model_override` value (tests).
        2. Anthropic if model name starts with ``claude``.
        3. OpenAI otherwise.

    The provider's API key MUST be set in ``.env`` (or env vars) for live
    usage. We do not crash here on missing keys — the LLM call itself will
    surface a clear error, which the agent's retry loop catches.
    """
    if _OVERRIDE is not None:
        return _OVERRIDE

    settings = get_settings()
    model_name = settings.crashwise_llm_model
    temperature = settings.crashwise_llm_temperature

    log.info(
        "harness_synth.llm.resolve",
        model=model_name,
        temperature=temperature,
    )

    if model_name.lower().startswith("claude"):
        from langchain_anthropic import ChatAnthropic

        anthropic_key = (
            settings.anthropic_api_key.get_secret_value() if settings.anthropic_api_key else None
        )
        return ChatAnthropic(
            model=model_name,
            temperature=temperature,
            api_key=anthropic_key,
            timeout=120,
            stop=None,
        )

    from langchain_openai import ChatOpenAI

    openai_key = settings.openai_api_key.get_secret_value() if settings.openai_api_key else None
    kwargs: dict[str, Any] = {
        "model": model_name,
        "temperature": temperature,
        "api_key": openai_key,
        "timeout": 120,
    }
    if settings.openai_api_base:
        kwargs["base_url"] = settings.openai_api_base
    return ChatOpenAI(**kwargs)


__all__ = ["ChatModelLike", "get_chat_model", "set_chat_model_override"]
