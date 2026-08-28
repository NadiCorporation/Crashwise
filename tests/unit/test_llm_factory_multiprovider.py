# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Tests for the universal multi-provider LLM factory."""

from crashwise.core.config import Settings
from crashwise.core.llm_factory import _detect_provider, get_llm_provider


def test_detect_provider():
    # Anthropic models
    s = Settings()
    assert _detect_provider("claude-sonnet-4-5", None, s) == "anthropic"
    assert _detect_provider("claude-3-5-sonnet", None, s) == "anthropic"

    # OpenAI-compatible custom base URL
    assert _detect_provider("deepseek-chat", "https://api.deepseek.com", s) == "openai_compatible"
    assert _detect_provider("llama3.1:8b", "http://localhost:11434/v1", s) == "openai_compatible"
    assert _detect_provider("deepseek-chat", None, s) == "openai_compatible"

    # OpenAI native
    assert _detect_provider("gpt-4o", None, s) == "openai"


def test_get_llm_provider_overrides():
    provider = get_llm_provider(
        model="deepseek-chat",
        temperature=0.7,
        api_key="sk-test-deepseek",
        base_url="https://api.deepseek.com",
        max_tokens=2048,
        reasoning_effort="medium",
    )

    assert provider.model == "deepseek-chat"
    assert provider.temperature == 0.7
    assert provider.api_key == "sk-test-deepseek"
    assert provider.base_url == "https://api.deepseek.com"
    assert provider.max_tokens == 2048
    assert provider.reasoning_effort == "medium"
    assert provider.provider == "openai_compatible"

    # Verify openhands config derivation
    oh_cfg = provider.openhands_llm_config
    assert oh_cfg["model"] == "deepseek-chat"
    assert oh_cfg["base_url"] == "https://api.deepseek.com"
    assert oh_cfg["api_key"] == "sk-test-deepseek"
    assert oh_cfg["temperature"] == 0.7
