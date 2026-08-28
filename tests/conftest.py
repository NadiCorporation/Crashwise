# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Pytest configuration for CrashWise tests.

Sets up a failing LLM override so tests don't hang trying to call real LLM APIs.
Individual tests can override this with their own mock if needed.
"""

from __future__ import annotations

import pytest

from crashwise.agents.harness_synth.llm import set_chat_model_override
from crashwise.core.config import get_settings


class FailingChatModel:
    """Chat model that always raises an exception to trigger fallback paths."""

    async def ainvoke(self, *args, **kwargs):
        raise RuntimeError("LLM not configured in tests")


@pytest.fixture(autouse=True)
def _isolate_test_environment(monkeypatch: pytest.MonkeyPatch):
    """Ensure tests run isolated from local .env settings and external services."""
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("REDIS_ENABLED", "false")
    monkeypatch.setenv("AI_PROVIDER", "")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("OPENAI_API_BASE", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def mock_llm_for_tests():
    """Automatically set a failing LLM override for all tests.

    This ensures tests don't hang trying to call real LLM APIs.
    Tests that need a working LLM mock should override this fixture
    or use set_chat_model_override directly.
    """
    set_chat_model_override(FailingChatModel())
    yield
    set_chat_model_override(None)
