# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the Hybrid AI Root Cause & Exploitability Agent (Phase 10)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from crashwise.core.ai_provider import (
    OllamaProvider,
    VeniceProvider,
    _NullProvider,
    _safe_parse_json,
    get_provider,
)
from crashwise.core.config import get_settings

# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    """Clear settings cache so env changes take effect."""
    get_settings.cache_clear()


# ── Provider factory ─────────────────────────────────────────────────────────


def test_get_provider_null_when_unconfigured() -> None:
    """When AI_PROVIDER is not set, factory returns NullProvider."""
    provider = get_provider()
    assert isinstance(provider, _NullProvider)


def test_get_provider_ollama() -> None:
    """Factory returns OllamaProvider when AI_PROVIDER=ollama."""
    import os

    os.environ["AI_PROVIDER"] = "ollama"
    os.environ["AI_MODEL"] = "llama3.1:8b"
    get_settings.cache_clear()

    provider = get_provider()
    assert isinstance(provider, OllamaProvider)
    assert provider.model == "llama3.1:8b"

    del os.environ["AI_PROVIDER"]
    del os.environ["AI_MODEL"]


def test_get_provider_venice_no_key() -> None:
    """Factory returns NullProvider when Venice is chosen but no API key."""
    import os

    os.environ["AI_PROVIDER"] = "venice"
    os.environ["AI_MODEL"] = "llama-3.3-70b"
    get_settings.cache_clear()

    provider = get_provider()
    assert isinstance(provider, _NullProvider)

    del os.environ["AI_PROVIDER"]
    del os.environ["AI_MODEL"]


# ── Null provider ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_null_provider_analyze() -> None:
    provider = _NullProvider()
    result = await provider.analyze("some crash context")
    assert result["bug_type"] == "unknown"
    assert result["exploitability"] == 0.0
    assert "not configured" in result["root_cause"]


@pytest.mark.asyncio
async def test_null_provider_suggest_patch() -> None:
    provider = _NullProvider()
    result = await provider.suggest_patch("heap overflow in parser")
    assert result["patch"] == ""
    assert result["confidence"] == 0.0


# ── JSON parsing helper ──────────────────────────────────────────────────────


def test_safe_parse_json_valid() -> None:
    text = '{"bug_type": "use-after-free", "exploitability": 8.5}'
    result = _safe_parse_json(text)
    assert result["bug_type"] == "use-after-free"
    assert result["exploitability"] == 8.5


def test_safe_parse_json_with_markdown_fences() -> None:
    text = '```json\n{"bug_type": "heap-buffer-overflow"}\n```'
    result = _safe_parse_json(text)
    assert result["bug_type"] == "heap-buffer-overflow"


def test_safe_parse_json_invalid() -> None:
    text = "not json at all"
    result = _safe_parse_json(text)
    assert result == {}


# ── Patcher ──────────────────────────────────────────────────────────────────


# ── Ollama provider (mocked HTTP) ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_ollama_provider_analyze() -> None:
    """OllamaProvider sends correct payload and parses response."""
    provider = OllamaProvider(base_url="http://localhost:11434", model="test-model")

    mock_chat = AsyncMock(return_value={
        "bug_type": "heap-buffer-overflow",
        "exploitability": 7.5,
        "root_cause": "OOB write",
        "vulnerability_type": "cwe-122",
        "confidence": 0.9,
    })

    with patch.object(provider, "_chat", mock_chat):
        result = await provider.analyze("ASAN heap-buffer-overflow")

    assert result["bug_type"] == "heap-buffer-overflow"
    assert result["exploitability"] == 7.5
    assert result["vulnerability_type"] == "cwe-122"
    mock_chat.assert_called_once()


@pytest.mark.asyncio
async def test_ollama_provider_health_check() -> None:
    """Health check returns True when Ollama is reachable."""

    provider = OllamaProvider()

    mock_response = AsyncMock()
    mock_response.status_code = 200

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("crashwise.core.ai_provider.httpx.AsyncClient", return_value=mock_client):
        assert await provider.health_check() is True


# ── Venice provider (mocked HTTP) ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_venice_provider_analyze() -> None:
    """VeniceProvider sends correct payload and parses response."""
    provider = VeniceProvider(api_key="test-key", model="test-model")

    mock_chat = AsyncMock(return_value={
        "bug_type": "use-after-free",
        "exploitability": 9.0,
        "root_cause": "Double free leads to UAF",
        "vulnerability_type": "cwe-416",
        "confidence": 0.95,
    })

    with patch.object(provider, "_chat", mock_chat):
        result = await provider.analyze("double free in parser")

    assert result["bug_type"] == "use-after-free"
    assert result["exploitability"] == 9.0
    assert result["vulnerability_type"] == "cwe-416"
    mock_chat.assert_called_once()


@pytest.mark.asyncio
async def test_venice_provider_health_check() -> None:
    """Health check returns True when Venice API is reachable."""

    provider = VeniceProvider(api_key="test-key")

    mock_response = AsyncMock()
    mock_response.status_code = 200

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("crashwise.core.ai_provider.httpx.AsyncClient", return_value=mock_client):
        assert await provider.health_check() is True


# ── DB integration (analyze_crash activity) ──────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_crash_activity_null_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """When AI provider is not configured, analyze_crash returns gracefully."""
    from crashwise.orchestration.activities.analyze_crash import analyze_crash

    # Mock activity.info() to avoid Temporal runtime dependency.
    mock_info = MagicMock()
    mock_info.workflow_id = "test-workflow"
    mock_info.attempt = 1

    with patch("crashwise.orchestration.activities.analyze_crash.activity.info", return_value=mock_info):
        result = await analyze_crash(
            crash_id=str(uuid4()),
            crash_context="SIGSEGV at 0x0",
            campaign_id=str(uuid4()),
        )

    assert result["bug_type"] == "unknown"
    assert result["exploitability"] == 0.0
    assert "not configured" in result["root_cause"]


@pytest.mark.asyncio
async def test_analyze_crash_skips_patch_when_self_healing_enabled() -> None:
    """When skip_patch_generation=True, no patch is generated."""
    from crashwise.orchestration.activities.analyze_crash import analyze_crash

    mock_info = MagicMock()
    mock_info.workflow_id = "test-workflow"
    mock_info.attempt = 1

    mock_provider = AsyncMock()
    mock_provider.health_check.return_value = True
    mock_provider.analyze.return_value = {
        "bug_type": "heap-buffer-overflow",
        "exploitability": 8.0,
        "root_cause": "Out-of-bounds write in parser",
        "vulnerability_type": "cwe-122",
        "confidence": 0.9,
    }

    with (
        patch("crashwise.orchestration.activities.analyze_crash.activity.info", return_value=mock_info),
        patch("crashwise.orchestration.activities.analyze_crash.get_provider", return_value=mock_provider),
        patch("crashwise.orchestration.activities.analyze_crash._update_crash_record", new_callable=AsyncMock),
    ):
        result = await analyze_crash(
            crash_id=str(uuid4()),
            crash_context="ASAN: heap-buffer-overflow",
            campaign_id=str(uuid4()),
            skip_patch_generation=True,
        )

    assert result["patch"] == ""
    assert result["patch_confidence"] == 0.0
    # Provider.analyze should only be called once (for RCA, not for patch)
    assert mock_provider.analyze.call_count == 1


@pytest.mark.asyncio
async def test_analyze_crash_generates_patch_when_self_healing_disabled() -> None:
    """When skip_patch_generation=False, intelligent patch is generated."""
    from crashwise.orchestration.activities.analyze_crash import analyze_crash

    mock_info = MagicMock()
    mock_info.workflow_id = "test-workflow"
    mock_info.attempt = 1

    mock_provider = AsyncMock()
    mock_provider.health_check.return_value = True
    mock_provider.analyze.side_effect = [
        # First call: RCA
        {
            "bug_type": "use-after-free",
            "exploitability": 9.0,
            "root_cause": "Use-after-free in cleanup",
            "vulnerability_type": "cwe-416",
            "confidence": 0.95,
        },
        # Second call: patch generation
        {
            "patch": "--- a/parser.c\n+++ b/parser.c\n@@ -42,6 +42,7 @@\n+ if (ptr) free(ptr);",
            "explanation": "Add null check before free",
            "confidence": 0.85,
        },
    ]

    with (
        patch("crashwise.orchestration.activities.analyze_crash.activity.info", return_value=mock_info),
        patch("crashwise.orchestration.activities.analyze_crash.get_provider", return_value=mock_provider),
        patch("crashwise.orchestration.activities.analyze_crash._update_crash_record", new_callable=AsyncMock),
    ):
        result = await analyze_crash(
            crash_id=str(uuid4()),
            crash_context="ASAN: use-after-free",
            campaign_id=str(uuid4()),
            skip_patch_generation=False,
        )

    assert "if (ptr) free(ptr)" in result["patch"]
    assert result["patch_confidence"] == 0.85
    # Provider.analyze should be called twice (RCA + patch)
    assert mock_provider.analyze.call_count == 2
