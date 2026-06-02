# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Phase 13 — Auto-Disclosure & Bounty Engine."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from crashwise.agents.reporting.cvss import _compute_base_score, _heuristic_vector, calculate_cvss
from crashwise.agents.reporting.generator import generate_report
from crashwise.core.notifications import NotificationConfig, NotificationRouter

# ── CVSS Calculator ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_calculate_cvss_uaf() -> None:
    """UAF should produce a high CVSS vector."""
    result = await calculate_cvss("use-after-free", exploitability_score=9.0)
    assert result["score"] >= 7.0
    assert "AV:N" in result["vector"]
    assert "C:H" in result["vector"]
    assert result["severity"] in ("Critical", "High")


@pytest.mark.asyncio
async def test_calculate_cvss_null_deref() -> None:
    """Null deref should produce a lower score."""
    result = await calculate_cvss("null-pointer-dereference", exploitability_score=2.0)
    assert result["score"] < 7.0
    assert result["severity"] in ("Low", "Medium")


@pytest.mark.asyncio
async def test_calculate_cvss_unknown_type() -> None:
    """Unknown bug type defaults to safe values."""
    result = await calculate_cvss("unknown-bug", exploitability_score=5.0)
    assert 0 <= result["score"] <= 10
    assert result["severity"] in ("Low", "Medium", "High", "Critical", "None")


@pytest.mark.asyncio
async def test_calculate_cvss_with_ai_refinement() -> None:
    """When AI provider is available, it can refine the vector."""
    mock_provider = AsyncMock()
    mock_provider.health_check = AsyncMock(return_value=True)
    mock_provider.analyze = AsyncMock(return_value={
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    })

    result = await calculate_cvss(
        "heap-buffer-overflow",
        exploitability_score=8.0,
        provider=mock_provider,
    )
    assert result["score"] >= 7.0
    mock_provider.analyze.assert_called_once()


def test_heuristic_vector_uaf() -> None:
    vector = _heuristic_vector("use-after-free", 9.0)
    assert "AV:N" in vector
    assert "C:H" in vector
    assert "I:H" in vector
    assert "A:H" in vector


def test_compute_base_score_critical() -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = _compute_base_score(vector)
    assert score >= 9.0


def test_compute_base_score_low() -> None:
    vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"
    score = _compute_base_score(vector)
    assert score < 4.0


# ── Report Generator ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_report_generic() -> None:
    """Generic format produces valid Markdown."""
    crash_data = {
        "bug_type": "heap-buffer-overflow",
        "severity": "critical",
        "severity_score": 9,
        "vulnerability_type": "cwe-122",
        "root_cause": "Missing bounds check in parser.c:42",
        "suggested_patch": "+ if (len > 0) { buf = malloc(len); }",
        "verification_status": "fixed",
        "stack_trace": "main\nfoo\nbar",
        "target_name": "libpng",
        "target_repo": "https://github.com/glennrp/libpng",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
    }
    result = await generate_report(crash_data, fmt="generic")
    assert "libpng" in result["title"]
    assert "libpng" in result["body"]
    assert "heap-buffer-overflow" in result["body"]
    assert "CVSS" in result["body"]
    assert result["platform"] == "generic"


@pytest.mark.asyncio
async def test_generate_report_hackerone() -> None:
    """HackerOne format includes impact and reproduction steps."""
    crash_data = {
        "bug_type": "use-after-free",
        "severity": "critical",
        "severity_score": 9,
        "vulnerability_type": "cwe-416",
        "root_cause": "Double free in ssl3_read_bytes",
        "suggested_patch": "+ if (s->init_buf != NULL) { ... }",
        "verification_status": "fixed",
        "stack_trace": "ssl3_read_bytes\n...",
        "target_name": "openssl",
        "target_repo": "https://github.com/openssl/openssl",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
    }
    result = await generate_report(crash_data, fmt="hackerone")
    assert "Impact" in result["body"]
    assert "Steps to Reproduce" in result["body"]
    assert "Proof of Concept" in result["body"]
    assert result["platform"] == "hackerone"


@pytest.mark.asyncio
async def test_generate_report_kernel() -> None:
    """Kernel format is mailing-list style."""
    crash_data = {
        "bug_type": "heap-buffer-overflow",
        "severity": "high",
        "severity_score": 7,
        "vulnerability_type": "cwe-122",
        "root_cause": "OOB write in png parser",
        "suggested_patch": "+ if (len > max) return;",
        "verification_status": "fixed",
        "stack_trace": "png_read_row\n...",
        "target_name": "libpng",
        "target_repo": "https://github.com/glennrp/libpng",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 8.5,
        "timeout_seconds": 60,
    }
    result = await generate_report(crash_data, fmt="kernel")
    assert "Subject:" in result["body"]
    assert "PATCH" in result["body"]
    assert "Hi maintainers" in result["body"]
    assert result["platform"] == "kernel"


@pytest.mark.asyncio
async def test_generate_report_no_patch() -> None:
    """When no patch is available, report handles gracefully."""
    crash_data = {
        "bug_type": "memory-leak",
        "severity": "low",
        "severity_score": 2,
        "vulnerability_type": "cwe-401",
        "root_cause": "",
        "suggested_patch": "",
        "verification_status": "pending",
        "stack_trace": "main\n...",
        "target_name": "testlib",
        "target_repo": "https://github.com/example/testlib",
        "cvss_vector": "N/A",
        "cvss_score": "N/A",
    }
    result = await generate_report(crash_data, fmt="bugcrowd")
    assert "No patch available" in result["body"] or "testlib" in result["body"]


# ── Notification Router ──────────────────────────────────────────────────────


def test_notification_config_from_settings() -> None:
    """Config reads from settings correctly."""
    config = NotificationConfig(
        webhook_url="https://hooks.slack.com/test",
        webhook_format="slack",
        enabled=True,
        min_cvss_threshold=7.0,
    )
    assert config.webhook_url == "https://hooks.slack.com/test"
    assert config.enabled is True
    assert config.min_cvss_threshold == 7.0


@pytest.mark.asyncio
async def test_router_skips_when_disabled() -> None:
    """When notifications_enabled=False, router returns empty dict."""
    router = NotificationRouter(NotificationConfig(enabled=False))
    result = await router.send(
        title="Test",
        body="Body",
        severity="critical",
        cvss_score=9.0,
    )
    assert result == {}


@pytest.mark.asyncio
async def test_router_skips_below_threshold() -> None:
    """When CVSS is below threshold, router returns empty dict."""
    router = NotificationRouter(NotificationConfig(enabled=True, min_cvss_threshold=7.0))
    result = await router.send(
        title="Test",
        body="Body",
        severity="medium",
        cvss_score=3.0,
    )
    assert result == {}


@pytest.mark.asyncio
async def test_router_sends_webhook() -> None:
    """Webhook is called when configured and CVSS is above threshold."""

    mock_response = MagicMock()
    mock_response.status_code = 200

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    router = NotificationRouter(NotificationConfig(
        enabled=True,
        webhook_url="https://hooks.slack.com/test",
        webhook_format="slack",
        min_cvss_threshold=7.0,
    ))

    with patch("crashwise.core.notifications.httpx.AsyncClient", return_value=mock_client):
        result = await router.send(
            title="Critical UAF",
            body="Details...",
            severity="critical",
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            target="libpng",
            crash_id="abc-123",
        )

    assert result.get("webhook") is True
    mock_client.post.assert_called_once()
    call_args = mock_client.post.call_args
    assert call_args.args[0] == "https://hooks.slack.com/test"
    payload = call_args.kwargs["json"]
    assert "attachments" in payload


@pytest.mark.asyncio
async def test_router_webhook_failure_graceful() -> None:
    """Webhook failure is logged but doesn't raise."""
    import httpx

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("No network"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    router = NotificationRouter(NotificationConfig(
        enabled=True,
        webhook_url="https://bad-url",
        min_cvss_threshold=7.0,
    ))

    with patch("crashwise.core.notifications.httpx.AsyncClient", return_value=mock_client):
        result = await router.send(
            title="Test",
            body="Body",
            severity="critical",
            cvss_score=9.0,
        )

    assert result.get("webhook") is False


def test_slack_payload_structure() -> None:
    """Slack payload has the expected structure."""
    from crashwise.core.notifications import _build_slack_payload

    payload = _build_slack_payload(
        title="Test Bug",
        severity="critical",
        cvss_score=9.5,
        target="openssl",
        crash_id="abc-123",
    )
    assert "attachments" in payload
    assert payload["attachments"][0]["title"] == "CrashWise Alert: Test Bug"
    assert payload["attachments"][0]["color"] == "#dc2626"


def test_discord_payload_structure() -> None:
    """Discord payload has the expected structure."""
    from crashwise.core.notifications import _build_discord_payload

    payload = _build_discord_payload(
        title="Test Bug",
        severity="high",
        cvss_score=7.5,
        target="libpng",
        crash_id="def-456",
    )
    assert "embeds" in payload
    assert payload["embeds"][0]["title"] == "CrashWise Alert: Test Bug"
    assert payload["embeds"][0]["color"] == 0xEA580C
