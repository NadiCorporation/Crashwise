# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Phase 11 API enhancements (AI fields, workers, export)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from crashwise.api.main import app
from crashwise.core.database import (
    Campaign,
    Crash,
    FuzzingRun,
    close_db,
    get_session,
    init_db,
)


@pytest.fixture(autouse=True)
async def _fresh_db() -> None:
    """Drop and recreate tables before every test."""
    await init_db(drop=True)
    yield
    await close_db()


@pytest.fixture
async def client() -> AsyncClient:
    """Async HTTPX client for FastAPI."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


# ── AI fields in crash responses ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_crashes_includes_ai_fields(client: AsyncClient) -> None:
    """GET /campaigns/{id}/crashes returns Phase 10 AI fields."""
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()

        run = FuzzingRun(
            campaign_id=campaign.id,
            iteration=0,
            status="completed",
        )
        session.add(run)
        await session.commit()

        session.add(
            Crash(
                run_id=run.id,
                crash_type="heap-buffer-overflow",
                severity="critical",
                severity_score=9,
                vulnerability_type="cwe-122",
                suggested_patch="+ if (len > 0) { buf = malloc(len); }",
                stack_hash="deadbeef",
                signal="SIGSEGV",
            )
        )
        await session.commit()
        cid = str(campaign.id)

    response = await client.get(f"/campaigns/{cid}/crashes")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1

    crash = data[0]
    assert crash["crash_type"] == "heap-buffer-overflow"
    assert crash["severity"] == "critical"
    assert crash["severity_score"] == 9
    assert crash["vulnerability_type"] == "cwe-122"
    assert "malloc" in crash["suggested_patch"]


@pytest.mark.asyncio
async def test_list_crashes_cwe_filter(client: AsyncClient) -> None:
    """CWE filter returns only matching crashes."""
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()

        run = FuzzingRun(campaign_id=campaign.id, iteration=0, status="completed")
        session.add(run)
        await session.commit()

        session.add(
            Crash(
                run_id=run.id,
                crash_type="uaf",
                severity="critical",
                severity_score=9,
                vulnerability_type="cwe-416",
                stack_hash="aaa",
            )
        )
        session.add(
            Crash(
                run_id=run.id,
                crash_type="heap-overflow",
                severity="high",
                severity_score=7,
                vulnerability_type="cwe-122",
                stack_hash="bbb",
            )
        )
        await session.commit()
        cid = str(campaign.id)

    response = await client.get(
        f"/campaigns/{cid}/crashes",
        params={"vulnerability_type": "cwe-416"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["vulnerability_type"] == "cwe-416"


@pytest.mark.asyncio
async def test_list_crashes_severity_filter(client: AsyncClient) -> None:
    """min_severity_score filter returns only high-severity crashes."""
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()

        run = FuzzingRun(campaign_id=campaign.id, iteration=0, status="completed")
        session.add(run)
        await session.commit()

        session.add(
            Crash(
                run_id=run.id,
                crash_type="uaf",
                severity="critical",
                severity_score=9,
                vulnerability_type="cwe-416",
                stack_hash="aaa",
            )
        )
        session.add(
            Crash(
                run_id=run.id,
                crash_type="null-deref",
                severity="low",
                severity_score=2,
                vulnerability_type="cwe-476",
                stack_hash="bbb",
            )
        )
        await session.commit()
        cid = str(campaign.id)

    response = await client.get(
        f"/campaigns/{cid}/crashes",
        params={"min_severity_score": 5},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["severity_score"] == 9


# ── Workers endpoint ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_workers_empty_when_redis_disabled(client: AsyncClient) -> None:
    """GET /workers returns empty list when Redis is not enabled."""
    response = await client.get("/workers")
    assert response.status_code == 200
    data = response.json()
    assert data == []


@pytest.mark.asyncio
async def test_list_workers_with_redis(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """GET /workers returns active workers from Redis."""
    from crashwise.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    from crashwise.core import redis as redis_mod

    redis_mod._pool = None

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.keys = AsyncMock(return_value=[b"crashwise:worker:worker-1"])

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        response = await client.get("/workers")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["name"] == "worker-1"
    assert data[0]["status"] == "online"


# ── Export endpoint ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_export_markdown(client: AsyncClient) -> None:
    """GET /campaigns/{id}/export returns Markdown report."""
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()

        run = FuzzingRun(campaign_id=campaign.id, iteration=0, status="completed")
        session.add(run)
        await session.commit()

        session.add(
            Crash(
                run_id=run.id,
                crash_type="heap-buffer-overflow",
                severity="critical",
                severity_score=9,
                vulnerability_type="cwe-122",
                suggested_patch="+ if (len > 0) { buf = malloc(len); }",
                stack_hash="deadbeef",
                signal="SIGSEGV",
                stack_trace="main\nfoo\nbar",
            )
        )
        await session.commit()
        cid = str(campaign.id)

    response = await client.get(f"/campaigns/{cid}/export?fmt=markdown")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/markdown; charset=utf-8"
    body = response.text
    assert "# CrashWise Campaign Report" in body
    assert "heap-buffer-overflow" in body
    assert "cwe-122" in body
    assert "malloc" in body
    assert "deadbeef" in body


@pytest.mark.asyncio
async def test_export_json(client: AsyncClient) -> None:
    """GET /campaigns/{id}/export returns JSON report."""
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()
        cid = str(campaign.id)

    response = await client.get(f"/campaigns/{cid}/export?fmt=json")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    data = response.json()
    assert data["campaign"]["id"] == cid
    assert "crashes" in data


@pytest.mark.asyncio
async def test_export_not_found(client: AsyncClient) -> None:
    """Export for non-existent campaign returns 404."""
    response = await client.get(f"/campaigns/{uuid4()}/export")
    assert response.status_code == 404
