# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the Management API (Phase 8)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

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


# ── Health ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ── Campaigns list ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_campaigns_empty(client: AsyncClient) -> None:
    response = await client.get("/campaigns")
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_list_campaigns_with_data(client: AsyncClient) -> None:
    async with get_session() as session:
        session.add(
            Campaign(
                target_repo="https://github.com/example/target",
                target_name="target",
                fuzzer_type="libfuzzer",
                status="completed",
            )
        )
        await session.commit()

    response = await client.get("/campaigns")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["target_name"] == "target"
    assert data[0]["status"] == "completed"
    assert data[0]["run_count"] == 0
    assert data[0]["seed_count"] == 0


# ── Campaign detail ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_campaign_found(client: AsyncClient) -> None:
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
            status="running",
        )
        session.add(campaign)
        await session.commit()
        cid = str(campaign.id)

    response = await client.get(f"/campaigns/{cid}")
    assert response.status_code == 200
    data = response.json()
    assert data["target_name"] == "target"
    assert data["status"] == "running"
    assert "runs" in data
    assert "seeds" in data


@pytest.mark.asyncio
async def test_get_campaign_not_found(client: AsyncClient) -> None:
    from uuid import uuid4

    response = await client.get(f"/campaigns/{uuid4()}")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


# ── Campaign crashes ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_crashes_for_campaign(client: AsyncClient) -> None:
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
                severity="high",
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
    assert data[0]["crash_type"] == "heap-buffer-overflow"
    assert data[0]["severity"] == "high"
    assert data[0]["stack_hash"] == "deadbeef"


@pytest.mark.asyncio
async def test_list_crashes_empty(client: AsyncClient) -> None:
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()
        cid = str(campaign.id)

    response = await client.get(f"/campaigns/{cid}/crashes")
    assert response.status_code == 200
    assert response.json() == []


# ── Start campaign ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_start_campaign_success(client: AsyncClient) -> None:
    """POST /campaigns/start creates a campaign and triggers a workflow."""
    mock_handle = MagicMock()
    mock_client = AsyncMock()
    mock_client.start_workflow.return_value = mock_handle

    with patch(
        "crashwise.api.main.connect",
        return_value=mock_client,
    ):
        payload = {
            "target_repo": "https://github.com/openssl/openssl",
            "target_name": "openssl",
            "fuzzer_type": "libfuzzer",
            "timeout_seconds": 60,
            "max_iterations": 1,
        }
        response = await client.post("/campaigns/start", json=payload)

    assert response.status_code == 202
    data = response.json()
    assert "campaign_id" in data
    assert "workflow_id" in data
    assert data["message"] == "Campaign started successfully"

    # Verify campaign was persisted.
    async with get_session() as session:
        campaign_id = UUID(data["campaign_id"])
        from crashwise.core.database import get_campaign_by_id

        campaign = await get_campaign_by_id(session, campaign_id)
        assert campaign is not None
        assert campaign.target_name == "openssl"
        assert campaign.status == "pending"

    # Verify workflow was started with campaign_id.
    mock_client.start_workflow.assert_called_once()
    call_args = mock_client.start_workflow.call_args
    fuzzing_input = call_args.args[1]
    assert fuzzing_input.campaign_id == str(campaign_id)
