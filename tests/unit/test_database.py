# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the persistence layer (Phase 8)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from crashwise.core.database import (
    Campaign,
    Crash,
    FuzzingRun,
    Seed,
    close_db,
    get_campaign_by_id,
    get_campaigns,
    get_crashes_for_campaign,
    get_session,
    init_db,
)


@pytest.fixture(autouse=True)
async def _fresh_db() -> None:
    """Drop and recreate tables before every test."""
    await init_db(drop=True)
    yield
    await close_db()


# ── Campaign CRUD ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_campaign() -> None:
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
            status="pending",
        )
        session.add(campaign)
        await session.commit()
        await session.refresh(campaign)
        assert campaign.id is not None
        assert campaign.target_name == "target"


@pytest.mark.asyncio
async def test_get_campaigns_ordered_by_date() -> None:
    async with get_session() as session:
        for i in range(3):
            session.add(
                Campaign(
                    target_repo=f"https://github.com/example/{i}",
                    target_name=f"target-{i}",
                    fuzzer_type="libfuzzer",
                )
            )
        await session.commit()

    async with get_session() as session:
        campaigns = await get_campaigns(session, limit=10)
        assert len(campaigns) == 3
        # Most recent first.
        assert campaigns[0].target_name == "target-2"


@pytest.mark.asyncio
async def test_get_campaign_by_id_found() -> None:
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()
        cid = campaign.id

    async with get_session() as session:
        found = await get_campaign_by_id(session, cid)
        assert found is not None
        assert found.target_name == "target"


@pytest.mark.asyncio
async def test_get_campaign_by_id_not_found() -> None:
    from uuid import uuid4

    async with get_session() as session:
        found = await get_campaign_by_id(session, uuid4())
        assert found is None


# ── FuzzingRun ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_run_linked_to_campaign() -> None:
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
            executions=1_000_000,
            duration_seconds=10.5,
            status="completed",
        )
        session.add(run)
        await session.commit()

    async with get_session() as session:
        result = await session.execute(select(FuzzingRun))
        runs = result.scalars().all()
        assert len(runs) == 1
        assert runs[0].executions == 1_000_000


# ── Seed ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_seed_linked_to_campaign() -> None:
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()

        seed = Seed(
            campaign_id=campaign.id,
            seed_id="CVE-2022-3602",
            source="cve",
            target_name="openssl",
            language="c",
            tags=["buffer-overflow", "critical"],
        )
        session.add(seed)
        await session.commit()

    async with get_session() as session:
        result = await session.execute(select(Seed))
        seeds = result.scalars().all()
        assert len(seeds) == 1
        assert seeds[0].seed_id == "CVE-2022-3602"
        assert "buffer-overflow" in seeds[0].tags


# ── Crash ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_crash_linked_to_run() -> None:
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

        crash = Crash(
            run_id=run.id,
            crash_type="heap-buffer-overflow",
            severity="high",
            stack_trace="main\nfoo\nbar",
            stack_hash="abc123",
            signal="SIGSEGV",
        )
        session.add(crash)
        await session.commit()

    async with get_session() as session:
        result = await session.execute(select(Crash))
        crashes = result.scalars().all()
        assert len(crashes) == 1
        assert crashes[0].severity == "high"


@pytest.mark.asyncio
async def test_get_crashes_for_campaign() -> None:
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

        for i in range(3):
            session.add(
                Crash(
                    run_id=run.id,
                    crash_type="heap-buffer-overflow",
                    severity="high",
                    stack_hash=f"hash-{i}",
                )
            )
        await session.commit()

    async with get_session() as session:
        crashes = await get_crashes_for_campaign(session, campaign.id)
        assert len(crashes) == 3
