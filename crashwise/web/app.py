# SPDX-License-Identifier: MIT
"""Web Control Plane — FastAPI backend with SSE telemetry.

Operation Hydra Phase 5: Real-time campaign control and crash browsing.

Endpoints:
    POST /api/v1/campaigns/start  — Launch a new fuzzing campaign
    GET  /api/v1/campaigns        — List all campaigns
    GET  /api/v1/crashes           — Deduplicated crash groups
    GET  /api/v1/telemetry/stream  — SSE real-time stats
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger
from crashwise.web.models import Base, CrashTestCase, FuzzingCampaign

log = get_logger(__name__)

app = FastAPI(title="CrashWise Control Plane", version="0.2.0-dev")

_engine = None
_session_factory: async_sessionmaker | None = None


# ── Lifecycle ────────────────────────────────────────────────────────────────

async def _startup() -> None:
    global _engine, _session_factory
    settings = get_settings()
    _engine = create_async_engine(settings.database_url, echo=False)
    _session_factory = async_sessionmaker(bind=_engine, class_=AsyncSession, expire_on_commit=False)
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("web.startup", database=settings.database_url)


async def _shutdown() -> None:
    if _engine:
        await _engine.dispose()


def _get_session() -> AsyncSession:
    if _session_factory is None:
        raise RuntimeError("Web DB not initialized. Call _startup() first.")
    return _session_factory()


# ── Request/Response Models ──────────────────────────────────────────────────

class CampaignStartRequest(BaseModel):
    target_name: str
    target_repo: str
    engine: str = "libfuzzer"
    timeout_seconds: int = 300


class CampaignResponse(BaseModel):
    id: str
    target_name: str
    engine: str
    status: str
    total_executions: int
    edges_covered: int
    crash_count: int
    started_at: str


class CrashResponse(BaseModel):
    id: str
    campaign_id: str
    crash_type: str
    crash_state: str
    severity: str
    status: str
    found_at: str


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.post("/campaigns/start", response_model=CampaignResponse)
async def start_campaign(req: CampaignStartRequest):
    """Launch a new fuzzing campaign."""
    async with _get_session() as session:
        campaign = FuzzingCampaign(
            target_name=req.target_name,
            target_repo=req.target_repo,
            engine=req.engine,
            status="running",
        )
        session.add(campaign)
        await session.commit()
        await session.refresh(campaign)

        log.info("web.campaign_started", id=str(campaign.id), target=req.target_name)

        return CampaignResponse(
            id=str(campaign.id),
            target_name=campaign.target_name,
            engine=campaign.engine,
            status=campaign.status,
            total_executions=0,
            edges_covered=0,
            crash_count=0,
            started_at=campaign.started_at.isoformat(),
        )


@app.get("/campaigns", response_model=list[CampaignResponse])
async def list_campaigns():
    """List all campaigns ordered by most recent."""
    async with _get_session() as session:
        result = await session.execute(
            select(FuzzingCampaign).order_by(FuzzingCampaign.started_at.desc()).limit(100)
        )
        campaigns = result.scalars().all()
        return [
            CampaignResponse(
                id=str(c.id),
                target_name=c.target_name,
                engine=c.engine,
                status=c.status,
                total_executions=c.total_executions or 0,
                edges_covered=c.edges_covered or 0,
                crash_count=c.crash_count or 0,
                started_at=c.started_at.isoformat(),
            )
            for c in campaigns
        ]


@app.get("/crashes", response_model=list[CrashResponse])
async def list_crashes(campaign_id: str | None = None):
    """Return deduplicated crash groups sorted by severity and recency."""
    async with _get_session() as session:
        query = select(CrashTestCase).order_by(CrashTestCase.found_at.desc()).limit(200)
        if campaign_id:
            query = query.where(CrashTestCase.campaign_id == UUID(campaign_id))
        result = await session.execute(query)
        crashes = result.scalars().all()

        # Severity ordering.
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        crashes_sorted = sorted(crashes, key=lambda c: severity_order.get(c.severity, 4))

        return [
            CrashResponse(
                id=str(c.id),
                campaign_id=str(c.campaign_id),
                crash_type=c.crash_type,
                crash_state=c.crash_state,
                severity=c.severity,
                status=c.status,
                found_at=c.found_at.isoformat(),
            )
            for c in crashes_sorted
        ]


# ── SSE Telemetry Stream ─────────────────────────────────────────────────────


@app.get("/telemetry/stream")
async def telemetry_stream():
    """Server-Sent Events stream of real-time fuzzing statistics."""
    from sqlalchemy import func

    from crashwise.core.database import Campaign, Crash, FuzzingRun, get_session

    async def _compute_telemetry() -> dict[str, Any]:
        try:
            async with get_session() as session:
                # Total executions and max edges across all runs
                row = (await session.execute(
                    select(
                        func.coalesce(func.sum(FuzzingRun.executions), 0),
                        func.coalesce(func.max(FuzzingRun.coverage_edges), 0),
                    )
                )).one()
                total_execs = int(row[0])
                unique_edges = int(row[1])

                # Active campaigns
                active = (await session.execute(
                    select(func.count()).where(Campaign.status == "running")
                )).scalar() or 0

                # Crashes
                crash_count = (await session.execute(
                    select(func.count()).select_from(Crash)
                )).scalar() or 0

                # Exec/s: Only non-zero when campaigns are actively running
                execs_per_sec = 0
                if active > 0:
                    recent = (await session.execute(
                        select(
                            func.coalesce(func.sum(FuzzingRun.executions), 0),
                            func.coalesce(func.sum(FuzzingRun.duration_seconds), 0),
                        ).where(FuzzingRun.duration_seconds > 0)
                    )).one()
                    execs_per_sec = int(int(recent[0]) / float(recent[1])) if recent[1] and float(recent[1]) > 0 else 0

                return {
                    "global_execs_per_sec": execs_per_sec,
                    "total_executions": total_execs,
                    "unique_edges": unique_edges,
                    "crashes_found": crash_count,
                    "active_campaigns": active,
                    "timestamp": datetime.utcnow().isoformat(),
                }
        except Exception:
            return {
                "global_execs_per_sec": 0,
                "total_executions": 0,
                "unique_edges": 0,
                "crashes_found": 0,
                "active_campaigns": 0,
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _generate():
        while True:
            data = await _compute_telemetry()
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(2.0)

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
