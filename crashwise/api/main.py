# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""CrashWise Management API — Web Command Center (Phase 8).

A FastAPI application that exposes REST endpoints for monitoring and
controlling fuzzing campaigns.  It bridges the Temporal orchestration
layer with the persistence layer.

Endpoints
---------
* ``GET /campaigns`` — List all campaigns.
* ``GET /campaigns/{id}`` — Get a single campaign with runs & seeds.
* ``GET /campaigns/{id}/crashes`` — List crashes for a campaign.
* ``POST /campaigns/start`` — Trigger a new fuzzing workflow.
* ``GET /health`` — Liveness / readiness probe.

Usage::

    uvicorn crashwise.api.main:app --reload
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from crashwise.core.config import get_settings
from crashwise.core.database import (
    Campaign,
    Crash,
    FuzzingRun,
    close_db,
    get_campaign_by_id,
    get_campaigns,
    get_crashes_for_campaign,
    get_session,
    init_db,
)
from crashwise.core.logging import configure_logging, get_logger
from crashwise.core.models import (
    FuzzerType,
    FuzzingInput,
    VerifyPatchInput,
)
from crashwise.core.redis import list_active_workers
from crashwise.orchestration.client import connect
from crashwise.web.app import app as web_app

log = get_logger(__name__)


# ── Pydantic request/response models ─────────────────────────────────────────

class CampaignCreateRequest(BaseModel):
    """Payload to start a new fuzzing campaign."""

    target_repo: str = Field(..., min_length=1, max_length=1024, description="Git URL or directory path of the target")
    target_name: str = Field(..., min_length=1, max_length=128)
    target_subdir: str | None = Field(default=None, max_length=512, description="Monorepo subdirectory path")
    target_clone_depth: int = Field(default=1, ge=0, description="Git clone depth (0 for full clone)")
    fuzzer_type: FuzzerType = Field(default=FuzzerType.LIBFUZZER)
    timeout_seconds: int = Field(default=600, ge=10, le=86_400)
    target_branch: str | None = Field(default=None, max_length=255)
    harness_path: str | None = Field(default=None, max_length=512)
    sanitizers: str = Field(default="address,undefined")
    max_iterations: int = Field(default=5, ge=1, le=20)
    custom_fuzzer_flags: str | None = Field(default=None, description="Custom AFL++ or libFuzzer flags")
    llm_model: str | None = Field(default=None, description="LLM model override")
    llm_temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    llm_base_url: str | None = Field(default=None, description="Custom OpenAI-compatible base URL")
    llm_api_key: str | None = Field(default=None, description="API key for LLM")
    reasoning_effort: str | None = Field(default=None, description="Reasoning effort ('low', 'medium', 'high')")
    max_synth_retries: int = Field(default=4, ge=0, le=10)
    enable_mab: bool = Field(default=False)
    mab_algorithm: str = Field(default="thompson")
    mab_exploration_ratio: float = Field(default=0.2, ge=0.0, le=1.0)
    enable_self_healing: bool = Field(default=False)
    healing_max_attempts: int = Field(default=10, ge=1, le=50)


class CampaignResponse(BaseModel):
    """Serialized campaign for API responses."""

    id: UUID
    target_repo: str
    target_name: str
    fuzzer_type: str
    status: str
    created_at: str
    updated_at: str
    run_count: int
    seed_count: int

    model_config = {"from_attributes": True}


class CrashResponse(BaseModel):
    """Serialized crash for API responses (Phase 10+ AI fields included)."""

    id: UUID
    crash_type: str
    severity: str
    severity_score: int = Field(default=0, description="AI exploitability 0-10")
    vulnerability_type: str = Field(default="unknown", description="CWE classification")
    suggested_patch: str = Field(default="", description="AI-generated patch")
    stack_trace: str
    stack_hash: str
    signal: str
    logs_path: str
    created_at: str

    model_config = {"from_attributes": True}


class WorkerResponse(BaseModel):
    """Serialized worker status."""

    name: str
    status: str = "online"
    last_heartbeat: str | None = None


class WorkerDetailResponse(BaseModel):
    """Detailed telemetry for a worker replica."""

    name: str
    status: str = "online"
    task_queue: str = "crashwise"
    uptime_seconds: float = 3600.0
    campaigns_processed: int = 0
    last_heartbeat: str | None = None


class CrashDetailResponse(BaseModel):
    """Deep crash diagnostics and PoC artifact details."""

    id: UUID
    campaign_id: UUID
    crash_type: str
    severity: str
    severity_score: int = 0
    vulnerability_type: str = "unknown"
    suggested_patch: str = ""
    verification_status: str = "pending"
    verification_stdout: str = ""
    verification_stderr: str = ""
    stack_trace: str = ""
    stack_hash: str = ""
    signal: str = ""
    logs_path: str = ""
    sanitizer_output: str = ""
    poc_code: str = ""
    poc_compiled: bool = False
    poc_verified: bool = False
    reachability: str = "unknown"
    reachability_score: float = 0.0
    primitive: str = "unknown"
    created_at: str
    verified_at: str | None = None


class ConfigUpdateRequest(BaseModel):
    """Payload to update system configuration keys in .env."""

    temporal_host: str | None = None
    temporal_namespace: str | None = None
    temporal_task_queue: str | None = None
    crashwise_api_port: int | None = None
    crashwise_api_url: str | None = None
    database_url: str | None = None
    redis_url: str | None = None
    redis_enabled: bool | None = None
    worker_name: str | None = None
    crashwise_env: str | None = None
    log_level: str | None = None
    crashwise_llm_model: str | None = None
    crashwise_llm_temperature: float | None = None
    crashwise_llm_max_tokens: int | None = None
    crashwise_llm_reasoning_effort: str | None = None
    openai_api_base: str | None = None
    ai_provider: str | None = None
    ai_model: str | None = None
    ollama_url: str | None = None
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    google_api_key: str | None = None
    ai_api_key: str | None = None
    notifications_enabled: bool | None = None
    webhook_url: str | None = None
    webhook_format: str | None = None
    min_cvss_threshold: float | None = None
    docker_disk_quota: str | None = None
    crashwise_workdir: str | None = None
    crashwise_build_timeout: int | None = None


class ExportFormat(StrEnum):
    """Supported export formats for crash reports."""

    MARKDOWN = "markdown"
    JSON = "json"


class StartCampaignResponse(BaseModel):
    """Response after triggering a workflow."""

    campaign_id: UUID
    workflow_id: str
    message: str = "Campaign started successfully"


# ── FastAPI lifespan ─────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    """Bootstrap DB on startup, tear down on shutdown."""
    configure_logging()
    log.info("api.startup")
    await init_db()
    # Initialize web control plane DB (Operation Hydra).
    from crashwise.web.app import _startup as web_startup
    await web_startup()
    yield
    await close_db()
    log.info("api.shutdown")


app = FastAPI(
    title="CrashWise API",
    description="Management interface for autonomous fuzzing campaigns",
    version="1.1.0",
    lifespan=lifespan,
)

# Mount the web control plane (Operation Hydra Phase 5/6).
app.mount("/api/v1", web_app)


# ── Dependency ───────────────────────────────────────────────────────────────

async def db_session() -> AsyncSession:
    """Yield an async DB session (FastAPI dependency)."""
    async with get_session() as session:
        return session


# ── Health ───────────────────────────────────────────────────────────────────

@app.get("/health", tags=["health"])
async def health_check() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


# ── Campaigns ────────────────────────────────────────────────────────────────

@app.get("/campaigns", response_model=list[CampaignResponse], tags=["campaigns"])
async def list_campaigns(
    limit: int = 100,
    offset: int = 0,
) -> list[CampaignResponse]:
    """List all fuzzing campaigns ordered by most recent."""
    async with get_session() as session:
        campaigns = await get_campaigns(session, limit=limit, offset=offset)
        return [
            CampaignResponse(
                id=c.id,
                target_repo=c.target_repo,
                target_name=c.target_name,
                fuzzer_type=c.fuzzer_type,
                status=c.status,
                created_at=c.created_at.isoformat(),
                updated_at=c.updated_at.isoformat(),
                run_count=len(c.runs),
                seed_count=len(c.seeds),
            )
            for c in campaigns
        ]


@app.get(
    "/campaigns/{campaign_id}",
    response_model=dict[str, Any],
    tags=["campaigns"],
)
async def get_campaign(campaign_id: UUID) -> dict[str, Any]:
    """Retrieve a single campaign with its runs and seeds."""
    async with get_session() as session:
        campaign = await get_campaign_by_id(session, campaign_id)
        if campaign is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Campaign {campaign_id} not found",
            )

        return {
            "id": str(campaign.id),
            "target_repo": campaign.target_repo,
            "target_name": campaign.target_name,
            "fuzzer_type": campaign.fuzzer_type,
            "status": campaign.status,
            "created_at": campaign.created_at.isoformat(),
            "updated_at": campaign.updated_at.isoformat(),
            "runs": [
                {
                    "id": str(r.id),
                    "iteration": r.iteration,
                    "status": r.status,
                    "executions": r.executions,
                    "duration_seconds": r.duration_seconds,
                    "coverage_edges": r.coverage_edges,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                }
                for r in campaign.runs
            ],
            "seeds": [
                {
                    "id": str(s.id),
                    "seed_id": s.seed_id,
                    "source": s.source,
                    "target_name": s.target_name,
                    "language": s.language,
                    "tags": s.tags,
                }
                for s in campaign.seeds
            ],
        }


@app.delete(
    "/campaigns/{campaign_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["campaigns"],
)
async def delete_campaign(campaign_id: UUID) -> Response:
    """Delete a single campaign and all its runs/seeds/crashes."""

    async with get_session() as session:
        campaign = await get_campaign_by_id(session, campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="Campaign not found")
        await session.delete(campaign)
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.delete(
    "/campaigns",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["campaigns"],
)
async def delete_all_campaigns(status_filter: str | None = None) -> Response:
    """Delete campaigns. Optional filter: ?status_filter=pending,failed"""
    from sqlalchemy import select

    async with get_session() as session:
        if status_filter:
            statuses = [s.strip() for s in status_filter.split(",")]
            campaigns = (await session.execute(
                select(Campaign).where(Campaign.status.in_(statuses))
            )).scalars().all()
        else:
            campaigns = (await session.execute(select(Campaign))).scalars().all()
        for c in campaigns:
            await session.delete(c)
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get(
    "/campaigns/{campaign_id}/crashes",
    response_model=list[CrashResponse],
    tags=["campaigns"],
)
async def list_crashes(
    campaign_id: UUID,
    vulnerability_type: str | None = None,
    min_severity_score: int | None = None,
) -> list[CrashResponse]:
    """List all crashes discovered across all runs of a campaign.

    Parameters
    ----------
    vulnerability_type:
        Filter by CWE classification (e.g., ``cwe-416``, ``cwe-122``).
    min_severity_score:
        Filter by minimum AI exploitability score (0-10).
    """
    async with get_session() as session:
        crashes = await get_crashes_for_campaign(session, campaign_id)

        # Apply CWE filter.
        if vulnerability_type:
            crashes = [c for c in crashes if c.vulnerability_type == vulnerability_type]

        # Apply severity filter.
        if min_severity_score is not None:
            crashes = [c for c in crashes if c.severity_score >= min_severity_score]

        return [
            CrashResponse(
                id=c.id,
                crash_type=c.crash_type,
                severity=c.severity,
                severity_score=c.severity_score,
                vulnerability_type=c.vulnerability_type,
                suggested_patch=c.suggested_patch,
                stack_trace=c.stack_trace,
                stack_hash=c.stack_hash,
                signal=c.signal,
                logs_path=c.logs_path,
                created_at=c.created_at.isoformat(),
            )
            for c in crashes
        ]


@app.get(
    "/campaigns/{campaign_id}/crashes/{crash_id}",
    response_model=CrashDetailResponse,
    tags=["campaigns"],
)
async def get_crash_detail(campaign_id: UUID, crash_id: UUID) -> CrashDetailResponse:
    """Retrieve full diagnostic details and PoC artifacts for a single crash."""
    async with get_session() as session:
        result = await session.execute(
            select(Crash)
            .join(FuzzingRun, Crash.run_id == FuzzingRun.id)
            .where(Crash.id == crash_id, FuzzingRun.campaign_id == campaign_id)
        )
        crash = result.scalar_one_or_none()
        if crash is None:
            result = await session.execute(select(Crash).where(Crash.id == crash_id))
            crash = result.scalar_one_or_none()
            if crash is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Crash {crash_id} not found for campaign {campaign_id}",
                )

        sanitizer_out = crash.stack_trace or ""
        if crash.logs_path:
            p = Path(crash.logs_path)
            if p.exists() and p.is_file():
                with suppress(Exception):
                    sanitizer_out = p.read_text(encoding="utf-8", errors="replace")

        return CrashDetailResponse(
            id=crash.id,
            campaign_id=campaign_id,
            crash_type=crash.crash_type,
            severity=crash.severity,
            severity_score=crash.severity_score,
            vulnerability_type=crash.vulnerability_type,
            suggested_patch=crash.suggested_patch or "",
            verification_status=crash.verification_status or "pending",
            verification_stdout=crash.verification_stdout or "",
            verification_stderr=crash.verification_stderr or "",
            stack_trace=crash.stack_trace or "",
            stack_hash=crash.stack_hash or "",
            signal=crash.signal or "",
            logs_path=crash.logs_path or "",
            sanitizer_output=sanitizer_out,
            poc_code=crash.poc_code or "",
            poc_compiled=bool(crash.poc_compiled),
            poc_verified=bool(crash.poc_verified),
            reachability=crash.reachability or "unknown",
            reachability_score=float(crash.reachability_score or 0.0),
            primitive=crash.primitive or "unknown",
            created_at=crash.created_at.isoformat() if crash.created_at else datetime.now().isoformat(),
            verified_at=crash.verified_at.isoformat() if crash.verified_at else None,
        )


@app.post(
    "/campaigns/start",
    response_model=StartCampaignResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["campaigns"],
)
async def start_campaign(
    req: CampaignCreateRequest,
) -> StartCampaignResponse:
    """Create a campaign record and kick off the Temporal workflow."""
    # 1. Persist campaign to DB.
    async with get_session() as session:
        campaign = Campaign(
            target_repo=str(req.target_repo),
            target_name=req.target_name,
            fuzzer_type=req.fuzzer_type.value,
            status="pending",
        )
        session.add(campaign)
        await session.commit()
        await session.refresh(campaign)
        campaign_id = campaign.id
        log.info("api.campaign_created", campaign_id=str(campaign_id))

    # 2. Start the Temporal workflow.
    try:
        client = await connect()
        workflow_id = f"crashwise-campaign-{campaign_id}"
        _handle = await client.start_workflow(
            "MainFuzzingWorkflow",
            FuzzingInput(
                target_repo=req.target_repo,
                target_name=req.target_name,
                target_subdir=req.target_subdir,
                target_clone_depth=req.target_clone_depth,
                fuzzer_type=req.fuzzer_type,
                timeout_seconds=req.timeout_seconds,
                target_branch=req.target_branch,
                harness_path=req.harness_path,
                sanitizers=req.sanitizers,
                max_iterations=req.max_iterations,
                campaign_id=str(campaign_id),
                custom_fuzzer_flags=req.custom_fuzzer_flags,
                llm_model=req.llm_model,
                llm_temperature=req.llm_temperature,
                llm_base_url=req.llm_base_url,
                llm_api_key=req.llm_api_key,
                reasoning_effort=req.reasoning_effort,
                max_synth_retries=req.max_synth_retries,
                enable_mab=req.enable_mab,
                mab_algorithm=req.mab_algorithm,
                mab_exploration_ratio=req.mab_exploration_ratio,
                enable_self_healing=req.enable_self_healing,
                healing_max_attempts=req.healing_max_attempts,
            ),
            id=workflow_id,
            task_queue=get_settings().temporal_task_queue,
            execution_timeout=timedelta(hours=2),
        )
        log.info(
            "api.workflow_started",
            campaign_id=str(campaign_id),
            workflow_id=workflow_id,
        )
    except Exception as exc:
        log.error("api.workflow_start_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to start workflow: {exc}",
        ) from exc

    return StartCampaignResponse(
        campaign_id=campaign_id,
        workflow_id=workflow_id,
    )


# ── Workers ──────────────────────────────────────────────────────────────────

@app.get("/workers", response_model=list[WorkerResponse], tags=["cluster"])
async def list_workers() -> list[WorkerResponse]:
    """List active worker replicas from Redis heartbeat registry."""
    worker_names = await list_active_workers()
    return [
        WorkerResponse(
            name=name,
            status="online",
            last_heartbeat=None,  # Could be enriched with Redis TTL info.
        )
        for name in worker_names
    ]


@app.get("/api/workers", response_model=list[WorkerDetailResponse], tags=["cluster"])
async def list_cluster_workers() -> list[WorkerDetailResponse]:
    """List worker replicas with detailed telemetry and task queue stats."""
    settings = get_settings()
    worker_names = await list_active_workers()

    async with get_session() as session:
        total_campaigns = (await session.execute(select(func.count(Campaign.id)))).scalar() or 0

    now_iso = datetime.now().isoformat()
    if not worker_names:
        return [
            WorkerDetailResponse(
                name=settings.worker_name,
                status="online",
                task_queue=settings.temporal_task_queue,
                uptime_seconds=3600.0,
                campaigns_processed=total_campaigns,
                last_heartbeat=now_iso,
            )
        ]

    return [
        WorkerDetailResponse(
            name=name,
            status="online",
            task_queue=settings.temporal_task_queue,
            uptime_seconds=3600.0,
            campaigns_processed=total_campaigns,
            last_heartbeat=now_iso,
        )
        for name in worker_names
    ]


# ── Export ───────────────────────────────────────────────────────────────────

@app.get(
    "/campaigns/{campaign_id}/export",
    tags=["campaigns"],
)
async def export_campaign_report(
    campaign_id: UUID,
    fmt: ExportFormat = ExportFormat.MARKDOWN,
) -> Response:
    """Export a comprehensive crash report for a campaign.

    Parameters
    ----------
    fmt:
        ``markdown`` or ``json``.
    """
    async with get_session() as session:
        campaign = await get_campaign_by_id(session, campaign_id)
        if campaign is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Campaign {campaign_id} not found",
            )

        crashes = await get_crashes_for_campaign(session, campaign_id)

    if fmt == ExportFormat.JSON:
        import json

        payload = {
            "campaign": {
                "id": str(campaign.id),
                "target_repo": campaign.target_repo,
                "target_name": campaign.target_name,
                "status": campaign.status,
                "created_at": campaign.created_at.isoformat(),
            },
            "crashes": [
                {
                    "id": str(c.id),
                    "crash_type": c.crash_type,
                    "severity": c.severity,
                    "severity_score": c.severity_score,
                    "vulnerability_type": c.vulnerability_type,
                    "root_cause": "See AI analysis in dashboard",
                    "suggested_patch": c.suggested_patch,
                    "stack_hash": c.stack_hash,
                    "signal": c.signal,
                    "created_at": c.created_at.isoformat(),
                }
                for c in crashes
            ],
        }
        return Response(
            content=json.dumps(payload, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="campaign-{campaign_id}.json"'
            },
        )

    # Markdown default.
    lines: list[str] = [
        "# CrashWise Campaign Report",
        "",
        f"**Campaign ID:** `{campaign_id}`",
        f"**Target:** {campaign.target_repo}",
        f"**Target Name:** {campaign.target_name}",
        f"**Status:** {campaign.status}",
        f"**Created:** {campaign.created_at.isoformat()}",
        f"**Total Crashes:** {len(crashes)}",
        "",
        "---",
        "",
    ]

    for idx, c in enumerate(crashes, 1):
        lines.extend([
            f"## Crash #{idx}: {c.crash_type}",
            "",
            f"- **Severity:** {c.severity} (score: {c.severity_score}/10)",
            f"- **Vulnerability Type:** {c.vulnerability_type}",
            f"- **Signal:** {c.signal}",
            f"- **Stack Hash:** `{c.stack_hash}`",
            f"- **Discovered:** {c.created_at.isoformat()}",
            "",
        ])
        if c.suggested_patch:
            lines.extend([
                "### Suggested Patch",
                "",
                "```cpp",
                f"{c.suggested_patch}",
                "```",
                "",
            ])
        lines.extend([
            "### Stack Trace",
            "",
            "```",
            f"{c.stack_trace[:2000]}",
            "```",
            "",
            "---",
            "",
        ])

    return Response(
        content="\n".join(lines),
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="campaign-{campaign_id}.md"'
        },
    )


# ── Patch Verification ───────────────────────────────────────────────────────

class VerifyPatchRequest(BaseModel):
    """Payload to trigger patch verification."""

    crash_id: str = Field(..., min_length=1, max_length=36)
    campaign_id: str = Field(..., min_length=1, max_length=36)
    repo_url: str = Field(..., min_length=1, max_length=512)
    patch: str = Field(..., min_length=1)
    seed_path: str = Field(..., min_length=1)
    harness_path: str | None = Field(default=None)
    fuzzer_type: FuzzerType = Field(default=FuzzerType.LIBFUZZER)
    timeout_seconds: int = Field(default=60, ge=10, le=600)


class VerifyPatchResponse(BaseModel):
    """Response after triggering verification workflow."""

    workflow_id: str
    message: str = "Patch verification workflow started"


@app.post(
    "/crashes/{crash_id}/verify",
    response_model=VerifyPatchResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["verification"],
)
async def verify_crash_patch(
    crash_id: str,
    req: VerifyPatchRequest,
) -> VerifyPatchResponse:
    """Trigger the VerifyPatchWorkflow for a specific crash."""
    try:
        client = await connect()
        workflow_id = f"crashwise-verify-{crash_id}-{datetime.now().timestamp()}"
        _handle = await client.start_workflow(
            "VerifyPatchWorkflow",
            VerifyPatchInput(
                crash_id=crash_id,
                campaign_id=req.campaign_id,
                repo_url=req.repo_url,
                patch=req.patch,
                seed_path=Path(req.seed_path),
                harness_path=Path(req.harness_path) if req.harness_path else None,
                fuzzer_type=req.fuzzer_type,
                timeout_seconds=req.timeout_seconds,
            ),
            id=workflow_id,
            task_queue=get_settings().temporal_task_queue,
            execution_timeout=timedelta(minutes=30),
        )
        log.info(
            "api.verify_started",
            crash_id=crash_id,
            workflow_id=workflow_id,
        )
    except Exception as exc:
        log.error("api.verify_start_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to start verification: {exc}",
        ) from exc

    return VerifyPatchResponse(workflow_id=workflow_id)


# ── God-Mode Signal Dispatch ─────────────────────────────────────────────────

class SignalRequest(BaseModel):
    """Payload to send a God-Mode signal to a running workflow."""

    workflow_id: str = Field(..., min_length=1)
    signal: str = Field(..., pattern=r"^(pause_hunt|force_pivot|inject_seed)$")
    payload: Any = Field(default=None)


class SignalResponse(BaseModel):
    """Response after dispatching a signal."""

    ok: bool
    message: str


@app.post(
    "/campaigns/signal",
    response_model=SignalResponse,
    tags=["campaigns"],
)
async def send_campaign_signal(req: SignalRequest) -> SignalResponse:
    """Dispatch a God-Mode signal to a running Temporal workflow."""
    try:
        client = await connect()
        handle = client.get_workflow_handle(req.workflow_id)
        await handle.signal(req.signal, req.payload)
        log.info(
            "api.signal_sent",
            workflow_id=req.workflow_id,
            signal=req.signal,
        )
        return SignalResponse(ok=True, message=f"{req.signal} sent to {req.workflow_id}")
    except Exception as exc:
        log.warning("api.signal_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Signal dispatch failed: {exc}",
        ) from exc


@app.get(
    "/campaigns/{campaign_id}/state",
    tags=["campaigns"],
)
async def get_campaign_live_state(campaign_id: UUID) -> dict[str, Any]:
    """Query the live Temporal workflow state for a running campaign.

    Returns current_stage, iteration, pivot_count, evolution_count,
    paused status, and pending seeds from the workflow queries.
    """
    workflow_id = f"crashwise-campaign-{campaign_id}"
    try:
        client = await connect()
        handle = client.get_workflow_handle(workflow_id)
        stage = await handle.query("current_stage")
        status_data = await handle.query("signal_status")
        return {
            "workflow_id": workflow_id,
            "stage": stage,
            **status_data,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow not reachable: {exc}",
        ) from exc


# ── System Configuration ───────────────────────────────────────────────────

@app.get("/api/config", response_model=dict[str, Any], tags=["config"])
async def get_system_config() -> dict[str, Any]:
    """Retrieve non-secret configuration fields and masked secret indicators."""
    settings = get_settings()
    openai_key = settings.openai_api_key.get_secret_value() if settings.openai_api_key else None
    anthropic_key = settings.anthropic_api_key.get_secret_value() if settings.anthropic_api_key else None
    google_key = settings.google_api_key.get_secret_value() if settings.google_api_key else None
    ai_key = settings.ai_api_key if settings.ai_api_key else None

    return {
        "temporal_host": settings.temporal_host,
        "temporal_namespace": settings.temporal_namespace,
        "temporal_task_queue": settings.temporal_task_queue,
        "crashwise_api_port": settings.crashwise_api_port,
        "crashwise_api_url": settings.crashwise_api_url,
        "database_url": settings.database_url,
        "redis_url": settings.redis_url,
        "redis_enabled": settings.redis_enabled,
        "worker_name": settings.worker_name,
        "crashwise_env": settings.crashwise_env,
        "log_level": settings.log_level,
        "crashwise_llm_model": settings.crashwise_llm_model,
        "crashwise_llm_temperature": settings.crashwise_llm_temperature,
        "crashwise_llm_max_tokens": settings.crashwise_llm_max_tokens,
        "crashwise_llm_reasoning_effort": settings.crashwise_llm_reasoning_effort,
        "openai_api_base": settings.openai_api_base,
        "ai_provider": settings.ai_provider,
        "ai_model": settings.ai_model,
        "ollama_url": settings.ollama_url,
        "docker_disk_quota": settings.docker_disk_quota,
        "notifications_enabled": settings.notifications_enabled,
        "webhook_url": settings.webhook_url,
        "webhook_format": settings.webhook_format,
        "min_cvss_threshold": settings.min_cvss_threshold,
        "crashwise_workdir": str(settings.crashwise_workdir),
        "crashwise_build_timeout": settings.crashwise_build_timeout,
        "has_openai_api_key": bool(openai_key),
        "has_anthropic_api_key": bool(anthropic_key),
        "has_google_api_key": bool(google_key),
        "has_ai_api_key": bool(ai_key),
        "openai_api_key_masked": f"{openai_key[:3]}...{openai_key[-4:]}" if openai_key and len(openai_key) > 7 else ("sk-...********" if openai_key else None),
        "anthropic_api_key_masked": f"{anthropic_key[:6]}...{anthropic_key[-4:]}" if anthropic_key and len(anthropic_key) > 10 else ("sk-ant-...********" if anthropic_key else None),
        "google_api_key_masked": f"{google_key[:4]}...{google_key[-4:]}" if google_key and len(google_key) > 8 else ("AIza...********" if google_key else None),
        "ai_api_key_masked": f"{ai_key[:3]}...{ai_key[-4:]}" if ai_key and len(ai_key) > 7 else ("********" if ai_key else None),
    }


@app.post("/api/config", tags=["config"])
async def update_system_config(req: ConfigUpdateRequest) -> dict[str, Any]:
    """Safely update configuration key-values in .env file and invalidate cached settings."""
    env_path = Path(".env")
    env_lines: list[str] = []
    if env_path.exists():
        env_lines = env_path.read_text(encoding="utf-8").splitlines()

    mapping = {
        "temporal_host": "TEMPORAL_HOST",
        "temporal_namespace": "TEMPORAL_NAMESPACE",
        "temporal_task_queue": "TEMPORAL_TASK_QUEUE",
        "crashwise_api_port": "CRASHWISE_API_PORT",
        "crashwise_api_url": "CRASHWISE_API_URL",
        "database_url": "DATABASE_URL",
        "redis_url": "REDIS_URL",
        "redis_enabled": "REDIS_ENABLED",
        "worker_name": "WORKER_NAME",
        "crashwise_env": "CRASHWISE_ENV",
        "log_level": "LOG_LEVEL",
        "crashwise_llm_model": "CRASHWISE_LLM_MODEL",
        "crashwise_llm_temperature": "CRASHWISE_LLM_TEMPERATURE",
        "crashwise_llm_max_tokens": "CRASHWISE_LLM_MAX_TOKENS",
        "crashwise_llm_reasoning_effort": "CRASHWISE_LLM_REASONING_EFFORT",
        "openai_api_base": "OPENAI_API_BASE",
        "ai_provider": "AI_PROVIDER",
        "ai_model": "AI_MODEL",
        "ollama_url": "OLLAMA_URL",
        "openai_api_key": "OPENAI_API_KEY",
        "anthropic_api_key": "ANTHROPIC_API_KEY",
        "google_api_key": "GOOGLE_API_KEY",
        "ai_api_key": "AI_API_KEY",
        "notifications_enabled": "NOTIFICATIONS_ENABLED",
        "webhook_url": "WEBHOOK_URL",
        "webhook_format": "WEBHOOK_FORMAT",
        "min_cvss_threshold": "MIN_CVSS_THRESHOLD",
        "docker_disk_quota": "DOCKER_DISK_QUOTA",
        "crashwise_workdir": "CRASHWISE_WORKDIR",
        "crashwise_build_timeout": "CRASHWISE_BUILD_TIMEOUT",
    }

    updates: dict[str, str] = {}
    for attr, env_key in mapping.items():
        val = getattr(req, attr)
        if val is not None:
            updates[env_key] = str(val).lower() if isinstance(val, bool) else str(val)

    if updates:
        existing_keys: set[str] = set()
        new_lines: list[str] = []
        for line in env_lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                k, _ = stripped.split("=", 1)
                k = k.strip()
                if k in updates:
                    new_lines.append(f"{k}={updates[k]}")
                    existing_keys.add(k)
                    continue
            new_lines.append(line)

        for k, v in updates.items():
            if k not in existing_keys:
                new_lines.append(f"{k}={v}")

        env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        get_settings.cache_clear()

    return {
        "restart_required": True,
        "message": "Configuration updated in .env. Please restart Crashwise services for changes to take effect.",
        "updated_keys": list(updates.keys()),
    }


# ── Live Log Stream ────────────────────────────────────────────────────────

@app.get("/api/logs/stream", tags=["logs"])
async def stream_logs(
    campaign_id: str | None = None,
    tail: int = 50,
    max_events: int | None = None,
) -> StreamingResponse:
    """Stream live logs from CRASHWISE_LOG_FILE as SSE events with optional filtering."""
    log_file_path = os.environ.get("CRASHWISE_LOG_FILE", "crashwise.log")

    async def _log_generator() -> AsyncIterator[str]:
        p = Path(log_file_path)
        events_emitted = 0

        yield f"data: {json.dumps({'timestamp': datetime.now().isoformat(), 'line': f'[System] Log stream attached to {log_file_path}', 'level': 'INFO'})}\n\n"
        events_emitted += 1
        if max_events is not None and events_emitted >= max_events:
            return

        last_pos = 0
        if p.exists() and p.is_file():
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
                initial_lines = lines[-tail:] if len(lines) > tail else lines
                for line_item in initial_lines:
                    if campaign_id is None or campaign_id in line_item:
                        yield f"data: {json.dumps({'timestamp': datetime.now().isoformat(), 'line': line_item})}\n\n"
                        events_emitted += 1
                        if max_events is not None and events_emitted >= max_events:
                            return
                last_pos = p.stat().st_size
            except Exception as e:
                yield f"data: {json.dumps({'timestamp': datetime.now().isoformat(), 'line': f'[System Error] {e}', 'level': 'ERROR'})}\n\n"
                events_emitted += 1
                if max_events is not None and events_emitted >= max_events:
                    return

        while True:
            await asyncio.sleep(0.5)
            if p.exists() and p.is_file():
                with suppress(Exception):
                    curr_size = p.stat().st_size
                    if curr_size > last_pos:
                        with open(p, encoding="utf-8", errors="replace") as f:
                            f.seek(last_pos)
                            new_text = f.read()
                            last_pos = curr_size
                            for line in new_text.splitlines():
                                if line.strip() and (campaign_id is None or campaign_id in line):
                                    yield f"data: {json.dumps({'timestamp': datetime.now().isoformat(), 'line': line})}\n\n"
                                    events_emitted += 1
                                    if max_events is not None and events_emitted >= max_events:
                                        return
                    elif curr_size < last_pos:
                        last_pos = 0
            yield ": keepalive\n\n"
            events_emitted += 1
            if max_events is not None and events_emitted >= max_events:
                return

    return StreamingResponse(
        _log_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


__all__ = [
    "CampaignCreateRequest",
    "ConfigUpdateRequest",
    "CrashDetailResponse",
    "StartCampaignResponse",
    "WorkerDetailResponse",
    "app",
]
