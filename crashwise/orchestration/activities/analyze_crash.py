# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``analyze_crash`` activity — deep AI-powered root-cause analysis.

Triggered by the workflow only when a *unique* crash is found (to save
API costs).  The activity sends the crash context to the configured
inference provider, receives structured RCA + exploitability scores,
generates a patch suggestion, and persists everything to the DB.

If no AI provider is configured, the activity exits gracefully after
logging a debug message.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from temporalio import activity

from crashwise.agents.feedback.patcher import suggest_patch
from crashwise.core.ai_provider import get_provider
from crashwise.core.database import Crash, get_session
from crashwise.core.logging import get_logger

log = get_logger(__name__)


@activity.defn(name="analyze_crash")
async def analyze_crash(
    crash_id: str,
    crash_context: str,
    campaign_id: str,
) -> dict[str, object]:
    """Perform deep AI analysis on a unique crash.

    Parameters
    ----------
    crash_id:
        Database UUID of the crash record to update.
    crash_context:
        Concatenated crash report (ASAN + GDB + stack trace).
    campaign_id:
        Campaign UUID (for logging only).

    Returns
    -------
    Structured analysis result with keys: bug_type, exploitability,
    root_cause, vulnerability_type, patch, patch_confidence.
    """
    info = activity.info()
    log.info(
        "analyze_crash.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        crash_id=crash_id,
        campaign_id=campaign_id,
    )

    provider = get_provider()

    # Fast-path: null provider means AI is not configured.
    if not await provider.health_check():
        log.debug("analyze_crash.provider_unavailable", crash_id=crash_id)
        return {
            "bug_type": "unknown",
            "exploitability": 0.0,
            "root_cause": "AI provider not configured — skipping deep analysis",
            "vulnerability_type": "unknown",
            "patch": "",
            "patch_confidence": 0.0,
        }

    # 1. Deep RCA via inference provider.
    ai_result = await provider.analyze(crash_context)
    bug_type = str(ai_result.get("bug_type", "unknown"))
    exploitability = float(ai_result.get("exploitability", 0.0))
    root_cause = str(ai_result.get("root_cause", ""))
    vulnerability_type = str(ai_result.get("vulnerability_type", "unknown"))
    confidence = float(ai_result.get("confidence", 0.0))

    log.info(
        "analyze_crash.ai_result",
        crash_id=crash_id,
        bug_type=bug_type,
        exploitability=exploitability,
        confidence=confidence,
    )

    # 2. Suggest patch from RCA.
    patch_result = await suggest_patch(root_cause, provider=provider)
    suggested_patch = str(patch_result.get("patch", ""))
    patch_confidence = float(patch_result.get("confidence", 0.0))

    log.info(
        "analyze_crash.patch_result",
        crash_id=crash_id,
        patch_len=len(suggested_patch),
        patch_confidence=patch_confidence,
    )

    # 3. Persist to DB.
    await _update_crash_record(
        crash_id=crash_id,
        severity_score=int(exploitability),
        vulnerability_type=vulnerability_type,
        suggested_patch=suggested_patch,
    )

    return {
        "bug_type": bug_type,
        "exploitability": exploitability,
        "root_cause": root_cause,
        "vulnerability_type": vulnerability_type,
        "confidence": confidence,
        "patch": suggested_patch,
        "patch_confidence": patch_confidence,
    }


async def _update_crash_record(
    crash_id: str,
    severity_score: int,
    vulnerability_type: str,
    suggested_patch: str,
) -> None:
    """Update the crash record with AI-generated fields."""
    try:
        async with get_session() as session:
            crash = await session.get(Crash, UUID(crash_id))
            if crash is not None:
                crash.severity_score = severity_score
                crash.vulnerability_type = vulnerability_type
                crash.suggested_patch = suggested_patch
                await session.commit()
                log.info(
                    "analyze_crash.db_updated",
                    crash_id=crash_id,
                    severity_score=severity_score,
                )
            else:
                log.warning("analyze_crash.record_not_found", crash_id=crash_id)
    except Exception:
        log.warning("analyze_crash.db_update_failed", crash_id=crash_id, exc_info=True)


__all__ = ["analyze_crash"]
