# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``analyze_crash`` activity — deep AI-powered root-cause analysis.

Triggered by the workflow only when a *unique* crash is found (to save
API costs).  The activity sends the crash context to the configured
inference provider, receives structured RCA + exploitability scores,
and persists everything to the DB.

Patch generation is skipped when self-healing is enabled (the Healing
Engine's REPAIR mode will generate a verified patch). When self-healing
is disabled, the activity generates an intelligent patch suggestion
using the full crash context.

If no AI provider is configured, the activity exits gracefully after
logging a debug message.
"""

from __future__ import annotations

from uuid import UUID

from temporalio import activity

from crashwise.core.ai_provider import get_provider
from crashwise.core.database import Crash, get_session
from crashwise.core.logging import get_logger

log = get_logger(__name__)


@activity.defn(name="analyze_crash")
async def analyze_crash(
    crash_id: str,
    crash_context: str,
    campaign_id: str,
    skip_patch_generation: bool = False,
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
    skip_patch_generation:
        When True, skip patch generation (self-healing REPAIR mode will
        generate a verified patch). When False, generate an intelligent
        patch suggestion using the full crash context.

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

    # 2. Generate patch suggestion (skip when self-healing will do it better).
    if skip_patch_generation:
        log.info(
            "analyze_crash.patch_skipped",
            crash_id=crash_id,
            reason="self_healing_enabled",
        )
        suggested_patch = ""
        patch_confidence = 0.0
    else:
        patch_result = await _generate_intelligent_patch(
            crash_context=crash_context,
            root_cause=root_cause,
            bug_type=bug_type,
            provider=provider,
        )
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


async def _generate_intelligent_patch(
    *,
    crash_context: str,
    root_cause: str,
    bug_type: str,
    provider: object,
) -> dict[str, str | float]:
    """Generate an intelligent patch suggestion using full crash context.

    Unlike the old stub patcher that only used root_cause, this function
    provides the LLM with the complete crash context including ASAN output,
    stack traces, and source code snippets when available.

    Parameters
    ----------
    crash_context:
        Full crash report (ASAN + GDB + stack trace + source snippets).
    root_cause:
        AI-generated root cause explanation.
    bug_type:
        Classified bug type (heap-buffer-overflow, use-after-free, etc.).
    provider:
        AI inference provider.

    Returns
    -------
    dict with keys: patch (str), explanation (str), confidence (float).
    """
    if not root_cause or root_cause.strip().lower().startswith("ai provider not configured"):
        log.debug("patcher.no_root_cause")
        return {
            "patch": "",
            "explanation": "No root cause available — skipping patch generation",
            "confidence": 0.0,
        }

    # Build a rich prompt with full context.
    prompt = f"""You are an expert C/C++ security engineer. Analyze this crash and generate a minimal, safe patch.

## Crash Context
{crash_context}

## Root Cause Analysis
{root_cause}

## Bug Type
{bug_type}

## Instructions
Generate a unified diff patch that fixes the root cause. The patch should:
1. Be minimal — only change what's necessary to fix the bug
2. Follow secure coding practices (bounds checking, null checks, etc.)
3. Include a brief comment explaining the fix
4. Be conservative — when in doubt, add defensive checks

Output format:
- patch: unified diff format (--- a/file.c, +++ b/file.c, @@ ... @@)
- explanation: one-sentence summary of the fix
- confidence: 0.0-1.0 based on how confident you are in the fix
"""

    try:
        result = await provider.analyze(prompt)  # type: ignore[union-attr]
        return {
            "patch": str(result.get("patch", "")),
            "explanation": str(result.get("explanation", "")),
            "confidence": float(result.get("confidence", 0.0)),
        }
    except Exception as exc:
        log.warning("patcher.llm_error", error=str(exc))
        return {
            "patch": "",
            "explanation": f"Patch generation failed: {exc}",
            "confidence": 0.0,
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
