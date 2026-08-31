# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``persist_triaged_crash`` activity — Phase 22 healing engine.

Single-crash persistence helper invoked by :class:`MainFuzzingWorkflow`
*after* the autonomous repair agent has run on a unique, net-new crash.
Splitting persistence out of the bulk ``triage_results`` activity lets
the workflow interleave the LLM-driven repair step between the Redis
fast-path dedup check and the SQL write, so the verified ``.patch``
ends up in the same DB row as the crash it fixes.

Idempotency
-----------
The activity uses the campaign-scoped Redis stack-hash set as the
authoritative dedup token: a second invocation for the same
``(campaign_id, stack_hash)`` returns ``persisted=False`` and never
touches PostgreSQL. This makes Temporal activity retries safe even when
the DB write succeeded but the activity returned-result handoff failed.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from temporalio import activity

from crashwise.core.logging import get_logger
from crashwise.core.models import (
    PersistTriagedCrashInput,
    PersistTriagedCrashOutput,
)

log = get_logger(__name__)


@activity.defn(name="persist_triaged_crash")
async def persist_triaged_crash(
    payload: PersistTriagedCrashInput,
) -> PersistTriagedCrashOutput:
    """Persist a single triaged crash row, optionally with a verified patch.

    The flow mirrors the legacy bulk ``_persist_crashes`` helper inside
    ``triage_results.py`` but operates on exactly one
    :class:`TriagedCrashRef` so the workflow can stitch in the patch
    text returned by ``run_autonomous_repair_activity``.

    Returns
    -------
    PersistTriagedCrashOutput
        ``persisted=True`` and the new ``crash_uuid`` on success;
        ``persisted=False`` and ``duplicate=True`` when Redis already
        knew the stack hash; ``persisted=False`` on transient DB
        failures (already logged + non-retryable to the workflow).
    """
    info = activity.info()
    crash = payload.crash
    log.info(
        "persist_triaged_crash.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        campaign_id=payload.campaign_id,
        crash_id=crash.crash_id,
        stack_hash=crash.stack_hash,
        bug_type=crash.bug_type,
        has_patch=bool(payload.patch),
        patch_chars=len(payload.patch),
    )

    from crashwise.core.database import Crash, get_session
    from crashwise.core.redis import (
        claim_stack_hash,
        incr_crash_counter,
        release_stack_hash,
    )

    # Resolve the run_id up-front so a malformed value never aborts the write.
    run_id: UUID | None = None
    if payload.run_id:
        try:
            run_id = UUID(payload.run_id)
        except (ValueError, TypeError, AttributeError):
            log.warning(
                "persist_triaged_crash.invalid_run_id",
                campaign_id=payload.campaign_id,
                run_id=payload.run_id,
            )

    stack_hash = crash.stack_hash
    claimed = False

    # ── Redis fast-path dedup (atomic claim) ────────────────────────────
    # We reserve the hash *before* the SQL write, but roll the reservation
    # back if the write fails — so a transient DB outage never permanently
    # deduplicates a crash away.
    if stack_hash:
        claimed = await claim_stack_hash(payload.campaign_id, stack_hash)
        if not claimed:
            log.debug(
                "persist_triaged_crash.redis_dedup",
                campaign_id=payload.campaign_id,
                stack_hash=stack_hash,
            )
            return PersistTriagedCrashOutput(
                persisted=False,
                crash_uuid=None,
                duplicate=True,
            )

    # ── DB write ─────────────────────────────────────────────────────────
    new_uuid = uuid4()
    try:
        async with get_session() as session:
            row = Crash(
                id=new_uuid,
                run_id=run_id,
                crash_type=crash.bug_type,
                severity=crash.severity.value,
                stack_trace=crash.stack_trace,
                stack_hash=stack_hash,
                signal=crash.signal,
                logs_path=crash.crash_file_path,
                suggested_patch=payload.patch,
                # When the healing engine produced a verified patch,
                # mark verification as fixed so the dashboard can
                # surface the autonomous repair without waiting for the
                # downstream VerifyPatchWorkflow.
                verification_status=("fixed" if payload.patch else "pending"),
            )
            session.add(row)
            await session.commit()

        if stack_hash:
            await incr_crash_counter(payload.campaign_id, count=1)

        # Mirror to the web control plane (best-effort; never fatal).
        await _mirror_to_web_control_plane(payload)

        log.info(
            "persist_triaged_crash.db_committed",
            campaign_id=payload.campaign_id,
            crash_uuid=str(new_uuid),
            run_id=str(run_id) if run_id else None,
            patch_chars=len(payload.patch),
            healing_attempts=payload.healing_attempts,
        )
        return PersistTriagedCrashOutput(
            persisted=True,
            crash_uuid=str(new_uuid),
            duplicate=False,
        )
    except Exception:
        # Roll back the Redis reservation so the crash can be retried later.
        if claimed and stack_hash:
            await release_stack_hash(payload.campaign_id, stack_hash)
        # We deliberately do NOT raise here — the workflow already paid
        # for the LLM repair step and we don't want a transient DB
        # outage to retry the entire healing chain. The workflow logs
        # ``persisted=False`` and continues.
        log.warning(
            "persist_triaged_crash.db_failed",
            campaign_id=payload.campaign_id,
            crash_id=crash.crash_id,
            exc_info=True,
        )
        return PersistTriagedCrashOutput(
            persisted=False,
            crash_uuid=None,
            duplicate=False,
        )


async def _mirror_to_web_control_plane(
    payload: PersistTriagedCrashInput,
) -> None:
    """Best-effort mirror to the FastAPI control-plane DB.

    Matches the side-effect that lived inside the legacy bulk persister
    so dashboards keep working when the workflow drives persistence.
    """
    crash = payload.crash
    try:
        from crashwise.web.hooks import persist_crash_to_web

        crash_state = (
            f"{crash.crash_file_path}:{crash.bug_type}" if crash.crash_file_path else crash.bug_type
        )
        await persist_crash_to_web(
            campaign_id=payload.campaign_id,
            crash_type=crash.bug_type,
            crash_state=crash_state,
            severity=crash.severity.value,
            sanitizer_log=crash.asan_log,
            gdb_backtrace=crash.stack_trace,
            reproducer_path=crash.crash_file_path,
        )
    except Exception:  # pragma: no cover - degrades gracefully
        # Web DB may not be configured in dev — never fatal.
        log.debug(
            "persist_triaged_crash.web_mirror_skipped",
            campaign_id=payload.campaign_id,
        )


# Re-export for older callers that still import the dict-payload shape
# from the previous interim. Helps downstream code migrate without a
# big-bang rename.
async def persist_triaged_crash_dict(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Adapter: accept a plain-dict payload, delegate to the typed activity.

    Not registered as a Temporal activity. Reserved for ad-hoc callers.
    """
    typed = PersistTriagedCrashInput.model_validate(payload)
    out = await persist_triaged_crash(typed)
    return out.model_dump()


__all__ = ["persist_triaged_crash", "persist_triaged_crash_dict"]
