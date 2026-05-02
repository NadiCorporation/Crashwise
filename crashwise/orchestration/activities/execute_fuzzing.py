# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``execute_fuzzing`` activity — long-running fuzz campaign with heartbeats.

Long-running activities MUST heartbeat regularly so Temporal can:
    1. Detect a hung worker via ``heartbeat_timeout``.
    2. Surface activity progress to operators.
    3. Allow graceful cancellation (we honour ``CancelledError``).

The Phase 1 implementation is a deterministic simulator: it sleeps in 1-second
ticks, heartbeats each tick, and terminates either when the requested timeout
elapses or when cancellation is signalled. Phase 2 will swap the loop body for
``subprocess`` invocations of AFL++/libFuzzer and stream their progress into
the heartbeat payload.
"""

from __future__ import annotations

import asyncio
import time

from temporalio import activity
from temporalio.exceptions import ApplicationError

from crashwise.core.logging import get_logger
from crashwise.core.models import (
    ExecuteFuzzingInput,
    ExecuteFuzzingOutput,
    FuzzerType,
)

log = get_logger(__name__)

# Heartbeat cadence. Must be << the workflow's heartbeat_timeout.
_HEARTBEAT_INTERVAL_SECONDS: float = 1.0


@activity.defn(name="execute_fuzzing")
async def execute_fuzzing(payload: ExecuteFuzzingInput) -> ExecuteFuzzingOutput:
    """Run a fuzz campaign and emit periodic heartbeats."""
    info = activity.info()
    workflow_id = info.workflow_id

    if not payload.workdir.exists():
        raise ApplicationError(
            f"workdir does not exist: {payload.workdir}",
            type="WorkdirMissing",
            non_retryable=True,
        )

    logs_path = payload.workdir / "fuzz.log"
    crashes_dir = payload.workdir / "crashes"
    crashes_dir.mkdir(parents=True, exist_ok=True)
    logs_path.touch(exist_ok=True)

    log.info(
        "execute_fuzzing.start",
        workflow_id=workflow_id,
        attempt=info.attempt,
        fuzzer=payload.fuzzer_type.value,
        timeout_seconds=payload.timeout_seconds,
        workdir=str(payload.workdir),
        corpus_dir=str(payload.corpus_dir) if payload.corpus_dir else None,
    )

    # Download seed corpus from R2 if distributed storage is enabled.
    if payload.campaign_id is not None:
        from crashwise.core.storage import sync_directory

        corpus_local = payload.workdir / "corpus"
        corpus_local.mkdir(parents=True, exist_ok=True)
        prefix = f"campaigns/{payload.campaign_id}/corpus"
        await sync_directory(corpus_local, prefix, direction="down")

    # If a seed corpus was prepared, copy seeds into the workdir so the
    # fuzzer can ingest them.  (Real implementation: pass -corpus= flag.)
    if payload.corpus_dir is not None and payload.corpus_dir.exists():
        for seed_file in payload.corpus_dir.iterdir():
            if seed_file.is_file():
                dest = crashes_dir.parent / "corpus" / seed_file.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(seed_file.read_bytes())
                log.debug(
                    "execute_fuzzing.copied_seed",
                    seed=str(seed_file),
                    dest=str(dest),
                )

    # Honour any heartbeat details from a previous attempt so we resume,
    # not restart, on retry.
    elapsed_resume: float = 0.0
    executions_resume: int = 0
    if info.heartbeat_details:
        try:
            prev = info.heartbeat_details[0]
            elapsed_resume = float(prev.get("elapsed_seconds", 0.0))
            executions_resume = int(prev.get("executions", 0))
            log.info(
                "execute_fuzzing.resume",
                elapsed_resume=elapsed_resume,
                executions_resume=executions_resume,
            )
        except (TypeError, ValueError, AttributeError, IndexError):
            log.warning("execute_fuzzing.invalid_heartbeat_details")

    started_monotonic = time.monotonic()
    elapsed = elapsed_resume
    executions = executions_resume

    try:
        while elapsed < float(payload.timeout_seconds):
            # Simulated fuzzer tick. Real implementation: read from AFL++/
            # libFuzzer subprocess stdout, parse exec/sec, harvest crashes.
            await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)
            tick = time.monotonic() - started_monotonic
            elapsed = elapsed_resume + tick
            executions += _simulated_execs_per_tick(payload.fuzzer_type)

            activity.heartbeat(
                {
                    "elapsed_seconds": round(elapsed, 2),
                    "executions": executions,
                    "fuzzer": payload.fuzzer_type.value,
                }
            )
    except asyncio.CancelledError:
        log.warning(
            "execute_fuzzing.cancelled",
            workflow_id=workflow_id,
            elapsed_seconds=round(elapsed, 2),
            executions=executions,
        )
        raise

    duration = time.monotonic() - started_monotonic
    output = ExecuteFuzzingOutput(
        logs_path=logs_path,
        crashes_dir=crashes_dir,
        crash_count=0,  # Phase 1 stub: never finds a real crash.
        executions=executions,
        duration_seconds=round(duration, 3),
    )

    log.info(
        "execute_fuzzing.complete",
        workflow_id=workflow_id,
        executions=output.executions,
        duration_seconds=output.duration_seconds,
    )

    # Persist run stats when campaign_id is provided.
    if payload.campaign_id is not None:
        await _persist_run(payload, output)
        # Update Redis global counter.
        from crashwise.core.redis import incr_exec_counter

        await incr_exec_counter(payload.campaign_id, count=output.executions)

    # Upload crashes to R2 for distributed access.
    if payload.campaign_id is not None:
        from crashwise.core.storage import sync_directory

        crashes_prefix = f"campaigns/{payload.campaign_id}/crashes/iter-{payload.iteration}"
        await sync_directory(crashes_dir, crashes_prefix, direction="up")

    return output


async def _persist_run(
    payload: ExecuteFuzzingInput,
    output: ExecuteFuzzingOutput,
) -> None:
    """Write fuzzing run stats to the DB."""
    from datetime import UTC, datetime
    from uuid import UUID

    from crashwise.core.database import FuzzingRun, get_session

    try:
        async with get_session() as session:
            run = FuzzingRun(
                campaign_id=UUID(payload.campaign_id),
                iteration=payload.iteration,
                started_at=datetime.now(tz=UTC),
                finished_at=datetime.now(tz=UTC),
                executions=output.executions,
                duration_seconds=output.duration_seconds,
                status="completed",
            )
            session.add(run)
            await session.commit()
            log.info(
                "execute_fuzzing.db_persisted",
                campaign_id=payload.campaign_id,
                iteration=payload.iteration,
                executions=output.executions,
            )
    except Exception:
        log.warning("execute_fuzzing.db_persist_failed", exc_info=True)


def _simulated_execs_per_tick(fuzzer: FuzzerType) -> int:
    """Plausible exec counts per second per fuzzer for the stub."""
    return {
        FuzzerType.LIBFUZZER: 5_000,
        FuzzerType.AFLPP: 2_500,
        FuzzerType.HONGGFUZZ: 3_500,
    }.get(fuzzer, 1_000)


__all__ = ["execute_fuzzing"]


# Re-export for tests that want to tune the cadence.
def _set_heartbeat_interval(seconds: float) -> None:  # pragma: no cover - test hook
    global _HEARTBEAT_INTERVAL_SECONDS
    _HEARTBEAT_INTERVAL_SECONDS = seconds


def _get_heartbeat_interval() -> float:  # pragma: no cover - test hook
    return _HEARTBEAT_INTERVAL_SECONDS
