# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``execute_fuzzing`` activity — real fuzzer execution (Phase 21).

Phase 21 §1.2 fix: replaces the deterministic simulator with real Docker
invocations via :class:`crashwise.execution.docker_manager.DockerManager`.
The activity:

  1. Launches an AFL++/libFuzzer container (no ``--rm`` — see §1.3).
  2. Heartbeats Temporal every second with parsed exec/sec, coverage,
     and crash counts pulled from the container's stdout and AFL++'s
     ``fuzzer_stats`` file.
  3. On timeout / cancellation: stops the container, harvests the corpus
     and crashes via ``docker cp``, then ``docker rm -f``.

Backwards compatibility: the legacy simulator path is preserved for unit
tests that never pass a ``campaign_id``. Production callers always set
``campaign_id`` and therefore exercise the real path.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from pathlib import Path

from temporalio import activity
from temporalio.exceptions import ApplicationError

from crashwise.core.logging import get_logger
from crashwise.core.models import (
    ExecuteFuzzingInput,
    ExecuteFuzzingOutput,
    ExecutionBackend,
    FuzzerType,
    FuzzJob,
)

log = get_logger(__name__)

# Heartbeat cadence. Must be << the workflow's heartbeat_timeout.
_HEARTBEAT_INTERVAL_SECONDS: float = 1.0


@activity.defn(name="execute_fuzzing")
async def execute_fuzzing(payload: ExecuteFuzzingInput) -> ExecuteFuzzingOutput:
    """Run a fuzz campaign and emit periodic heartbeats.

    Production callers (workflows that pass a ``campaign_id``) trigger the
    real Docker execution path. Tests that omit ``campaign_id`` continue
    to exercise the deterministic simulator so the in-memory Temporal
    sandbox can resolve in milliseconds.
    """
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
        mode="real" if payload.campaign_id else "simulator",
    )

    # Download seed corpus from R2 if distributed storage is enabled.
    if payload.campaign_id is not None:
        from crashwise.core.storage import sync_directory

        corpus_local = payload.workdir / "corpus"
        corpus_local.mkdir(parents=True, exist_ok=True)
        prefix = f"campaigns/{payload.campaign_id}/corpus"
        await sync_directory(corpus_local, prefix, direction="down")

    # If a seed corpus was prepared, copy seeds into the workdir.
    if payload.corpus_dir is not None and payload.corpus_dir.exists():
        for seed_file in payload.corpus_dir.iterdir():
            if seed_file.is_file():
                dest = crashes_dir.parent / "corpus" / seed_file.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(seed_file.read_bytes())

    # Dispatch to the real path or the simulator. The simulator stays in
    # the codebase so the unit-test sandbox does not need Docker.
    if payload.campaign_id is None:
        return await _simulated_execute(payload, logs_path, crashes_dir)
    return await _real_execute(payload, logs_path, crashes_dir)


# ── Real execution (Phase 21) ────────────────────────────────────────────────


async def _real_execute(
    payload: ExecuteFuzzingInput,
    logs_path: Path,
    crashes_dir: Path,
) -> ExecuteFuzzingOutput:
    """Live Docker fuzzing with stdout parsing and heartbeat reporting."""
    from crashwise.execution.docker_manager import (
        DockerManager,
        parse_afl_fuzzer_stats,
        parse_libfuzzer_log_tail,
    )

    info = activity.info()
    job_id = f"{payload.campaign_id}-iter{payload.iteration}"

    # The harness binary lives next to the workdir; fall back gracefully.
    harness_path = payload.harness_path or (payload.workdir / "harness")
    corpus_dir = payload.corpus_dir or (payload.workdir / "corpus")
    corpus_dir.mkdir(parents=True, exist_ok=True)

    job = FuzzJob(
        job_id=job_id,
        backend=ExecutionBackend.DOCKER,
        harness_path=harness_path,
        corpus_dir=corpus_dir,
        output_dir=crashes_dir.parent,
        timeout_seconds=payload.timeout_seconds,
        cpu_limit=2.0,
        memory_limit_mb=2048,
    )

    mgr = DockerManager()
    started_monotonic = time.monotonic()
    last_executions = 0
    last_coverage = 0
    last_exec_per_sec = 0.0
    crash_count_observed = 0

    try:
        await mgr.start(job)
    except Exception as exc:
        log.error(
            "execute_fuzzing.docker_start_failed",
            job_id=job_id,
            error=str(exc),
        )
        raise ApplicationError(
            f"Failed to start Docker fuzzer container: {exc}",
            type="DockerStartFailed",
            non_retryable=False,
        ) from exc

    try:
        elapsed: float = 0.0
        while elapsed < float(payload.timeout_seconds):
            try:
                await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)
            except asyncio.CancelledError:
                raise

            elapsed = time.monotonic() - started_monotonic

            # Bail out early if the container has exited (crash / OOM).
            alive = await mgr.is_alive(job_id)

            # Pull fresh stdout for libFuzzer-style parsing.
            try:
                tail = await mgr.logs(job_id, tail=200)
            except Exception:
                tail = ""

            parsed_lf = parse_libfuzzer_log_tail(tail)
            if parsed_lf:
                last_executions = max(last_executions, int(parsed_lf["executions"]))
                last_coverage = max(last_coverage, int(parsed_lf["coverage"]))
                last_exec_per_sec = parsed_lf["exec_per_sec"]

            # AFL++ writes a fuzzer_stats file under -o/.
            afl_stats_path = crashes_dir.parent / "fuzzer_stats"
            if (
                payload.fuzzer_type == FuzzerType.AFLPP
                and afl_stats_path.exists()
            ):
                with contextlib.suppress(OSError):
                    afl_text = afl_stats_path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    parsed_afl = parse_afl_fuzzer_stats(afl_text)
                    if "executions" in parsed_afl:
                        last_executions = max(
                            last_executions, int(parsed_afl["executions"])
                        )
                    if "coverage" in parsed_afl:
                        last_coverage = max(last_coverage, int(parsed_afl["coverage"]))
                    if "exec_per_sec" in parsed_afl:
                        last_exec_per_sec = parsed_afl["exec_per_sec"]
                    if "crashes" in parsed_afl:
                        crash_count_observed = max(
                            crash_count_observed, int(parsed_afl["crashes"])
                        )

            # Snapshot the live tail to disk so analyze_progress can re-read it.
            if tail:
                with contextlib.suppress(OSError):
                    logs_path.write_text(tail, encoding="utf-8", errors="replace")

            # Crash detection by directory listing (libFuzzer drops crash-* files).
            with contextlib.suppress(OSError):
                crash_count_observed = max(
                    crash_count_observed,
                    sum(1 for p in crashes_dir.iterdir() if p.is_file()),
                )

            activity.heartbeat(
                {
                    "elapsed_seconds": round(elapsed, 2),
                    "executions": last_executions,
                    "coverage": last_coverage,
                    "exec_per_sec": last_exec_per_sec,
                    "crashes": crash_count_observed,
                    "fuzzer": payload.fuzzer_type.value,
                }
            )

            if not alive:
                # libFuzzer/AFL exits immediately on the first crash.
                log.info(
                    "execute_fuzzing.container_exited",
                    job_id=job_id,
                    elapsed=round(elapsed, 2),
                )
                break

        # Normal completion — stop, harvest, then remove. §1.3 ordering.
        await mgr.stop(job_id)
        # Harvest corpus BEFORE removal so seeds are not lost on next pivot.
        preserve_dir = payload.workdir / "corpus_preserved"
        try:
            await mgr.preserve_corpus(job_id, preserve_dir)
        except Exception as exc:
            log.warning(
                "execute_fuzzing.preserve_corpus_failed",
                job_id=job_id,
                error=str(exc),
            )
        # Now safe to remove the container.
        await mgr.cleanup(job_id)
    except asyncio.CancelledError:
        log.warning(
            "execute_fuzzing.cancelled",
            job_id=job_id,
            elapsed_seconds=round(time.monotonic() - started_monotonic, 2),
        )
        # Order matters: stop → cp → rm. Failure in any step must not skip rm.
        try:
            await mgr.stop(job_id)
            await mgr.preserve_corpus(job_id, payload.workdir / "corpus_preserved")
        finally:
            await mgr.cleanup(job_id)
        raise

    # Final crash-count read after container removal (files are still on host).
    with contextlib.suppress(OSError):
        crash_count_observed = max(
            crash_count_observed,
            sum(1 for p in crashes_dir.iterdir() if p.is_file()),
        )

    duration = time.monotonic() - started_monotonic
    output = ExecuteFuzzingOutput(
        logs_path=logs_path,
        crashes_dir=crashes_dir,
        crash_count=crash_count_observed,
        executions=last_executions,
        duration_seconds=round(duration, 3),
    )

    log.info(
        "execute_fuzzing.complete",
        workflow_id=info.workflow_id,
        job_id=job_id,
        executions=output.executions,
        coverage=last_coverage,
        crashes=output.crash_count,
        duration_seconds=output.duration_seconds,
    )

    # Persist run stats and propagate to Redis + R2.
    # Invariant: _real_execute is only entered when campaign_id is set.
    assert payload.campaign_id is not None, (
        "_real_execute must be invoked with a campaign_id"
    )
    campaign_id = payload.campaign_id
    await _persist_run(payload, output)
    from crashwise.core.redis import incr_exec_counter

    await incr_exec_counter(campaign_id, count=output.executions)

    from crashwise.core.storage import sync_directory

    crashes_prefix = (
        f"campaigns/{campaign_id}/crashes/iter-{payload.iteration}"
    )
    await sync_directory(crashes_dir, crashes_prefix, direction="up")

    return output


# ── Simulator (legacy; preserved for unit-test sandbox) ──────────────────────


async def _simulated_execute(
    payload: ExecuteFuzzingInput,
    logs_path: Path,
    crashes_dir: Path,
) -> ExecuteFuzzingOutput:
    """Deterministic simulator for the in-process Temporal sandbox.

    The simulator is what makes ``test_workflow.py`` resolve in
    milliseconds without Docker. It is preserved so the existing 374-test
    suite continues to pass; production code never enters this path
    because workflows always provide a ``campaign_id``.
    """
    info = activity.info()

    elapsed_resume: float = 0.0
    executions_resume: int = 0
    if info.heartbeat_details:
        try:
            prev = info.heartbeat_details[0]
            elapsed_resume = float(prev.get("elapsed_seconds", 0.0))
            executions_resume = int(prev.get("executions", 0))
        except (TypeError, ValueError, AttributeError, IndexError):
            log.warning("execute_fuzzing.invalid_heartbeat_details")

    started_monotonic = time.monotonic()
    elapsed = elapsed_resume
    executions = executions_resume

    try:
        while elapsed < float(payload.timeout_seconds):
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
        log.warning("execute_fuzzing.simulator_cancelled")
        raise

    duration = time.monotonic() - started_monotonic
    return ExecuteFuzzingOutput(
        logs_path=logs_path,
        crashes_dir=crashes_dir,
        crash_count=0,
        executions=executions,
        duration_seconds=round(duration, 3),
    )


async def _persist_run(
    payload: ExecuteFuzzingInput,
    output: ExecuteFuzzingOutput,
) -> None:
    """Write fuzzing run stats to the DB."""
    from datetime import UTC, datetime
    from uuid import UUID

    from crashwise.core.database import FuzzingRun, get_session

    if payload.campaign_id is None:
        return
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
    """Plausible exec counts per second per fuzzer for the legacy simulator.

    Retained for backwards compatibility — only used when no campaign_id
    is provided (i.e. inside the unit-test sandbox).
    """
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
