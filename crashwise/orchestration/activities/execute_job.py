# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``execute_job`` activity — unified fuzzing execution entry point.

Picks the right backend (Docker / QEMU / local) based on ``FuzzJob.backend``,
starts the environment, monitors it, and returns a structured result.

This is the activity that replaces the Phase-1 ``execute_fuzzing`` stub
for production deployments.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path

from temporalio import activity

from crashwise.core.logging import get_logger
from crashwise.core.models import ExecutionBackend, FuzzJob
from crashwise.execution.docker_manager import DockerManager
from crashwise.execution.monitor import DockerHealthChecker, QEMUHealthChecker, ResourceMonitor
from crashwise.execution.qemu_manager import QEMUManager

log = get_logger(__name__)


@activity.defn(name="execute_job")
async def execute_job(job: FuzzJob) -> dict[str, object]:
    """Run a fuzzing job inside an isolated environment.

    Returns a dict (serialised by the Pydantic data converter) with:
        - ``success``: bool
        - ``job_id``: str
        - ``crashes_found``: int
        - ``logs_path``: str
        - ``duration_seconds``: float
        - ``termination_reason``: str  (timeout | hang | oom | stall | completed)
    """
    info = activity.info()
    log.info(
        "execute_job.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        job_id=job.job_id,
        backend=job.backend.value,
        timeout=job.timeout_seconds,
    )

    started = asyncio.get_event_loop().time()

    # Pick manager.
    if job.backend == ExecutionBackend.DOCKER:
        result = await _run_docker(job)
    elif job.backend == ExecutionBackend.QEMU:
        result = await _run_qemu(job)
    else:
        result = await _run_local(job)

    duration = asyncio.get_event_loop().time() - started
    result["duration_seconds"] = round(duration, 2)

    log.info(
        "execute_job.complete",
        job_id=job.job_id,
        success=result["success"],
        reason=result["termination_reason"],
        duration=duration,
    )
    return result


# ── Backend runners ────────────────────────────────────────────────────────────
async def _run_docker(job: FuzzJob) -> dict[str, object]:
    manager = DockerManager()
    monitor: ResourceMonitor | None = None
    try:
        _container_id = await manager.start(job)

        # Start health monitor.
        # B9: pass an explicit fuzzer hint so AFL campaigns are parsed from
        # ``fuzzer_stats`` instead of the libFuzzer-only stdout regex.
        fuzzer_hint = "afl" if "afl" in job.harness_path.name.lower() else "libfuzzer"
        checker = DockerHealthChecker(
            manager, job.job_id, job.output_dir, fuzzer=fuzzer_hint
        )
        monitor = ResourceMonitor(
            job_id=job.job_id,
            check_fn=checker,  # type: ignore[arg-type]
        )
        monitor.start()

        # Wait for timeout or monitor event.
        await _wait_for_timeout_or_event(job, monitor)

        # Determine why we stopped.
        reason = _determine_reason(monitor)
        crashes = _count_crashes(job.output_dir)

        return {
            "success": True,
            "job_id": job.job_id,
            "crashes_found": crashes,
            "logs_path": str(job.output_dir / "fuzz.log"),
            "termination_reason": reason,
            "duration_seconds": 0.0,
        }
    except Exception as exc:
        log.error("execute_job.docker_failed", job_id=job.job_id, error=str(exc))
        return {
            "success": False,
            "job_id": job.job_id,
            "crashes_found": 0,
            "logs_path": str(job.output_dir / "fuzz.log"),
            "termination_reason": f"error: {exc}",
            "duration_seconds": 0.0,
        }
    finally:
        if monitor:
            await monitor.stop()
        await manager.stop(job.job_id)


async def _run_qemu(job: FuzzJob) -> dict[str, object]:
    manager = QEMUManager()
    monitor: ResourceMonitor | None = None
    try:
        _pid = await manager.start(job)

        serial_log = job.output_dir / "serial.log"
        checker = QEMUHealthChecker(manager, job.job_id, serial_log)
        monitor = ResourceMonitor(
            job_id=job.job_id,
            check_fn=checker,  # type: ignore[arg-type]
        )
        monitor.start()

        await _wait_for_timeout_or_event(job, monitor)
        reason = _determine_reason(monitor)

        return {
            "success": True,
            "job_id": job.job_id,
            "crashes_found": 0,  # Kernel crashes detected by kernel_monitor.
            "logs_path": str(serial_log),
            "termination_reason": reason,
            "duration_seconds": 0.0,
        }
    except Exception as exc:
        log.error("execute_job.qemu_failed", job_id=job.job_id, error=str(exc))
        return {
            "success": False,
            "job_id": job.job_id,
            "crashes_found": 0,
            "logs_path": str(job.output_dir / "serial.log"),
            "termination_reason": f"error: {exc}",
            "duration_seconds": 0.0,
        }
    finally:
        if monitor:
            await monitor.stop()
        await manager.stop(job.job_id)


async def _run_local(job: FuzzJob) -> dict[str, object]:
    # Phase-5 stub: local execution is not sandboxed; use Docker instead.
    log.warning("execute_job.local_unsupported", job_id=job.job_id)
    return {
        "success": False,
        "job_id": job.job_id,
        "crashes_found": 0,
        "logs_path": str(job.output_dir / "fuzz.log"),
        "termination_reason": "local backend not supported in Phase 5",
        "duration_seconds": 0.0,
    }


# ── Helpers ──────────────────────────────────────────────────────────────────
async def _wait_for_timeout_or_event(
    job: FuzzJob,
    monitor: ResourceMonitor,
) -> None:
    """Block until the job timeout expires or a monitor event fires."""
    timeout_task = asyncio.create_task(asyncio.sleep(job.timeout_seconds))
    event_task = asyncio.create_task(monitor.hang_event.wait())
    oom_task = asyncio.create_task(monitor.oom_event.wait())
    stall_task = asyncio.create_task(monitor.stall_event.wait())

    _, pending = await asyncio.wait(
        [timeout_task, event_task, oom_task, stall_task],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for t in pending:
        t.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await t


def _determine_reason(monitor: ResourceMonitor) -> str:
    if monitor.oom_event.is_set():
        return "oom"
    if monitor.hang_event.is_set():
        return "hang"
    if monitor.stall_event.is_set():
        return "stall"
    return "timeout"


def _count_crashes(output_dir: Path) -> int:
    crashes_dir = output_dir / "crashes"
    if not crashes_dir.exists():
        return 0
    return sum(1 for p in crashes_dir.iterdir() if p.is_file())


__all__ = ["execute_job"]
