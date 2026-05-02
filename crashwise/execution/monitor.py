# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Resource monitor for fuzzing environments.

Watches Docker containers and QEMU VMs for:
    • Hangs (no output / heartbeat for N seconds)
    • OOMs (container exits with code 137, QEMU killed by OOM-killer)
    • Stalled fuzzers (exec/s or coverage flatlined)

The monitor runs as an asyncio task alongside the fuzzer and signals
via an ``asyncio.Event`` when intervention is required.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from crashwise.core.logging import get_logger

log = get_logger(__name__)

# Defaults
_HANG_TIMEOUT_SECONDS: float = 120.0
_STALL_CHECK_INTERVAL: float = 30.0
_OOM_SIGNATURES = ("killed", "oom", "out of memory", "137")


class HealthSnapshot:
    """Point-in-time health metrics for a fuzzing worker."""

    def __init__(
        self,
        *,
        timestamp: float,
        alive: bool,
        cpu_percent: str = "N/A",
        memory: str = "N/A",
        pids: str = "N/A",
        last_output_line: str = "",
        exec_per_sec: float = 0.0,
    ) -> None:
        self.timestamp = timestamp
        self.alive = alive
        self.cpu_percent = cpu_percent
        self.memory = memory
        self.pids = pids
        self.last_output_line = last_output_line
        self.exec_per_sec = exec_per_sec


class ResourceMonitor:
    """Monitors a single fuzzing job and detects unhealthy states.

    Usage::

        monitor = ResourceMonitor(job_id="abc", check_fn=my_check)
        monitor.start()
        ...
        if monitor.hang_event.is_set():
            await manager.stop(job_id)
    """

    def __init__(
        self,
        *,
        job_id: str,
        check_fn: Callable[[], asyncio.Future[HealthSnapshot]],
        hang_timeout: float = _HANG_TIMEOUT_SECONDS,
        stall_interval: float = _STALL_CHECK_INTERVAL,
    ) -> None:
        self.job_id = job_id
        self._check_fn = check_fn
        self._hang_timeout = hang_timeout
        self._stall_interval = stall_interval
        self._task: asyncio.Task[Any] | None = None
        self.hang_event = asyncio.Event()
        self.oom_event = asyncio.Event()
        self.stall_event = asyncio.Event()
        self._history: list[HealthSnapshot] = []

    def start(self) -> None:
        """Begin monitoring in a background task."""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop())
        log.info("monitor.start", job_id=self.job_id)

    async def stop(self) -> None:
        """Cancel the monitor loop."""
        if self._task and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        log.info("monitor.stop", job_id=self.job_id)

    async def _loop(self) -> None:
        """Main monitoring loop."""
        last_output = ""
        last_output_time = time.monotonic()

        while True:
            try:
                snap = await self._check_fn()
            except Exception as exc:
                log.warning("monitor.check_failed", job_id=self.job_id, error=str(exc))
                await asyncio.sleep(self._stall_interval)
                continue

            self._history.append(snap)
            now = time.monotonic()

            # ── Hang detection ─────────────────────────────────────────────
            if snap.last_output_line != last_output:
                last_output = snap.last_output_line
                last_output_time = now
            elif now - last_output_time > self._hang_timeout:
                log.warning(
                    "monitor.hang_detected",
                    job_id=self.job_id,
                    idle_seconds=round(now - last_output_time, 1),
                )
                self.hang_event.set()
                return

            # ── OOM detection ──────────────────────────────────────────────
            if not snap.alive:
                # Check recent logs for OOM signatures.
                logs_lower = snap.last_output_line.lower()
                if any(sig in logs_lower for sig in _OOM_SIGNATURES):
                    log.warning("monitor.oom_detected", job_id=self.job_id)
                    self.oom_event.set()
                    return

            # ── Stall detection (coverage/exec flatline) ───────────────────
            if len(self._history) >= 3:
                recent = self._history[-3:]
                exec_rates = [s.exec_per_sec for s in recent]
                if all(r == 0.0 for r in exec_rates) and snap.alive:
                    log.warning(
                        "monitor.stall_detected",
                        job_id=self.job_id,
                        checks=len(recent),
                    )
                    self.stall_event.set()
                    return

            await asyncio.sleep(self._stall_interval)


class DockerHealthChecker:
    """Adapter that turns a ``DockerManager`` into a ``ResourceMonitor`` check."""

    def __init__(self, manager: Any, job_id: str, output_dir: Path) -> None:
        self._manager = manager
        self._job_id = job_id
        self._output_dir = output_dir

    async def __call__(self) -> HealthSnapshot:
        alive = await self._manager.is_alive(self._job_id)
        stats = await self._manager.stats(self._job_id) if alive else {}
        logs = await self._manager.logs(self._job_id, tail=1) if alive else ""
        return HealthSnapshot(
            timestamp=time.monotonic(),
            alive=alive,
            cpu_percent=stats.get("cpu_percent", "N/A"),
            memory=stats.get("memory", "N/A"),
            pids=stats.get("pids", "N/A"),
            last_output_line=logs.strip().splitlines()[-1] if logs else "",
            exec_per_sec=0.0,  # TODO: parse AFL/libFuzzer stats file.
        )


class QEMUHealthChecker:
    """Adapter that turns a ``QEMUManager`` into a ``ResourceMonitor`` check."""

    def __init__(self, manager: Any, job_id: str, serial_log: Path) -> None:
        self._manager = manager
        self._job_id = job_id
        self._serial_log = serial_log

    async def __call__(self) -> HealthSnapshot:
        alive = await self._manager.is_alive(self._job_id)
        log_text = ""
        if self._serial_log.exists():
            log_text = self._serial_log.read_text(encoding="utf-8", errors="replace")
        last_line = log_text.strip().splitlines()[-1] if log_text else ""
        return HealthSnapshot(
            timestamp=time.monotonic(),
            alive=alive,
            last_output_line=last_line,
            exec_per_sec=0.0,
        )


__all__ = [
    "DockerHealthChecker",
    "HealthSnapshot",
    "QEMUHealthChecker",
    "ResourceMonitor",
]
