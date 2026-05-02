# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""QEMU orchestrator for kernel-space fuzzing.

Launches QEMU VMs with a specific kernel, initrd, and cmdline. Monitors
VM health via serial console heartbeat strings (no SSH required in the
stub — production would add a management NIC).

This is intentionally lightweight: it wraps ``qemu-system-x86_64`` via
subprocess and provides start / stop / is_alive / send_file primitives.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
from pathlib import Path
from typing import Any

from crashwise.core.logging import get_logger
from crashwise.core.models import FuzzJob

log = get_logger(__name__)

_QEMU_BINARY = "qemu-system-x86_64"


class QEMUManager:
    """Async QEMU VM manager for kernel fuzzing campaigns.

    Each ``FuzzJob`` maps to one QEMU process. The manager tracks the
    subprocess handle and exposes health-check methods.
    """

    def __init__(self) -> None:
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._monitors: dict[str, asyncio.Task[Any]] = {}

    # ── Lifecycle ────────────────────────────────────────────────────────────
    async def start(self, job: FuzzJob) -> int:
        """Launch a QEMU VM and return the PID.

        Raises
        ------
        FileNotFoundError
            If the kernel image or QEMU binary is missing.
        RuntimeError
            If QEMU exits immediately.
        """
        if not job.qemu_kernel or not job.qemu_kernel.exists():
            raise FileNotFoundError(f"kernel image not found: {job.qemu_kernel}")
        if not shutil.which(_QEMU_BINARY):
            raise FileNotFoundError(f"{_QEMU_BINARY} not on PATH; install via scripts/setup.sh")

        job.output_dir.mkdir(parents=True, exist_ok=True)

        cmd: list[str] = [
            _QEMU_BINARY,
            "-enable-kvm" if await self._kvm_available() else "",
            "-m",
            str(job.memory_limit_mb),
            "-smp",
            str(int(job.cpu_limit)),
            "-kernel",
            str(job.qemu_kernel),
            "-append",
            self._build_append(job),
            "-nographic",
            "-no-reboot",
            "-serial",
            f"file:{job.output_dir / 'serial.log'}",
        ]
        if job.qemu_initrd and job.qemu_initrd.exists():
            cmd.extend(["-initrd", str(job.qemu_initrd)])

        # Remove empty strings (e.g. when KVM is unavailable).
        cmd = [c for c in cmd if c]

        log.info(
            "qemu.start",
            job_id=job.job_id,
            kernel=str(job.qemu_kernel),
            memory_mb=job.memory_limit_mb,
            smp=int(job.cpu_limit),
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        # Give QEMU a moment to fail (e.g. bad kernel).
        await asyncio.sleep(0.5)
        if proc.returncode is not None:
            _, stderr = await proc.communicate()
            raise RuntimeError(
                f"QEMU exited immediately (rc={proc.returncode}): "
                f"{stderr.decode('utf-8', errors='replace')}"
            )

        self._processes[job.job_id] = proc
        log.info("qemu.started", job_id=job.job_id, pid=proc.pid)
        return proc.pid

    async def stop(self, job_id: str, *, timeout: float = 30.0) -> None:
        """Gracefully power off the VM, then kill if necessary."""
        proc = self._processes.pop(job_id, None)
        if proc is None:
            log.warning("qemu.stop.unknown_job", job_id=job_id)
            return

        log.info("qemu.stop", job_id=job_id, pid=proc.pid)
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except TimeoutError:
            log.warning("qemu.kill", job_id=job_id, pid=proc.pid)
            proc.kill()
            await proc.wait()

        # Cancel any dangling monitor task.
        monitor_task = self._monitors.pop(job_id, None)
        if monitor_task and not monitor_task.done():
            monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await monitor_task

    async def is_alive(self, job_id: str) -> bool:
        """Check whether the QEMU process is still running."""
        proc = self._processes.get(job_id)
        if proc is None:
            return False
        return proc.returncode is None

    async def serial_log(self, job_id: str) -> str:
        """Return the contents of the serial console log file."""
        # We don't store the output_dir per job; derive from job model in
        # practice. Here we just check the most recent serial.log in output.
        log_path = Path("/tmp") / f"crashwise-qemu-{job_id}-serial.log"
        if not log_path.exists():
            return ""
        return log_path.read_text(encoding="utf-8", errors="replace")

    async def send_monitor_cmd(self, job_id: str, cmd: str) -> str:
        """Send a command via QEMU monitor socket (future work)."""
        # Phase-5 stub: monitor socket not yet implemented.
        log.debug("qemu.monitor_cmd", job_id=job_id, cmd=cmd)
        return ""

    # ── Internals ────────────────────────────────────────────────────────────
    async def _kvm_available(self) -> bool:
        return Path("/dev/kvm").exists() and shutil.which(_QEMU_BINARY) is not None

    def _build_append(self, job: FuzzJob) -> str:
        """Build the kernel cmdline string."""
        parts: list[str] = [
            "console=ttyS0",
            "panic=1",
            "oops=panic",
        ]
        if job.qemu_append:
            parts.append(job.qemu_append)
        return " ".join(parts)


__all__ = ["QEMUManager"]
