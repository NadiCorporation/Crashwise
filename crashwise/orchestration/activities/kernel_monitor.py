# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Kernel monitor activity — watches a QEMU/KVM target for kernel panics.

Phase 4 ships a stub that polls a log file for OOPS signatures. In
production this will be replaced by a live QEMU monitor socket + serial
console capture.
"""

from __future__ import annotations

from temporalio import activity

from crashwise.core.logging import get_logger
from crashwise.core.models import TriageInput, TriageOutput
from crashwise.kernelbridge.models import KernelCrash
from crashwise.kernelbridge.parser import parse_kernel_crash

log = get_logger(__name__)

# Poll interval when scanning a live QEMU serial log.
_POLL_INTERVAL_SECONDS: float = 2.0


@activity.defn(name="kernel_monitor")
async def kernel_monitor(payload: TriageInput) -> TriageOutput:
    """Poll ``payload.logs_path`` for kernel OOPS signatures.

    This is a Phase-4 stub: it reads any existing crash logs from
    ``payload.crashes_dir`` and returns a structured summary. A future
    iteration will spawn QEMU, drive syzkaller, and stream panics in
    real time via the Temporal heartbeat mechanism.
    """
    info = activity.info()
    log.info(
        "kernel_monitor.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        logs_path=str(payload.logs_path),
        crashes_dir=str(payload.crashes_dir),
    )

    crashes: list[KernelCrash] = []
    if payload.crashes_dir.exists():
        for entry in sorted(payload.crashes_dir.iterdir()):
            if not entry.is_file():
                continue
            raw = entry.read_text(encoding="utf-8", errors="replace")
            if "Oops" in raw or "BUG:" in raw or "Unable to handle" in raw:
                crash = parse_kernel_crash(
                    crash_id=entry.name,
                    oops_text=raw,
                    kernel_version="6.8.0-stub",
                )
                crashes.append(crash)
                log.info(
                    "kernel_monitor.found_crash",
                    crash_id=crash.crash_id,
                    bug_type=crash.oops.bug_type.value,
                    fault_addr=crash.oops.faulting_address,
                )

    summary_parts = [
        f"Kernel monitor scanned {payload.crashes_dir}: {len(crashes)} kernel crash(es) found."
    ]
    for c in crashes:
        summary_parts.append(
            f"  • {c.crash_id}: {c.oops.bug_type.value} at {c.oops.faulting_address or 'N/A'}"
        )

    output = TriageOutput(
        severity=_severity_from_crashes(crashes),
        summary="\n".join(summary_parts),
        triaged_crash_count=len(crashes),
    )

    log.info(
        "kernel_monitor.complete",
        workflow_id=info.workflow_id,
        crashes_found=len(crashes),
    )
    return output


def _severity_from_crashes(crashes: list[KernelCrash]) -> str:
    from crashwise.core.models import CrashSeverity

    if not crashes:
        return CrashSeverity.UNKNOWN.value
    # Map kernel bug types to coarse severity.
    critical = {"null-pointer-deref", "use-after-free", "double-free", "buffer-overflow"}
    high = {"stack-overflow", "race-condition", "info-leak"}
    severities = []
    for c in crashes:
        bt = c.oops.bug_type.value
        if bt in critical:
            severities.append(4)
        elif bt in high:
            severities.append(3)
        elif bt != "unknown":
            severities.append(2)
        else:
            severities.append(1)
    max_sev = max(severities)
    mapping = {1: "low", 2: "medium", 3: "high", 4: "critical"}
    return mapping.get(max_sev, "unknown")


__all__ = ["kernel_monitor"]
