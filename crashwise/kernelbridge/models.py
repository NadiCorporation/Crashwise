# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Pydantic models for the KernelBridge — Linux kernel fuzzing vertical.

These models capture kernel-space crash artefacts: OOPS reports, panic
logs, and syzkaller reproducer sequences. They are intentionally narrow
so they serialise cleanly across Temporal workflow boundaries.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class KernelBugType(StrEnum):
    """Known kernel bug-class taxonomy."""

    UNKNOWN = "unknown"
    NULL_POINTER_DEREF = "null-pointer-deref"
    USE_AFTER_FREE = "use-after-free"
    DOUBLE_FREE = "double-free"
    BUFFER_OVERFLOW = "buffer-overflow"
    STACK_OVERFLOW = "stack-overflow"
    INTEGER_OVERFLOW = "integer-overflow"
    RACE_CONDITION = "race-condition"
    INFO_LEAK = "info-leak"
    DEADLOCK = "deadlock"
    HANG = "hang"
    SYZ_FAIL = "syzkaller-failure"


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        arbitrary_types_allowed=True,
    )


class StackFrame(_StrictModel):
    """A single frame from a kernel backtrace."""

    function: str = ""
    file: str = ""
    line: int = Field(default=0, ge=0)
    module: str = ""
    offset: str = ""


class OopsReport(_StrictModel):
    """Parsed Linux kernel OOPS / panic report.

    Attributes
    ----------
    raw_text:
        The complete, unmodified OOPS log.
    bug_type:
        Heuristic classification derived from the OOPS signature.
    faulting_address:
        The address that caused the fault (e.g. ``0000000000000000``).
    crashing_instruction:
        The disassembly snippet at the faulting PC.
    register_state:
        Key/value dump of GPRs at crash time.
    stack_trace:
        Parsed kernel backtrace frames, innermost first.
    taint:
        Kernel taint flags (e.g. ``T:1234``).
    comm:
        The process/command name that triggered the fault.
    pid:
        PID of the faulting task.
    """

    raw_text: str = ""
    bug_type: KernelBugType = KernelBugType.UNKNOWN
    faulting_address: str = ""
    crashing_instruction: str = ""
    register_state: dict[str, str] = Field(default_factory=dict)
    stack_trace: list[StackFrame] = Field(default_factory=list)
    taint: str = ""
    comm: str = ""
    pid: int = Field(default=0, ge=0)


class SyscallSequence(_StrictModel):
    """A syzkaller reproducer — ordered list of syscalls with arguments.

    Attributes
    ----------
    syscalls:
        Ordered list of syscall names (e.g. ``["open", "ioctl", "mmap"]``).
    args:
        Per-syscall argument blobs (hex-encoded or raw strings).
    coverage:
        Optional KCOV edge-coverage bitmap / hit map.
    """

    syscalls: list[str] = Field(default_factory=list)
    args: list[list[str]] = Field(default_factory=list)
    coverage: dict[str, int] = Field(default_factory=dict)


class KernelCrash(_StrictModel):
    """Top-level kernel crash artefact.

    Attributes
    ----------
    crash_id:
        Unique identifier (syzkaller reproducer name or UUID).
    timestamp:
        UTC time the crash was observed.
    oops:
        Parsed OOPS report.
    reproducer:
        Optional syzkaller reproducer sequence.
    kernel_version:
        Target kernel version string (e.g. ``6.8.0``).
    config_hash:
        SHA256 of the kernel ``.config`` used for the run.
    qemu_args:
        QEMU command-line snapshot for reproducibility.
    triaged:
        Whether a human or agent has reviewed this crash.
    """

    crash_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    oops: OopsReport = Field(default_factory=OopsReport)
    reproducer: SyscallSequence | None = None
    kernel_version: str = ""
    config_hash: str = ""
    qemu_args: list[str] = Field(default_factory=list)
    triaged: bool = False


__all__ = [
    "KernelBugType",
    "KernelCrash",
    "OopsReport",
    "StackFrame",
    "SyscallSequence",
]
