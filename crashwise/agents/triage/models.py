# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Pydantic models for the triage pipeline.

These models capture crash artefacts — GDB backtraces, ASAN reports,
register dumps — and the structured conclusions the triage agent draws
from them.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class BugType(StrEnum):
    """Known bug-class taxonomy used by the triage engine."""

    UNKNOWN = "unknown"
    USE_AFTER_FREE = "use-after-free"
    DOUBLE_FREE = "double-free"
    HEAP_BUFFER_OVERFLOW = "heap-buffer-overflow"
    STACK_BUFFER_OVERFLOW = "stack-buffer-overflow"
    BUFFER_OVERFLOW = "buffer-overflow"
    HEAP_USE_AFTER_FREE = "heap-use-after-free"
    OUT_OF_BOUNDS_READ = "out-of-bounds-read"
    OUT_OF_BOUNDS_WRITE = "out-of-bounds-write"
    INTEGER_OVERFLOW = "integer-overflow"
    NULL_POINTER_DEREF = "null-pointer-dereference"
    DIVIDE_BY_ZERO = "divide-by-zero"
    UNINITIALIZED_READ = "uninitialized-read"
    MEMORY_LEAK = "memory-leak"
    RACE_CONDITION = "race-condition"


class _StrictModel(BaseModel):
    """Strict, non-frozen base."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        arbitrary_types_allowed=True,
    )


class StackFrame(_StrictModel):
    """A single frame from a debugger backtrace."""

    function: str = Field(default="", description="Demangled function name")
    file: str = Field(default="", description="Source file path (if available)")
    line: int = Field(default=0, ge=0, description="Source line number")
    module: str = Field(default="", description="Binary / shared-object name")
    offset: str = Field(default="", description="Hex offset within function")
    pc: str = Field(default="", description="Program counter address")


class CrashReport(_StrictModel):
    """Raw crash data harvested from ASAN / GDB / libFuzzer output.

    Attributes
    ----------
    crash_id:
        Unique identifier (usually the fuzzer-generated crash filename).
    raw_text:
        The complete, unmodified crash log.
    signal:
        Unix signal number or name (e.g. ``SIGSEGV``, ``11``).
    stack_frames:
        Parsed backtrace frames, outermost first.
    registers:
        Key/value register dump (architecture-dependent).
    asan_output:
        Extracted ASAN report block (if present).
    gdb_output:
        Extracted GDB backtrace block (if present).
    crash_file:
        Path to the on-disk crash input that triggered this report.
    """

    crash_id: str = Field(..., description="Fuzzer crash filename / UUID")
    raw_text: str = ""
    signal: str = ""
    stack_frames: list[StackFrame] = Field(default_factory=list)
    registers: dict[str, str] = Field(default_factory=dict)
    asan_output: str = ""
    gdb_output: str = ""
    crash_file: Path | None = None


class TriageResult(_StrictModel):
    """Structured conclusion produced by the triage agent.

    Attributes
    ----------
    bug_type:
        The classified bug category.
    severity:
        Mapped from bug_type + exploitability heuristics.
    root_cause:
        One-paragraph human-readable explanation.
    confidence:
        0.0-1.0 score reflecting how certain the agent is.
    stack_hash:
        Normalised stack-trace SHA256 — used for deduplication.
    duplicate_of:
        If this crash matches a previously-seen hash, the prior crash_id.
    recommendations:
        Actionable next steps (e.g. "Audit free() in parser.c:42").
    """

    bug_type: BugType = BugType.UNKNOWN
    severity: str = "unknown"  # maps to CrashSeverity downstream
    root_cause: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    stack_hash: str = ""
    duplicate_of: str | None = None
    recommendations: list[str] = Field(default_factory=list)


__all__ = [
    "BugType",
    "CrashReport",
    "StackFrame",
    "TriageResult",
]
