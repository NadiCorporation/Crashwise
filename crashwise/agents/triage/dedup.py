# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Crash deduplication via normalised stack-trace hashing.

Two crashes are considered duplicates when their *normalised* stack traces
hash to the same value. Normalisation strips volatile artefacts:
hex addresses, pointer values, and absolute paths — keeping only the
structural skeleton (module + function + offset pattern).
"""

from __future__ import annotations

import hashlib
import re

from crashwise.agents.triage.models import CrashReport, StackFrame, TriageResult
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# Patterns to strip during normalisation.
_HEX_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_ABS_PATH_RE = re.compile(r"/[^\s:]+(?=:\d+)?")
_PTR_RE = re.compile(r"\b0x[0-9a-fA-F]+\b|\bp\d+=0x[0-9a-fA-F]+\b")


def normalise_frame(frame: StackFrame) -> str:
    """Return a stable string representation of a single frame."""
    # Prefer function name; fall back to module+offset.
    func = frame.function.strip() if frame.function else ""
    if not func:
        func = f"{frame.module or '??'}+{frame.offset or '??'}"
    # Strip template noise and argument lists for stability.
    func = re.sub(r"<[^>]+>", "", func)
    func = re.sub(r"\([^)]*\)", "", func)
    func = func.strip() or "??"
    file_hint = ""
    if frame.file:
        # Keep only the basename for stability across build machines.
        basename = frame.file.split("/")[-1].split("\\")[-1]
        if basename:
            file_hint = f"@{basename}:{frame.line}"
    return f"{func}{file_hint}"


def normalise_stack(report: CrashReport) -> str:
    """Produce a canonical string from the backtrace suitable for hashing."""
    lines: list[str] = []
    for frame in report.stack_frames:
        lines.append(normalise_frame(frame))
    raw = "\n".join(lines)
    # Second pass: strip any remaining hex addresses that snuck into file
    # paths or function names.
    raw = _HEX_ADDR_RE.sub("<addr>", raw)
    raw = _ABS_PATH_RE.sub("<path>", raw)
    return raw


def compute_stack_hash(report: CrashReport) -> str:
    """SHA256 of the normalised stack trace."""
    normalised = normalise_stack(report)
    digest = hashlib.sha256(normalised.encode("utf-8"), usedforsecurity=False).hexdigest()
    log.debug("triage.dedup.hash", crash_id=report.crash_id, hash=digest[:16])
    return digest


class CrashDeduper:
    """Stateful deduplicator that tracks seen stack hashes.

    In production this would be backed by Redis / Temporal search
    attributes. For Phase 3 we keep an in-memory set scoped to the
    current worker process.
    """

    def __init__(self) -> None:
        self._seen: dict[str, str] = {}  # hash -> first crash_id

    def check(self, report: CrashReport) -> TriageResult:
        """Hash the report and return a :class:`TriageResult` with dedup info."""
        stack_hash = compute_stack_hash(report)
        duplicate_of = self._seen.get(stack_hash)
        if duplicate_of is None:
            self._seen[stack_hash] = report.crash_id
        return TriageResult(
            stack_hash=stack_hash,
            duplicate_of=duplicate_of,
        )

    def reset(self) -> None:
        """Clear the dedup table (useful between workflow runs in tests)."""
        self._seen.clear()


__all__ = ["CrashDeduper", "compute_stack_hash", "normalise_frame", "normalise_stack"]
