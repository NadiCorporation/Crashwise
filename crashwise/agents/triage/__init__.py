# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Triage & Exploitability Engine (Phase 3).

LangGraph + LLM pipeline that consumes ASAN/GDB crash dumps, parses
registers and disassembly, classifies the bug (UAF, OOB, double-free, etc.),
and emits a root-cause analysis report.

Public API:
    :func:`triage_crash`  — analyse a single :class:`CrashReport`.
    :func:`triage_batch`  — analyse multiple reports with deduplication.
    :class:`CrashReport`  — raw crash data model.
    :class:`TriageResult`  — structured conclusion.
    :class:`BugType`       — bug-class taxonomy.
"""

from __future__ import annotations

from crashwise.agents.triage.analyzer import triage_batch, triage_crash
from crashwise.agents.triage.models import BugType, CrashReport, StackFrame, TriageResult

__all__ = [
    "BugType",
    "CrashReport",
    "StackFrame",
    "TriageResult",
    "triage_batch",
    "triage_crash",
]
