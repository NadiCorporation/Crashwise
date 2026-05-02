# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Shared primitives: configuration, logging, and cross-cutting Pydantic models.

Anything imported by both ``orchestration`` and ``agents`` belongs here to
prevent circular dependencies.

The ``__init__`` is intentionally minimal — only re-exporting the pure
data-model namespace. Logging and config helpers are imported via their
fully-qualified module paths so workflow sandbox validation does not pull
``structlog`` (and its transitive ``rich``) into the deterministic context.
"""

from __future__ import annotations

from crashwise.core.models import (
    CrashSeverity,
    ExecuteFuzzingInput,
    ExecuteFuzzingOutput,
    FuzzerType,
    FuzzingInput,
    FuzzingOutput,
    SetupTargetInput,
    SetupTargetOutput,
    TriageInput,
    TriageOutput,
    WorkflowStage,
)

__all__ = [
    "CrashSeverity",
    "ExecuteFuzzingInput",
    "ExecuteFuzzingOutput",
    "FuzzerType",
    "FuzzingInput",
    "FuzzingOutput",
    "SetupTargetInput",
    "SetupTargetOutput",
    "TriageInput",
    "TriageOutput",
    "WorkflowStage",
]
