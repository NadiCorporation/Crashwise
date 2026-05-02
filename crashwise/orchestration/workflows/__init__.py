# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Temporal workflow definitions (Phase 1+).

Workflows MUST be deterministic. Side-effects belong in activities.
"""

from __future__ import annotations

from crashwise.orchestration.workflows.main import MainFuzzingWorkflow
from crashwise.orchestration.workflows.verify_patch import VerifyPatchWorkflow

# The canonical workflow registry passed into :class:`temporalio.worker.Worker`.
ALL_WORKFLOWS: list[type] = [MainFuzzingWorkflow, VerifyPatchWorkflow]

__all__ = ["ALL_WORKFLOWS", "MainFuzzingWorkflow", "VerifyPatchWorkflow"]
