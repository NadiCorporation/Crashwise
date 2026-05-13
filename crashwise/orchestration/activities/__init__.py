# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Temporal activities (Phase 1+).

Activities are where I/O and non-determinism live: compilation, fuzz runs,
crash collection, LLM calls, filesystem writes.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from crashwise.orchestration.activities.analyze_coverage import (
    analyze_coverage_activity,
)
from crashwise.orchestration.activities.analyze_crash import analyze_crash
from crashwise.orchestration.activities.analyze_progress import analyze_progress
from crashwise.orchestration.activities.evolve_harness import (
    evolve_harness_activity,
)
from crashwise.orchestration.activities.execute_fuzzing import execute_fuzzing
from crashwise.orchestration.activities.execute_job import execute_job
from crashwise.orchestration.activities.inject_seeds import inject_seeds
from crashwise.orchestration.activities.kernel_monitor import kernel_monitor
from crashwise.orchestration.activities.mutate_harness import mutate_harness
from crashwise.orchestration.activities.notify_stakeholders import notify_stakeholders
from crashwise.orchestration.activities.hot_swap_harness import hot_swap_harness
from crashwise.orchestration.activities.pivot_strategy import pivot_strategy
from crashwise.orchestration.activities.profile_target import profile_target
from crashwise.orchestration.activities.read_coverage_data import read_coverage_data
from crashwise.orchestration.activities.seed_corpus import seed_corpus
from crashwise.orchestration.activities.setup_target import setup_target
from crashwise.orchestration.activities.triage_results import triage_results
from crashwise.orchestration.activities.verify_patch import (
    apply_patch,
    build_patched,
    update_verification_status,
    verify_with_seed,
)
from crashwise.orchestration.activities.verify_poc import verify_poc

# The canonical activity registry passed into :class:`temporalio.worker.Worker`.
ALL_ACTIVITIES: list[Callable[..., Any]] = [
    setup_target,
    seed_corpus,
    execute_fuzzing,
    execute_job,
    analyze_progress,
    analyze_coverage_activity,
    analyze_crash,
    mutate_harness,
    triage_results,
    kernel_monitor,
    apply_patch,
    build_patched,
    verify_with_seed,
    update_verification_status,
    hot_swap_harness,
    inject_seeds,
    notify_stakeholders,
    pivot_strategy,
    profile_target,
    read_coverage_data,
    evolve_harness_activity,
    verify_poc,
]

__all__ = [
    "ALL_ACTIVITIES",
    "analyze_coverage_activity",
    "analyze_crash",
    "analyze_progress",
    "apply_patch",
    "build_patched",
    "evolve_harness_activity",
    "execute_fuzzing",
    "execute_job",
    "inject_seeds",
    "kernel_monitor",
    "mutate_harness",
    "hot_swap_harness",
    "notify_stakeholders",
    "pivot_strategy",
    "profile_target",
    "read_coverage_data",
    "update_verification_status",
    "verify_with_seed",
    "verify_poc",
]
