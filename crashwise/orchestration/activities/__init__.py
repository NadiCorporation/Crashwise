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
from crashwise.orchestration.activities.healing_activities import (
    run_adaptive_build_activity,
    run_autonomous_repair_activity,
)
from crashwise.orchestration.activities.hot_swap_harness import hot_swap_harness
from crashwise.orchestration.activities.inject_seeds import inject_seeds
from crashwise.orchestration.activities.kernel_monitor import kernel_monitor
from crashwise.orchestration.activities.mutate_harness import mutate_harness
from crashwise.orchestration.activities.notify_stakeholders import notify_stakeholders
from crashwise.orchestration.activities.persist_triaged_crash import (
    persist_triaged_crash,
)
from crashwise.orchestration.activities.pivot_strategy import pivot_strategy
from crashwise.orchestration.activities.profile_target import profile_target
from crashwise.orchestration.activities.read_coverage_data import read_coverage_data
from crashwise.orchestration.activities.seed_corpus import seed_corpus
from crashwise.orchestration.activities.setup_target import setup_target
from crashwise.orchestration.activities.store_campaign_knowledge import (
    store_campaign_knowledge,
)
from crashwise.orchestration.activities.synthesize_harness import (
    synthesize_harness_activity,
)
from crashwise.orchestration.activities.triage_results import triage_results
from crashwise.orchestration.activities.update_campaign import update_campaign_status
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
    synthesize_harness_activity,
    execute_fuzzing,
    execute_job,
    analyze_progress,
    analyze_coverage_activity,
    analyze_crash,
    mutate_harness,
    triage_results,
    persist_triaged_crash,
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
    update_campaign_status,
    # Phase 22 — CrashWise Healing Engine.
    run_adaptive_build_activity,
    run_autonomous_repair_activity,
    # Phase 23 — Cross-Campaign Learning.
    store_campaign_knowledge,
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
    "execute_job",
    "hot_swap_harness",
    "hot_swap_harness",
    "inject_seeds",
    "inject_seeds",
    "kernel_monitor",
    "kernel_monitor",
    "mutate_harness",
    "mutate_harness",
    "notify_stakeholders",
    "notify_stakeholders",
    "persist_triaged_crash",
    "persist_triaged_crash",
    "pivot_strategy",
    "pivot_strategy",
    "profile_target",
    "profile_target",
    "read_coverage_data",
    "read_coverage_data",
    "run_adaptive_build_activity",
    "run_adaptive_build_activity",
    "run_autonomous_repair_activity",
    "run_autonomous_repair_activity",
    "seed_corpus",
    "setup_target",
    "store_campaign_knowledge",
    "store_campaign_knowledge",
    "synthesize_harness_activity",
    "update_verification_status",
    "verify_poc",
    "verify_with_seed",
]
