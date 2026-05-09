# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``evolve_harness_activity`` — Phase 21 wiring for Phase 18.

Thin Temporal-activity wrapper around
:func:`crashwise.agents.harness_synth.evolution.evolve_harness`. Lets the
:class:`MainFuzzingWorkflow` invoke the harness-evolution agent
deterministically (the I/O lives here, not in the workflow body).
"""

from __future__ import annotations

from temporalio import activity

from crashwise.agents.harness_synth.evolution import evolve_harness as _evolve
from crashwise.core.logging import get_logger
from crashwise.core.models import EvolveHarnessInput, EvolveHarnessOutput

log = get_logger(__name__)


@activity.defn(name="evolve_harness_activity")
async def evolve_harness_activity(
    payload: EvolveHarnessInput,
) -> EvolveHarnessOutput:
    """Invoke the harness-evolution agent and return its rewrite."""
    info = activity.info()
    log.info(
        "evolve_harness_activity.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        iteration=payload.iteration,
        blocker_type=payload.blocker.blocker_type.value,
    )
    result = await _evolve(payload)
    log.info(
        "evolve_harness_activity.complete",
        workflow_id=info.workflow_id,
        confidence=result.confidence,
        bypass=result.bypass_strategy[:80],
    )
    return result


__all__ = ["evolve_harness_activity"]
