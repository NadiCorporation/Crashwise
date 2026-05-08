# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``pivot_strategy`` activity — MAB-driven strategy switch for fuzz campaigns.

Triggered periodically by the workflow (e.g. every 5 minutes) to evaluate
coverage growth and decide whether to pivot to a different fuzzing strategy.

When a pivot is recommended, the activity:
  1. Stops the current fuzzing container.
  2. Preserves the corpus (copies seeds to a shared volume).
  3. Returns the new arm configuration so the workflow can restart with it.
"""

from __future__ import annotations

from temporalio import activity

from crashwise.agents.execution.strategist import evaluate_and_pivot as _evaluate_and_pivot
from crashwise.core.logging import get_logger
from crashwise.core.models import PivotStrategyInput, PivotStrategyOutput

log = get_logger(__name__)


@activity.defn(name="pivot_strategy")
async def pivot_strategy(payload: PivotStrategyInput) -> PivotStrategyOutput:
    """Evaluate MAB state and decide whether to pivot fuzzing strategy.

    Parameters
    ----------
    payload:
        Current campaign MAB state, coverage metrics, and elapsed time.

    Returns
    -------
    PivotStrategyOutput with ``should_pivot``, ``new_arm_id``, and updated
    ``mab_state``. If ``should_pivot`` is True, the workflow should stop the
    current fuzzer and restart with the new arm.
    """
    info = activity.info()
    log.info(
        "pivot_strategy.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        campaign_id=payload.campaign_id,
        current_coverage=payload.current_coverage,
        current_arm=payload.mab_state.current_arm_id,
    )

    result = await _evaluate_and_pivot(payload)

    if result.should_pivot:
        log.info(
            "pivot_strategy.recommend_pivot",
            campaign_id=payload.campaign_id,
            from_arm=payload.mab_state.current_arm_id,
            to_arm=result.new_arm_id,
            reason=result.reason,
        )
    else:
        log.info(
            "pivot_strategy.no_pivot",
            campaign_id=payload.campaign_id,
            current_arm=payload.mab_state.current_arm_id,
            reason=result.reason,
        )

    return result


__all__ = ["pivot_strategy"]
