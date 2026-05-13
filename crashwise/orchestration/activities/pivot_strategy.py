# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``pivot_strategy`` activity — MAB-driven strategy switch for fuzz campaigns.

Triggered periodically by the workflow (e.g. every iteration) to evaluate
coverage growth and decide whether to pivot to a different fuzzing strategy.

Phase 21 wiring:
  1. Loads the latest MabState from Redis (if persisted).
  2. Evaluates the bandit + plateau detector.
  3. Persists the updated MabState back to Redis so the next call sees
     accumulated trial counts even across worker restarts.
"""

from __future__ import annotations

from temporalio import activity

from crashwise.agents.execution.strategist import evaluate_and_pivot as _evaluate_and_pivot
from crashwise.core.logging import get_logger
from crashwise.core.models import MabState, PivotStrategyInput, PivotStrategyOutput

log = get_logger(__name__)


@activity.defn(name="pivot_strategy")
async def pivot_strategy(payload: PivotStrategyInput) -> PivotStrategyOutput:
    """Evaluate MAB state and decide whether to pivot fuzzing strategy.

    Phase 21: the activity now reads ``MabState`` from Redis (when present)
    and writes the updated state back. Workflow callers no longer need to
    plumb the full state through every iteration — they pass an empty
    state on first call and Redis carries it forward.
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

    # Phase 21: try to hydrate from Redis; if found, the persisted state
    # supersedes the (potentially stale) one shipped in the payload.
    payload = await _hydrate_from_redis(payload)

    result = await _evaluate_and_pivot(payload)

    # Persist the updated state for the next iteration's pivot decision.
    await _persist_to_redis(payload.campaign_id, result.mab_state)

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


async def _hydrate_from_redis(payload: PivotStrategyInput) -> PivotStrategyInput:
    """If MabState exists in Redis (or DB fallback), prefer it over the payload's copy."""
    try:
        from crashwise.core.redis import load_mab_state

        raw = await load_mab_state(payload.campaign_id)
    except Exception as exc:  # Redis + DB both unreachable — fall through.
        log.warning("pivot_strategy.state_load_failed", error=str(exc)[:100])
        return payload
    if not raw:
        return payload
    try:
        loaded = MabState.model_validate_json(raw)
    except Exception as exc:
        log.warning("pivot_strategy.redis_state_invalid", error=str(exc))
        return payload
    # Preserve the arms shipped in the payload if Redis state has none
    # (defensive: stale Redis entries from older versions).
    if not loaded.arms and payload.mab_state.arms:
        loaded.arms = payload.mab_state.arms
    return payload.model_copy(update={"mab_state": loaded})


async def _persist_to_redis(campaign_id: str, state: MabState) -> None:
    """Save the updated MabState back to Redis (with DB fallback)."""
    try:
        from crashwise.core.redis import save_mab_state

        await save_mab_state(campaign_id, state.model_dump_json())
    except Exception as exc:
        log.warning(
            "pivot_strategy.state_persist_failed",
            campaign_id=campaign_id,
            error=str(exc)[:100],
        )


__all__ = ["pivot_strategy"]
