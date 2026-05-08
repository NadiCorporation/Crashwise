# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Multi-Armed Bandit (MAB) Strategy Switcher — self-optimising fuzz campaign.

The strategist maintains a set of "arms" (different fuzzing configurations)
and uses Thompson Sampling to dynamically select the best-performing arm
based on coverage growth as the reward signal.

When coverage plateaus (< 1% new edges in 30 minutes), the strategist
recommends a pivot to a new arm. The execution layer then gracefully
stops the current container, preserves the corpus, and restarts with the
new configuration.

Arms (default set):
  1. ``afl_default``     — AFL++ with default mutation.
  2. ``afl_exploit``     — AFL++ in exploit mode (fast cal, skip CPU freq).
  3. ``libfuzzer_custom`` — libFuzzer with custom mutators and dict.
  4. ``high_freq``        — libFuzzer with max_len=4096, fast execution.
  5. ``havoc_deep``       — AFL++ with deep havoc, larger corpus.

Reward: new coverage edges discovered per time unit.
"""

from __future__ import annotations

import math
import random
from datetime import UTC, datetime

from crashwise.core.logging import get_logger
from crashwise.core.models import (
    FuzzerType,
    MabState,
    PivotStrategyInput,
    PivotStrategyOutput,
    StrategyArm,
)

log = get_logger(__name__)

# ── Default arm definitions ─────────────────────────────────────────────────

_DEFAULT_ARMS: list[StrategyArm] = [
    StrategyArm(
        arm_id="afl_default",
        name="AFL++ Default",
        fuzzer_type=FuzzerType.AFLPP,
        compiler_flags=["-O2", "-g"],
        env_vars={},
        cpu_limit=2.0,
        memory_limit_mb=2048,
        mutation_mode="default",
    ),
    StrategyArm(
        arm_id="afl_exploit",
        name="AFL++ Exploit Mode",
        fuzzer_type=FuzzerType.AFLPP,
        compiler_flags=["-O2", "-g"],
        env_vars={"AFL_FAST_CAL": "1", "AFL_SKIP_CPUFREQ": "1"},
        cpu_limit=3.0,
        memory_limit_mb=2048,
        mutation_mode="exploit",
    ),
    StrategyArm(
        arm_id="libfuzzer_custom",
        name="libFuzzer Custom Mutators",
        fuzzer_type=FuzzerType.LIBFUZZER,
        compiler_flags=["-O1", "-g", "-fsanitize=fuzzer,address,undefined"],
        env_vars={"LIBFUZZER_ARGS": "-max_len=4096 -dict=custom.dict"},
        cpu_limit=2.0,
        memory_limit_mb=3072,
        mutation_mode="custom",
    ),
    StrategyArm(
        arm_id="high_freq",
        name="High-Frequency Mutation",
        fuzzer_type=FuzzerType.LIBFUZZER,
        compiler_flags=["-O0", "-g", "-fsanitize=fuzzer,address"],
        env_vars={"LIBFUZZER_ARGS": "-max_len=4096 -max_total_time=0"},
        cpu_limit=4.0,
        memory_limit_mb=2048,
        mutation_mode="high_freq",
    ),
    StrategyArm(
        arm_id="havoc_deep",
        name="AFL++ Deep Havoc",
        fuzzer_type=FuzzerType.AFLPP,
        compiler_flags=["-O2", "-g"],
        env_vars={"AFL_HAVOC_DEPTH": "64", "AFL_EXPAND_HAVOC": "1"},
        cpu_limit=3.0,
        memory_limit_mb=4096,
        mutation_mode="havoc_deep",
    ),
]


# ── Thompson Sampling ────────────────────────────────────────────────────────

def _thompson_sample(state: MabState) -> str:
    """Thompson Sampling: sample from Beta(s+1, f+1) for each arm and pick max.

    The Beta distribution is the conjugate prior for Bernoulli trials, making
    it ideal for binary rewards (found new coverage / did not).
    """
    best_arm = ""
    best_sample = -1.0

    for arm in state.arms:
        arm_id = arm.arm_id
        s = state.successes.get(arm_id, 0)
        f = state.failures.get(arm_id, 0)
        # Beta(s+1, f+1) — add 1 for Laplace smoothing.
        sample = random.betavariate(s + 1, f + 1)
        if sample > best_sample:
            best_sample = sample
            best_arm = arm_id

    log.debug(
        "mab.thompson_sample",
        selected=best_arm,
        sample=round(best_sample, 4),
    )
    return best_arm


def _ucb1_score(state: MabState, arm_id: str) -> float:
    """UCB1 upper-confidence-bound score for ``arm_id``."""
    total_trials = sum(state.trials.values())
    n = state.trials.get(arm_id, 0)
    if n == 0:
        return float("inf")  # Unexplored arms get priority.
    s = state.successes.get(arm_id, 0)
    f = state.failures.get(arm_id, 0)
    # Empirical success rate.
    avg_reward = s / (s + f) if (s + f) > 0 else 0.0
    # Exploration bonus.
    bonus = math.sqrt(2 * math.log(total_trials) / n) if total_trials > 0 else 0.0
    return avg_reward + bonus


def _ucb1_select(state: MabState) -> str:
    """UCB1 selection: maximise empirical reward + exploration bonus."""
    best_arm = ""
    best_score = -1.0
    for arm in state.arms:
        score = _ucb1_score(state, arm.arm_id)
        if score > best_score:
            best_score = score
            best_arm = arm.arm_id
    log.debug("mab.ucb1_select", selected=best_arm, score=round(best_score, 4))
    return best_arm


# ── Plateau detection ────────────────────────────────────────────────────────

def _detect_plateau(
    coverage_history: list[tuple[float, int]],
    *,
    window_minutes: float = 30.0,
    threshold: float = 0.01,
) -> bool:
    """Return True if coverage growth < ``threshold`` over ``window_minutes``."""
    import time

    if len(coverage_history) < 2:
        return False
    cutoff = time.time() - window_minutes * 60
    recent = [(t, c) for t, c in coverage_history if t >= cutoff]
    if len(recent) < 2:
        return False
    first_cov = recent[0][1]
    last_cov = recent[-1][1]
    if first_cov == 0:
        return False
    growth = (last_cov - first_cov) / first_cov
    return growth < threshold


# ── Public API ───────────────────────────────────────────────────────────────

def initialise_mab(arms: list[StrategyArm] | None = None) -> MabState:
    """Create a fresh MAB state with the given (or default) arms."""
    arms = arms or _DEFAULT_ARMS
    state = MabState(arms=arms)
    for arm in arms:
        state.trials[arm.arm_id] = 0
        state.successes[arm.arm_id] = 0
        state.failures[arm.arm_id] = 0
    return state


async def evaluate_and_pivot(
    payload: PivotStrategyInput,
    *,
    algorithm: str = "thompson",
    plateau_window_minutes: float = 30.0,
    plateau_threshold: float = 0.01,
) -> PivotStrategyOutput:
    """Evaluate current MAB state and decide whether to pivot strategy.

    Parameters
    ----------
    payload:
        Current campaign state, MAB state, coverage, and elapsed time.
    algorithm:
        ``"thompson"`` (default) or ``"ucb1"``.
    plateau_window_minutes:
        Time window for plateau detection (default 30 min).
    plateau_threshold:
        Minimum coverage growth fraction to avoid plateau (default 1%).

    Returns
    -------
    PivotStrategyOutput with ``should_pivot``, ``new_arm_id``, and updated
    ``mab_state``.
    """
    state = payload.mab_state

    # 1. Record the latest coverage observation.
    import time

    state.coverage_history.append((time.time(), payload.current_coverage))
    # Keep last 1000 observations to bound memory.
    if len(state.coverage_history) > 1000:
        state.coverage_history = state.coverage_history[-1000:]

    # 2. Determine if the current arm found new coverage.
    current_arm = state.current_arm_id
    if current_arm:
        prev_coverage = (
            state.coverage_history[-2][1]
            if len(state.coverage_history) >= 2
            else payload.current_coverage
        )
        new_coverage_found = payload.current_coverage > prev_coverage
        state.record_trial(current_arm, new_coverage_found)

    # 3. Check for plateau.
    is_plateau = _detect_plateau(
        state.coverage_history,
        window_minutes=plateau_window_minutes,
        threshold=plateau_threshold,
    )

    if not is_plateau:
        log.info(
            "mab.no_pivot",
            coverage=payload.current_coverage,
            arm=current_arm,
            history_len=len(state.coverage_history),
        )
        return PivotStrategyOutput(
            should_pivot=False,
            mab_state=state,
            reason="Coverage still growing — no plateau detected",
        )

    # 4. Plateau detected — select new arm.
    if algorithm == "ucb1":
        new_arm_id = _ucb1_select(state)
    else:
        new_arm_id = _thompson_sample(state)

    if new_arm_id == current_arm:
        # Same arm won — stay the course but log it.
        log.info(
            "mab.same_arm_wins",
            arm=new_arm_id,
            reason="Current arm still best according to MAB",
        )
        return PivotStrategyOutput(
            should_pivot=False,
            mab_state=state,
            reason="Plateau detected, but current arm is still optimal",
        )

    # 5. Pivot to new arm.
    new_arm = next((a for a in state.arms if a.arm_id == new_arm_id), None)
    if new_arm is None:
        log.error("mab.arm_not_found", arm_id=new_arm_id)
        return PivotStrategyOutput(
            should_pivot=False,
            mab_state=state,
            reason=f"Selected arm {new_arm_id} not found in arm list",
        )

    state.current_arm_id = new_arm_id
    state.last_pivot_at = datetime.now(tz=UTC)
    state.pivot_count += 1

    log.info(
        "mab.pivot",
        from_arm=current_arm,
        to_arm=new_arm_id,
        pivot_count=state.pivot_count,
        coverage=payload.current_coverage,
        reason=f"Plateau detected (< {plateau_threshold*100:.0f}% growth in {plateau_window_minutes:.0f} min)",
    )

    return PivotStrategyOutput(
        should_pivot=True,
        new_arm_id=new_arm_id,
        new_arm=new_arm,
        mab_state=state,
        reason=f"Coverage plateau detected. Switching from {current_arm} to {new_arm_id} "
               f"({new_arm.name}) for better exploration.",
    )


__all__ = [
    "_DEFAULT_ARMS",
    "evaluate_and_pivot",
    "initialise_mab",
]
