# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Phase 17 — Multi-Armed Bandit (MAB) Strategy Switcher."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from crashwise.agents.execution.strategist import (
    _DEFAULT_ARMS,
    _detect_plateau,
    _thompson_sample,
    _ucb1_score,
    _ucb1_select,
    evaluate_and_pivot,
    initialise_mab,
)
from crashwise.core.models import (
    FuzzerType,
    PivotStrategyInput,
    StrategyArm,
)
from crashwise.orchestration.activities.pivot_strategy import pivot_strategy

# ── MAB Initialisation ───────────────────────────────────────────────────────


def test_initialise_mab_default_arms() -> None:
    state = initialise_mab()
    assert len(state.arms) == 5
    arm_ids = {a.arm_id for a in state.arms}
    assert "afl_default" in arm_ids
    assert "afl_exploit" in arm_ids
    assert "libfuzzer_custom" in arm_ids
    assert "high_freq" in arm_ids
    assert "havoc_deep" in arm_ids


def test_initialise_mab_custom_arms() -> None:
    custom = [
        StrategyArm(arm_id="custom_1", name="Custom 1", fuzzer_type=FuzzerType.LIBFUZZER),
    ]
    state = initialise_mab(custom)
    assert len(state.arms) == 1
    assert state.arms[0].arm_id == "custom_1"


# ── Thompson Sampling ────────────────────────────────────────────────────────


def test_thompson_sample_prefers_high_success() -> None:
    state = initialise_mab()
    # Arm "a" has many successes, arm "b" has none.
    state.successes = {"afl_default": 50, "afl_exploit": 0}
    state.failures = {"afl_default": 10, "afl_exploit": 60}
    state.trials = {"afl_default": 60, "afl_exploit": 60}

    # Run many times and check the high-success arm wins most.
    wins: dict[str, int] = {}
    for _ in range(100):
        arm = _thompson_sample(state)
        wins[arm] = wins.get(arm, 0) + 1

    assert wins.get("afl_default", 0) > wins.get("afl_exploit", 0)


def test_thompson_sample_explores_untried() -> None:
    state = initialise_mab()
    # All arms have zero trials — should pick randomly.
    selected = {_thompson_sample(state) for _ in range(50)}
    assert len(selected) > 1  # More than one arm explored.


# ── UCB1 ─────────────────────────────────────────────────────────────────────


def test_ucb1_score_unexplored_infinite() -> None:
    state = initialise_mab()
    score = _ucb1_score(state, "afl_default")
    assert score == float("inf")


def test_ucb1_score_higher_with_success() -> None:
    state = initialise_mab()
    state.trials = {"afl_default": 10, "afl_exploit": 10}
    state.successes = {"afl_default": 8, "afl_exploit": 2}
    state.failures = {"afl_default": 2, "afl_exploit": 8}

    score_default = _ucb1_score(state, "afl_default")
    score_exploit = _ucb1_score(state, "afl_exploit")
    assert score_default > score_exploit


def test_ucb1_select_picks_best() -> None:
    state = initialise_mab()
    state.trials = {"afl_default": 10, "afl_exploit": 10, "libfuzzer_custom": 0}
    state.successes = {"afl_default": 2, "afl_exploit": 8}
    state.failures = {"afl_default": 8, "afl_exploit": 2}

    best = _ucb1_select(state)
    # UCB1 should pick afl_exploit (high reward) or libfuzzer_custom (unexplored).
    assert best in ("afl_exploit", "libfuzzer_custom")


# ── Plateau Detection ────────────────────────────────────────────────────────


def test_detect_plateau_true() -> None:
    now = time.time()
    history = [
        (now - 1800, 1000),  # 30 min ago
        (now - 900, 1001),   # 15 min ago
        (now - 300, 1001),   # 5 min ago
        (now, 1002),         # now
    ]
    assert _detect_plateau(history, window_minutes=30.0, threshold=0.01) is True


def test_detect_plateau_false_growth() -> None:
    now = time.time()
    history = [
        (now - 1800, 1000),
        (now, 1500),  # 50% growth
    ]
    assert _detect_plateau(history, window_minutes=30.0, threshold=0.01) is False


def test_detect_plateau_insufficient_history() -> None:
    assert _detect_plateau([], window_minutes=30.0) is False
    assert _detect_plateau([(time.time(), 100)], window_minutes=30.0) is False


def test_detect_plateau_zero_baseline() -> None:
    now = time.time()
    history = [
        (now - 1800, 0),
        (now, 0),
    ]
    assert _detect_plateau(history, window_minutes=30.0) is False


# ── evaluate_and_pivot Integration ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_evaluate_no_pivot_coverage_growing() -> None:
    state = initialise_mab()
    state.current_arm_id = "afl_default"
    state.coverage_history = [
        (time.time() - 1800, 1000),
        (time.time() - 900, 1200),
        (time.time(), 1500),  # 50% growth in 30 min
    ]

    result = await evaluate_and_pivot(
        PivotStrategyInput(
            campaign_id="test-1",
            mab_state=state,
            current_coverage=1500,
        )
    )

    assert result.should_pivot is False
    assert "still growing" in result.reason.lower() or "no plateau" in result.reason.lower()


@pytest.mark.asyncio
async def test_evaluate_pivot_on_plateau() -> None:
    state = initialise_mab()
    state.current_arm_id = "afl_default"
    now = time.time()
    state.coverage_history = [
        (now - 1800, 10000),
        (now - 900, 10001),
        (now - 300, 10001),
        (now, 10002),  # < 0.1% growth
    ]
    # Give afl_exploit some success history so it wins Thompson.
    state.successes = {"afl_default": 1, "afl_exploit": 10}
    state.failures = {"afl_default": 10, "afl_exploit": 1}
    state.trials = {"afl_default": 11, "afl_exploit": 11}

    result = await evaluate_and_pivot(
        PivotStrategyInput(
            campaign_id="test-2",
            mab_state=state,
            current_coverage=10002,
        )
    )

    assert result.should_pivot is True
    assert result.new_arm_id is not None
    assert result.new_arm_id != "afl_default"
    assert result.new_arm is not None
    assert result.mab_state.pivot_count == 1


@pytest.mark.asyncio
async def test_evaluate_same_arm_wins_no_pivot() -> None:
    state = initialise_mab()
    state.current_arm_id = "afl_default"
    now = time.time()
    state.coverage_history = [
        (now - 1800, 10000),
        (now, 10001),  # plateau
    ]
    # Make afl_default the clear winner across all arms.
    state.successes = {arm.arm_id: 0 for arm in state.arms}
    state.failures = {arm.arm_id: 100 for arm in state.arms}
    state.trials = {arm.arm_id: 100 for arm in state.arms}
    state.successes["afl_default"] = 100
    state.failures["afl_default"] = 0

    result = await evaluate_and_pivot(
        PivotStrategyInput(
            campaign_id="test-3",
            mab_state=state,
            current_coverage=10001,
        )
    )

    # Should NOT pivot because current arm is still best.
    assert result.should_pivot is False
    assert "still optimal" in result.reason.lower() or "same arm" in result.reason.lower()


@pytest.mark.asyncio
async def test_evaluate_records_trial() -> None:
    state = initialise_mab()
    state.current_arm_id = "afl_default"
    state.coverage_history = [
        (time.time() - 120, 1000),
        (time.time() - 60, 1050),
    ]

    await evaluate_and_pivot(
        PivotStrategyInput(
            campaign_id="test-4",
            mab_state=state,
            current_coverage=1100,  # greater than last history entry (1050)
        )
    )

    assert state.trials["afl_default"] == 1
    assert state.successes["afl_default"] == 1


@pytest.mark.asyncio
async def test_evaluate_ucb1_algorithm() -> None:
    state = initialise_mab()
    state.current_arm_id = "afl_default"
    now = time.time()
    state.coverage_history = [
        (now - 1800, 10000),
        (now, 10001),
    ]
    state.successes = {"afl_default": 1, "afl_exploit": 10}
    state.failures = {"afl_default": 10, "afl_exploit": 1}
    state.trials = {"afl_default": 11, "afl_exploit": 11}

    result = await evaluate_and_pivot(
        PivotStrategyInput(
            campaign_id="test-5",
            mab_state=state,
            current_coverage=10001,
        ),
        algorithm="ucb1",
    )

    assert result.should_pivot is True
    assert result.new_arm_id is not None


# ── MabState helpers ─────────────────────────────────────────────────────────


def test_mab_state_record_trial() -> None:
    state = initialise_mab()
    state.record_trial("afl_default", True)
    assert state.trials["afl_default"] == 1
    assert state.successes["afl_default"] == 1
    assert state.failures["afl_default"] == 0

    state.record_trial("afl_default", False)
    assert state.trials["afl_default"] == 2
    assert state.successes["afl_default"] == 1
    assert state.failures["afl_default"] == 1


def test_mab_state_is_plateaued_true() -> None:
    state = initialise_mab()
    now = time.time()
    state.coverage_history = [
        (now - 1800, 1000),
        (now - 900, 1001),
        (now, 1002),
    ]
    assert state.is_plateaued(window_minutes=30.0, threshold=0.01) is True


def test_mab_state_is_plateaued_false() -> None:
    state = initialise_mab()
    now = time.time()
    state.coverage_history = [
        (now - 1800, 1000),
        (now, 1500),
    ]
    assert state.is_plateaued(window_minutes=30.0, threshold=0.01) is False


# ── Default Arms Validation ──────────────────────────────────────────────────


def test_default_arms_have_required_fields() -> None:
    for arm in _DEFAULT_ARMS:
        assert arm.arm_id
        assert arm.name
        assert arm.fuzzer_type in {FuzzerType.AFLPP, FuzzerType.LIBFUZZER, FuzzerType.HONGGFUZZ}
        assert arm.cpu_limit > 0
        assert arm.memory_limit_mb >= 256


def test_default_arms_unique_ids() -> None:
    ids = [a.arm_id for a in _DEFAULT_ARMS]
    assert len(ids) == len(set(ids))


# ── Activity Integration ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pivot_strategy_activity_no_pivot() -> None:
    state = initialise_mab()
    state.current_arm_id = "afl_default"
    state.coverage_history = [
        (time.time() - 60, 1000),
        (time.time(), 1500),  # growing
    ]

    mock_info = MagicMock()
    mock_info.workflow_id = "test-wf"
    mock_info.attempt = 1

    with patch("crashwise.orchestration.activities.pivot_strategy.activity.info", return_value=mock_info):
        result = await pivot_strategy(
            PivotStrategyInput(
                campaign_id="test-act-1",
                mab_state=state,
                current_coverage=1500,
            )
        )

    assert result.should_pivot is False
    assert "growing" in result.reason.lower() or "no plateau" in result.reason.lower()


@pytest.mark.asyncio
async def test_pivot_strategy_activity_pivot() -> None:
    state = initialise_mab()
    state.current_arm_id = "afl_default"
    now = time.time()
    state.coverage_history = [
        (now - 1800, 10000),
        (now, 10001),
    ]
    state.successes = {"afl_default": 1, "afl_exploit": 10}
    state.failures = {"afl_default": 10, "afl_exploit": 1}
    state.trials = {"afl_default": 11, "afl_exploit": 11}

    mock_info = MagicMock()
    mock_info.workflow_id = "test-wf"
    mock_info.attempt = 1

    with patch("crashwise.orchestration.activities.pivot_strategy.activity.info", return_value=mock_info):
        result = await pivot_strategy(
            PivotStrategyInput(
                campaign_id="test-act-2",
                mab_state=state,
                current_coverage=10001,
            )
        )

    assert result.should_pivot is True
    assert result.new_arm_id is not None
    assert result.new_arm is not None
