# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Tests for the Phase-6 feedback analyzer."""

from __future__ import annotations

from pathlib import Path

from crashwise.agents.feedback.analyzer import (
    analyze_campaign,
    parse_afl_stats,
    parse_libfuzzer_stats,
)
from crashwise.core.models import (
    CampaignStatus,
    CoverageReport,
    FuzzingCampaignState,
)


# ── AFL stats parser ─────────────────────────────────────────────────────────
def test_parse_afl_stats_full(tmp_path: Path) -> None:
    stats = tmp_path / "fuzzer_stats"
    stats.write_text(
        "edges_found     : 1234\n"
        "execs_done      : 567890\n"
        "execs_per_sec   : 2500.50\n"
        "stability       : 95.20%\n"
        "map_density     : 3.45%\n"
        "pending_favs    : 12\n"
        "corpus_count    : 256\n"
    )
    report = parse_afl_stats(stats)
    assert report.edges_hit == 1234
    assert report.total_execs == 567890
    assert report.exec_per_sec == 2500.5
    assert report.stability == 95.2
    assert report.map_density == 3.45
    assert report.pending_favs == 12
    assert report.corpus_count == 256


def test_parse_afl_stats_missing_file() -> None:
    report = parse_afl_stats(Path("/nonexistent"))
    assert report.edges_hit == 0


# ── libFuzzer stats parser ───────────────────────────────────────────────────
def test_parse_libfuzzer_stats(tmp_path: Path) -> None:
    log = tmp_path / "fuzz.log"
    log.write_text(
        "#1\tINITED cov: 4 ft: 4 corp: 1/1b exec/s: 0\n"
        "#1000\tDONE cov: 42 ft: 88 corp: 12/345b exec/s: 2500\n"
    )
    report = parse_libfuzzer_stats(log)
    assert report.edges_hit == 42
    assert report.blocks_hit == 88
    assert report.corpus_count == 12
    assert report.exec_per_sec == 2500.0
    assert report.total_execs == 1000


def test_parse_libfuzzer_stats_empty() -> None:
    report = parse_libfuzzer_stats(Path("/nonexistent"))
    assert report.edges_hit == 0


# ── Campaign analyzer ──────────────────────────────────────────────────────
def test_analyze_campaign_crash_halts() -> None:
    state = FuzzingCampaignState(
        iteration=0,
        last_coverage=CoverageReport(edges_hit=100, exec_per_sec=1000.0),
        crash_count=3,
    )
    result = analyze_campaign(state)
    assert result.status == CampaignStatus.CRASHED
    assert result.should_continue is False
    assert "Crash found" in result.mutation_hint


def test_analyze_campaign_max_iterations_halts() -> None:
    state = FuzzingCampaignState(
        iteration=4,
        max_iterations=5,
        last_coverage=CoverageReport(edges_hit=100, exec_per_sec=1000.0),
    )
    result = analyze_campaign(state)
    assert result.status == CampaignStatus.COMPLETE
    assert result.should_continue is False
    assert "Max iterations" in result.mutation_hint


def test_analyze_campaign_healthy_continues() -> None:
    state = FuzzingCampaignState(
        iteration=0,
        max_iterations=5,
        last_coverage=CoverageReport(edges_hit=100, exec_per_sec=1000.0),
        best_coverage=CoverageReport(edges_hit=50),
    )
    result = analyze_campaign(state)
    assert result.status == CampaignStatus.RUNNING
    assert result.should_continue is True
    assert "Coverage growing" in result.mutation_hint


def test_analyze_campaign_detects_stall_low_exec_rate() -> None:
    state = FuzzingCampaignState(
        iteration=1,
        max_iterations=5,
        last_coverage=CoverageReport(
            edges_hit=100,
            exec_per_sec=5.0,  # Below stall threshold
            total_execs=5000,
        ),
        best_coverage=CoverageReport(edges_hit=100),
    )
    result = analyze_campaign(state)
    assert result.status == CampaignStatus.STALLED
    assert result.should_continue is True
    assert "Execution rate collapsed" in result.mutation_hint


def test_analyze_campaign_detects_stall_coverage_plateau() -> None:
    state = FuzzingCampaignState(
        iteration=1,
        max_iterations=5,
        last_coverage=CoverageReport(edges_hit=100, exec_per_sec=100.0),
        best_coverage=CoverageReport(edges_hit=100),
        consecutive_plateau_count=2,  # Already 2 stalls; this call triggers threshold.
    )
    result = analyze_campaign(state)
    assert result.status == CampaignStatus.STALLED
    assert result.should_continue is True
    assert "Coverage plateaued" in result.mutation_hint


def test_analyze_campaign_detects_stall_no_pending_favs() -> None:
    state = FuzzingCampaignState(
        iteration=1,
        max_iterations=5,
        last_coverage=CoverageReport(
            edges_hit=100,
            exec_per_sec=100.0,
            pending_favs=0,
            corpus_count=50,
        ),
        best_coverage=CoverageReport(edges_hit=100),
    )
    result = analyze_campaign(state)
    assert result.status == CampaignStatus.STALLED
    assert result.should_continue is True
    assert "No pending favourite" in result.mutation_hint


def test_analyze_campaign_updates_best_coverage() -> None:
    state = FuzzingCampaignState(
        iteration=1,
        max_iterations=5,
        last_coverage=CoverageReport(edges_hit=200, exec_per_sec=1000.0),
        best_coverage=CoverageReport(edges_hit=100),
    )
    result = analyze_campaign(state)
    assert result.best_coverage.edges_hit == 200
    assert result.status == CampaignStatus.RUNNING


def test_analyze_campaign_stability_degradation() -> None:
    state = FuzzingCampaignState(
        iteration=1,
        max_iterations=5,
        last_coverage=CoverageReport(
            edges_hit=100,
            exec_per_sec=100.0,
            stability=30.0,  # Below 50% threshold
        ),
        best_coverage=CoverageReport(edges_hit=100),
    )
    result = analyze_campaign(state)
    assert result.status == CampaignStatus.STALLED
    assert "Stability degraded" in result.mutation_hint


# ── Harness synth feedback integration ───────────────────────────────────────
def test_harness_state_accepts_feedback() -> None:
    from crashwise.agents.harness_synth.state import HarnessState

    state = HarnessState(
        source_path=Path("/tmp/test.c"),
        workdir=Path("/tmp/out"),
        feedback="Coverage plateaued at 42 edges. Try a different entry point.",
    )
    assert state.feedback == "Coverage plateaued at 42 edges. Try a different entry point."
