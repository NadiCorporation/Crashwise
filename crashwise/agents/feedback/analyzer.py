# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Feedback analyzer — turns coverage metrics into harness-mutation hints.

The agent reads AFL++ / libFuzzer statistics, compares coverage across
iterations, and produces structured feedback that the harness-synthesis
agent consumes to refine the next harness version.

Autonomy guarantee: even without an LLM, the rule-based fallback produces
actionable hints (e.g. "coverage plateaued — try a different entry point").
"""

from __future__ import annotations

import re
from pathlib import Path

from crashwise.core.logging import get_logger
from crashwise.core.models import CampaignStatus, CoverageReport, FuzzingCampaignState

log = get_logger(__name__)

# Thresholds
_STALL_EXEC_PER_SEC: float = 10.0
_STALL_STABILITY: float = 50.0
_PLATEAU_THRESHOLD: int = 3  # iterations with < 1 % edge growth

# B10 — instrumentation-failure / cold-start grace period.
#
# Iterations 0 and 1 may legitimately report ``edges_hit == 0`` because
# AFL is still calibrating or libFuzzer hasn't emitted its first stats
# line. From iteration ``_INSTRUMENTATION_GRACE_ITERATIONS`` onward we
# treat zero coverage as a *failure of instrumentation* — the most
# common silent failure mode for libjxl-class targets — and mark the
# campaign STALLED so the workflow escalates to evolution / mutation
# instead of declaring a healthy run.
_INSTRUMENTATION_GRACE_ITERATIONS: int = 2


def parse_afl_stats(stats_path: Path) -> CoverageReport:
    """Parse an AFL++ ``fuzzer_stats`` file into a :class:`CoverageReport`."""
    report = CoverageReport()
    if not stats_path.exists():
        return report

    text = stats_path.read_text(encoding="utf-8", errors="replace")
    kv: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            kv[key.strip()] = val.strip()

    report.edges_hit = _int_or(kv.get("edges_found"), 0)
    report.total_execs = _int_or(kv.get("execs_done"), 0)
    report.exec_per_sec = _float_or(kv.get("execs_per_sec"), 0.0)
    report.stability = _float_or(kv.get("stability"), 0.0)
    report.map_density = _float_or(kv.get("map_density"), 0.0)
    report.pending_favs = _int_or(kv.get("pending_favs"), 0)
    report.corpus_count = _int_or(kv.get("corpus_count"), 0)
    return report


def parse_libfuzzer_stats(log_path: Path) -> CoverageReport:
    """Parse libFuzzer stdout log for coverage lines.

    Looks for lines like::

        #12345  DONE cov: 42 ft: 88 corp: 12/345b exec/s: 2500
    """
    report = CoverageReport()
    if not log_path.exists():
        return report

    text = log_path.read_text(encoding="utf-8", errors="replace")
    # Find the last stats line.
    for line in reversed(text.splitlines()):
        if "cov:" in line and "ft:" in line:
            m = re.search(r"cov:\s+(\d+)", line)
            if m:
                report.edges_hit = int(m.group(1))
            m = re.search(r"ft:\s+(\d+)", line)
            if m:
                report.blocks_hit = int(m.group(1))
            m = re.search(r"corp:\s+(\d+)", line)
            if m:
                report.corpus_count = int(m.group(1))
            m = re.search(r"exec/s:\s+(\d+)", line)
            if m:
                report.exec_per_sec = float(m.group(1))
            m = re.search(r"#(\d+)", line)
            if m:
                report.total_execs = int(m.group(1))
            break
    return report


def analyze_campaign(state: FuzzingCampaignState) -> FuzzingCampaignState:
    """Compare ``last_coverage`` to ``best_coverage`` and decide next action.

    Returns an updated ``state`` with ``should_continue`` and
    ``mutation_hint`` populated.
    """
    last = state.last_coverage
    best = state.best_coverage

    # Update best coverage if we improved.
    if last.edges_hit > best.edges_hit:
        state.best_coverage = last
        log.info(
            "feedback.new_best_coverage",
            iteration=state.iteration,
            edges=last.edges_hit,
            execs=last.total_execs,
        )

    # Crash found → stop loop, triage.
    if state.crash_count > 0:
        state.status = CampaignStatus.CRASHED
        state.should_continue = False
        state.mutation_hint = "Crash found — halting campaign for triage."
        return state

    # Max iterations reached.
    if state.iteration >= state.max_iterations - 1:
        state.status = CampaignStatus.COMPLETE
        state.should_continue = False
        state.mutation_hint = "Max iterations reached."
        return state

    # Detect stall conditions.
    stall_reasons: list[str] = []

    # 0. B10 — Zero-coverage past the warm-up window. This is *not* a
    # \"healthy\" condition; it almost always means the harness was built
    # without ``-fsanitize-coverage`` instrumentation, or the binary is
    # the trivial fallback emitted by ``_apply_fallback`` (nodes.py).
    # Surfacing this as STALLED forces the workflow to escalate to
    # mutation / evolution instead of running blind for hours.
    if (
        last.edges_hit == 0
        and state.iteration >= _INSTRUMENTATION_GRACE_ITERATIONS
    ):
        stall_reasons.append(
            "Zero coverage edges observed after warm-up — fuzzer is not "
            "instrumented or harness is a no-op (check "
            "-fsanitize-coverage flags and verify harness exercises the "
            "target)."
        )

    # 1. Execution rate collapsed.
    if last.exec_per_sec < _STALL_EXEC_PER_SEC and last.total_execs > 1000:
        stall_reasons.append(
            f"Execution rate collapsed to {last.exec_per_sec:.1f} exec/s"
        )

    # 2. Stability dropped (AFL-specific).
    if last.stability > 0 and last.stability < _STALL_STABILITY:
        stall_reasons.append(f"Stability degraded to {last.stability:.1f}%")

    # 3. Coverage plateau.
    if best.edges_hit > 0:
        growth = (last.edges_hit - best.edges_hit) / best.edges_hit
        if growth < 0.01:
            stall_reasons.append(
                f"Coverage plateaued at {best.edges_hit} edges "
                f"(last: {last.edges_hit})"
            )

    # 4. No pending favourites (AFL has exhausted interesting seeds).
    if last.pending_favs == 0 and last.corpus_count > 10:
        stall_reasons.append("No pending favourite seeds — AFL considers corpus exhausted")

    if stall_reasons:
        state.status = CampaignStatus.STALLED
        state.should_continue = True
        state.mutation_hint = _generate_mutation_hint(state, stall_reasons)
        log.warning(
            "feedback.stall_detected",
            iteration=state.iteration,
            reasons=stall_reasons,
            hint=state.mutation_hint[:120],
        )
        return state

    # Healthy run → continue with same harness.
    state.status = CampaignStatus.RUNNING
    state.should_continue = True
    state.mutation_hint = (
        f"Coverage growing ({best.edges_hit} edges, {last.exec_per_sec:.0f} exec/s). "
        "Continue current harness."
    )
    log.info(
        "feedback.healthy",
        iteration=state.iteration,
        edges=last.edges_hit,
        exec_per_sec=last.exec_per_sec,
    )
    return state


def _generate_mutation_hint(
    state: FuzzingCampaignState, reasons: list[str]
) -> str:
    """Produce a structured hint for the harness synth agent."""
    lines: list[str] = [
        "## FEEDBACK FROM ITERATION {iteration}",
        "The previous harness reached a stall. Specific issues:",
    ]
    for r in reasons:
        lines.append(f"  • {r}")

    # Suggest concrete mutations based on the stall profile.
    if any("Execution rate" in r for r in reasons):
        lines.append(
            "  → SUGGESTION: Remove expensive setup code from the harness; "
            "call the target function directly with minimal pre-conditions."
        )
    if any("Coverage plateaued" in r for r in reasons):
        lines.append(
            "  → SUGGESTION: The current entry point may be guarded by a "
            "length or magic-value check. Try fuzzing a *different* function "
            "in the same file, or bypass the guard by pre-seeding the "
            "corpus with a valid header."
        )
    if any("No pending favourite" in r for r in reasons):
        lines.append(
            "  → SUGGESTION: Corpus is exhausted. Either increase max_len, "
            "switch to a deeper call chain, or add a secondary target "
            "function that shares state with the primary one."
        )
    if any("Stability" in r for r in reasons):
        lines.append(
            "  → SUGGESTION: Stability loss indicates non-determinism. "
            "Avoid threads, timers, or RNG in the harness. "
            "Use a fixed seed if the target requires initialisation."
        )
    if any("Zero coverage" in r for r in reasons):
        lines.append(
            "  → SUGGESTION: Confirm the target is built with "
            "``-fsanitize-coverage=trace-pc-guard,trace-cmp`` AND that the "
            "harness actually calls into target code. If the harness was "
            "produced by the LLM evolution agent, it may have been "
            "replaced with the deterministic fallback (no-op). Force a "
            "re-evolution with an explicit BlockerType set."
        )

    lines.append(
        "Produce a revised harness that addresses at least one of the "
        "suggestions above. Keep the same target file but change the "
        "entry point or input pre-processing."
    )
    return "\n".join(lines).format(iteration=state.iteration)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _int_or(val: str | None, default: int) -> int:
    if val is None:
        return default
    try:
        return int(val.replace("%", "").replace(",", ""))
    except ValueError:
        return default


def _float_or(val: str | None, default: float) -> float:
    if val is None:
        return default
    try:
        return float(val.replace("%", "").replace(",", ""))
    except ValueError:
        return default


__all__ = ["analyze_campaign", "parse_afl_stats", "parse_libfuzzer_stats"]
