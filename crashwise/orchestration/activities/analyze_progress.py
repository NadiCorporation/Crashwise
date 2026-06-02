# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``analyze_progress`` activity — feedback loop glue.

Reads fuzzer stats from the output directory, calls the feedback analyzer,
and returns a :class:`FuzzingCampaignState` that tells the workflow
whether to continue, mutate, or stop.

When a stall is detected, the agentic feedback analyzer is invoked to
replace the rule-based mutation hint with an LLM-powered diagnosis and
strategy. Falls back to rule-based hints when the LLM is unavailable.
"""

from __future__ import annotations

from pathlib import Path

from temporalio import activity

from crashwise.agents.feedback.analyzer import (
    agentic_enrich,
    analyze_campaign,
    parse_afl_stats,
    parse_libfuzzer_stats,
)
from crashwise.core.logging import get_logger
from crashwise.core.models import (
    AnalyzeProgressInput,
    CampaignStatus,
    CoverageReport,
    ExecuteFuzzingOutput,
    FuzzingCampaignState,
)

log = get_logger(__name__)


@activity.defn(name="analyze_progress")
async def analyze_progress(
    inp: AnalyzeProgressInput,
) -> FuzzingCampaignState:
    """Evaluate a completed fuzz iteration and decide the next step.

    Parameters
    ----------
    inp:
        Bundle of fuzz output and mutable campaign state.

    Returns
    -------
    Updated campaign state with ``should_continue``, ``mutation_hint``, and
    ``status`` fields populated.
    """
    fuzz_output = inp.fuzz_output
    campaign = inp.campaign
    info = activity.info()
    log.info(
        "analyze_progress.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        iteration=campaign.iteration,
        crashes=fuzz_output.crash_count,
    )

    # Parse coverage metrics from the output directory.
    coverage = _parse_coverage(fuzz_output)
    campaign.last_coverage = coverage
    campaign.crash_count = fuzz_output.crash_count

    # Propagate coverage data path so the evolution engine can use it.
    if fuzz_output.coverage_data_path is not None:
        campaign.last_coverage_data_path = fuzz_output.coverage_data_path

    # Record iteration history for the agentic analyzer.
    campaign.iteration_history.append({
        "iteration": campaign.iteration,
        "edges_hit": coverage.edges_hit,
        "exec_per_sec": coverage.exec_per_sec,
        "corpus_count": coverage.corpus_count,
        "stability": coverage.stability,
        "crash_count": fuzz_output.crash_count,
    })

    # Run the rule-based feedback analyzer.
    campaign = analyze_campaign(campaign)

    # Agentic enrichment: when stalled, invoke LLM-powered analysis.
    if campaign.status == CampaignStatus.STALLED:
        harness_code = _read_harness_code(campaign.harness_path)
        campaign = await agentic_enrich(
            campaign,
            harness_code=harness_code,
            fuzzer_type=_detect_fuzzer_type(fuzz_output),
            target_name=_extract_target_name(fuzz_output),
        )

    log.info(
        "analyze_progress.complete",
        iteration=campaign.iteration,
        status=campaign.status.value,
        should_continue=campaign.should_continue,
        hint=campaign.mutation_hint[:80] if campaign.mutation_hint else "",
    )
    return campaign


def _parse_coverage(fuzz_output: ExecuteFuzzingOutput) -> CoverageReport:
    """Best-effort coverage extraction from output artefacts."""
    # Try AFL++ stats first.
    afl_stats = fuzz_output.logs_path.parent / "fuzzer_stats"
    if afl_stats.exists():
        return parse_afl_stats(afl_stats)

    # Fall back to libFuzzer log.
    libfuzzer_log = fuzz_output.logs_path
    if libfuzzer_log.exists():
        return parse_libfuzzer_stats(libfuzzer_log)

    # No stats available — return empty report.
    return CoverageReport()


def _read_harness_code(harness_path: Path | None) -> str:
    """Read the current harness source code for agentic analysis."""
    if harness_path is None:
        return ""
    candidates = [
        harness_path.parent / "harness.cpp",
        harness_path.parent / "harness.c",
        harness_path.with_suffix(".cpp"),
        harness_path.with_suffix(".c"),
    ]
    if harness_path.suffix in (".cpp", ".c", ".cc"):
        candidates.insert(0, harness_path)
    for path in candidates:
        if path.exists():
            try:
                return path.read_text(encoding="utf-8", errors="replace")[:16_000]
            except OSError:
                continue
    return ""


def _detect_fuzzer_type(fuzz_output: ExecuteFuzzingOutput) -> str:
    """Detect fuzzer type from output artefacts."""
    afl_stats = fuzz_output.logs_path.parent / "fuzzer_stats"
    if afl_stats.exists():
        return "aflpp"
    return "libfuzzer"


def _extract_target_name(fuzz_output: ExecuteFuzzingOutput) -> str:
    """Extract target name from the logs path."""
    logs_dir = fuzz_output.logs_path.parent
    if logs_dir and logs_dir.name:
        return logs_dir.name
    return ""


__all__ = ["analyze_progress"]
