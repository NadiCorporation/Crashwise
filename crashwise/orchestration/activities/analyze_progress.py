# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``analyze_progress`` activity — feedback loop glue.

Reads fuzzer stats from the output directory, calls the feedback analyzer,
and returns a :class:`FuzzingCampaignState` that tells the workflow
whether to continue, mutate, or stop.
"""

from __future__ import annotations

from temporalio import activity

from crashwise.agents.feedback.analyzer import (
    analyze_campaign,
    parse_afl_stats,
    parse_libfuzzer_stats,
)
from crashwise.core.logging import get_logger
from crashwise.core.models import (
    AnalyzeProgressInput,
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

    # Run the feedback analyzer.
    campaign = analyze_campaign(campaign)

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


__all__ = ["analyze_progress"]
