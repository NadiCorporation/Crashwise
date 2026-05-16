# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``analyze_coverage_activity`` — Phase 21 wrapper around the coverage
analysis agent (Phase 18).

Used by :class:`MainFuzzingWorkflow` after a global plateau is detected,
to identify the most likely coverage blocker before invoking the
harness-evolution agent.

Supports ingestion of real line-level coverage from:
  - llvm-cov export JSON (via -fprofile-instr-generate)
  - sancov symbolized output
  - lcov/gcov DA: format
  - AFL++ fuzzer_stats (synthetic fallback)
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from temporalio import activity

from crashwise.agents.research.coverage_analyzer import analyze_coverage, generate_dictionary
from crashwise.core.logging import get_logger
from crashwise.core.models import CoverageAnalysis

log = get_logger(__name__)


class AnalyzeCoverageInput(BaseModel):
    """Input to the coverage analysis activity."""

    model_config = ConfigDict(extra="forbid")

    source_path: Path
    coverage_data: str = Field(default="", max_length=1_048_576)
    coverage_data_path: Path | None = Field(
        default=None,
        description="Path to coverage summary file produced by execute_fuzzing.",
    )


@activity.defn(name="analyze_coverage_activity")
async def analyze_coverage_activity(
    payload: AnalyzeCoverageInput,
) -> CoverageAnalysis:
    """Analyse coverage and return ranked blockers.

    Prefers real line-level coverage data from coverage_data_path when
    available. Falls back to inline coverage_data string, then to static
    analysis.
    """
    info = activity.info()
    log.info(
        "analyze_coverage_activity.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        source_path=str(payload.source_path),
        has_coverage_path=payload.coverage_data_path is not None,
    )

    # Load coverage data from file if path provided and file exists.
    coverage_text = payload.coverage_data
    if payload.coverage_data_path and payload.coverage_data_path.exists():
        try:
            coverage_text = payload.coverage_data_path.read_text(
                encoding="utf-8", errors="replace"
            )
            log.info(
                "analyze_coverage_activity.loaded_file",
                path=str(payload.coverage_data_path),
                size=len(coverage_text),
            )
        except OSError as exc:
            log.warning(
                "analyze_coverage_activity.file_read_failed",
                path=str(payload.coverage_data_path),
                error=str(exc),
            )

    analysis = await analyze_coverage(
        source_path=payload.source_path,
        coverage_data=coverage_text,
    )

    # Generate a fuzzer dictionary from identified blockers and source literals.
    # This feeds the MAB arm that passes -dict=custom.dict to libFuzzer/AFL++.
    if analysis.blockers:
        dict_content = generate_dictionary(payload.source_path, analysis.blockers)
        if dict_content:
            dict_path = payload.source_path.parent / "custom.dict"
            try:
                dict_path.write_text(dict_content, encoding="utf-8")
                log.info(
                    "analyze_coverage_activity.dict_written",
                    path=str(dict_path),
                    tokens=dict_content.count("\n") - 1,
                )
            except OSError as exc:
                log.warning(
                    "analyze_coverage_activity.dict_write_failed",
                    error=str(exc),
                )

    return analysis


__all__ = ["AnalyzeCoverageInput", "analyze_coverage_activity"]
