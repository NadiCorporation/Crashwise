# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``analyze_coverage_activity`` — Phase 21 wrapper around the coverage
analysis agent (Phase 18).

Used by :class:`MainFuzzingWorkflow` after a global plateau is detected,
to identify the most likely coverage blocker before invoking the
harness-evolution agent.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from temporalio import activity

from crashwise.agents.research.coverage_analyzer import analyze_coverage
from crashwise.core.logging import get_logger
from crashwise.core.models import CoverageAnalysis

log = get_logger(__name__)


class AnalyzeCoverageInput(BaseModel):
    """Input to the coverage analysis activity."""

    model_config = ConfigDict(extra="forbid")

    source_path: Path
    coverage_data: str = Field(default="", max_length=1_048_576)


@activity.defn(name="analyze_coverage_activity")
async def analyze_coverage_activity(
    payload: AnalyzeCoverageInput,
) -> CoverageAnalysis:
    """Analyse coverage and return ranked blockers."""
    info = activity.info()
    log.info(
        "analyze_coverage_activity.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        source_path=str(payload.source_path),
    )
    return await analyze_coverage(
        source_path=payload.source_path,
        coverage_data=payload.coverage_data,
    )


__all__ = ["AnalyzeCoverageInput", "analyze_coverage_activity"]
