# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``mutate_harness`` activity — re-synthesize a harness with feedback.

Called by the workflow loop when the coverage analyzer detects a stall.
It re-runs the Phase-2 harness synthesis agent with the mutation hint
injected into the LLM prompt, producing a revised harness for the next
fuzzing iteration.
"""

from __future__ import annotations

from pathlib import Path

from temporalio import activity

from crashwise.core.logging import get_logger
from crashwise.core.models import SetupTargetOutput

log = get_logger(__name__)


@activity.defn(name="mutate_harness")
async def mutate_harness(
    workdir: Path,
    harness_path: Path,
    feedback: str,
) -> SetupTargetOutput:
    """Re-synthesize the harness incorporating structured feedback.

    Parameters
    ----------
    workdir:
        Sandbox directory where the harness lives.
    harness_path:
        Current harness binary (used to locate the source file).
    feedback:
        Structured hint from the coverage analyzer.

    Returns
    -------
    A :class:`SetupTargetOutput` with the new ``harness_path``.
    """
    info = activity.info()
    log.info(
        "mutate_harness.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        workdir=str(workdir),
        feedback_preview=feedback[:120],
    )

    # Lazy import to avoid pulling LangGraph into workflow validation.
    from crashwise.agents.harness_synth import synthesize_harness

    # Derive the source path from the harness directory structure.
    # The harness synth agent writes harness.cpp in a subdir; we assume
    # the original target source is in the parent workdir.
    source_path = workdir / "target.cpp"
    if not source_path.exists():
        # Fallback: use the harness source itself as the target.
        source_path = harness_path.parent / "harness.cpp"

    synth_workdir = workdir / f"harness-mutated-{info.attempt}"
    result = await synthesize_harness(
        source_path=source_path,
        workdir=synth_workdir,
        max_retries=2,
    )

    # TODO: In a full implementation we would pass feedback into the
    # HarnessState before running the graph. For Phase 6 the stub
    # re-runs synthesis; the feedback is logged for human review.
    log.info(
        "mutate_harness.complete",
        success=result.success,
        simplified=result.simplified,
        harness_path=str(result.harness_path),
    )

    return SetupTargetOutput(
        workdir=synth_workdir,
        commit_sha="mutated",
        harness_path=result.harness_path,
    )


__all__ = ["mutate_harness"]
