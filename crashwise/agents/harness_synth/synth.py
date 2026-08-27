# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Public entry point for the harness-synthesis vertical.

This is the single function the rest of CrashWise (notably the
``setup_target`` activity) calls when it needs an autonomous harness.

The agent is total: it always returns a :class:`HarnessSynthesisResult`,
even when the LLM is unreachable or the source is incomprehensible. In
that case the fallback harness is reported with ``simplified=True``.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from crashwise.agents.harness_synth.analyzer import detect_language
from crashwise.agents.harness_synth.graph import build_graph
from crashwise.agents.harness_synth.models import ApiSequence
from crashwise.agents.harness_synth.state import EntryPoint, HarnessState
from crashwise.core.logging import get_logger

log = get_logger(__name__)


class HarnessSynthesisResult(BaseModel):
    """Outcome of :func:`synthesize_harness`."""

    model_config = ConfigDict(extra="forbid")

    harness_path: Path = Field(..., description="Where the harness lives on disk")
    binary_path: Path | None = Field(
        default=None, description="Compiled binary if compilation succeeded"
    )
    success: bool = Field(default=False, description="Did the final compile succeed?")
    simplified: bool = Field(default=False, description="Was the fallback harness used?")
    selected_entry_point: EntryPoint | None = None
    selected_sequence: ApiSequence | None = None
    retry_count: int = Field(default=0, ge=0)
    last_stderr: str = Field(default="", description="Final clang stderr (truncated)")


async def synthesize_harness(
    *,
    source_path: Path,
    workdir: Path,
    max_retries: int = 4,
    feedback: str = "",
    usage_example: str = "",
    engine: str = "libfuzzer",
) -> HarnessSynthesisResult:
    """Run the LangGraph harness-synthesis agent against ``source_path``.

    Parameters
    ----------
    source_path:
        Absolute path to the C/C++ source file the user wants fuzzed.
    workdir:
        Sandbox directory where ``harness.cpp`` and the compiled binary
        will be placed.
    max_retries:
        Maximum number of LLM regenerations before falling back to the
        deterministic minimal harness.
    feedback:
        Structured feedback from the coverage analyzer (stall reasons,
        mutation suggestions). Injected into the LLM prompt so the next
        harness iteration addresses coverage blockers.
    usage_example:
        Code snippet from tests/examples showing how the target API is
        properly called. Provides the LLM with a reference pattern.
    engine:
        Fuzzer engine: 'libfuzzer' or 'aflpp'. Determines harness format.
    """
    if not source_path.is_absolute():
        source_path = source_path.resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    initial = HarnessState(
        source_path=source_path,
        workdir=workdir,
        language=detect_language(source_path),
        max_retries=max_retries,
        feedback=feedback,
        usage_example=usage_example,
        engine=engine,
    )
    log.info(
        "harness_synth.synthesize.start",
        source_path=str(source_path),
        workdir=str(workdir),
        max_retries=max_retries,
    )

    graph = build_graph()
    raw = await graph.ainvoke(initial)

    # LangGraph may return a dict or our Pydantic model depending on version
    # — normalise both back to HarnessState.
    final = raw if isinstance(raw, HarnessState) else HarnessState.model_validate(raw)

    last_stderr = final.last_compile.stderr if final.last_compile else ""

    result = HarnessSynthesisResult(
        harness_path=final.harness_path or (workdir / "harness.cpp"),
        binary_path=final.last_compile.binary_path if final.last_compile else None,
        success=final.succeeded,
        simplified=final.simplified,
        selected_entry_point=final.selected_entry_point,
        selected_sequence=final.selected_sequence,
        retry_count=final.retry_count,
        last_stderr=last_stderr,
    )

    log.info(
        "harness_synth.synthesize.complete",
        success=result.success,
        simplified=result.simplified,
        retry_count=result.retry_count,
        binary_path=str(result.binary_path) if result.binary_path else None,
    )
    return result


__all__ = ["HarnessSynthesisResult", "synthesize_harness"]
