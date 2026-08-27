# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Pydantic state for the harness-synthesis LangGraph agent.

The state object is the single source of truth that flows between nodes:

    AnalyzeCode  ──▶  GenerateHarness  ──▶  ValidateHarness
                            ▲                        │
                            └──────── retry ─────────┘

Every field is explicit; the graph never reads from globals.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field

from crashwise.agents.harness_synth.models import (
    ApiFunction,
    ApiParam,
    ApiSequence,
    EntryPoint,
    _StrictModel,
)


class CompileResult(_StrictModel):
    """Outcome of a clang++ compile attempt."""

    success: bool
    returncode: int
    stdout: str = ""
    stderr: str = ""
    binary_path: Path | None = None
    duration_seconds: float = Field(default=0.0, ge=0.0)


class HarnessState(_StrictModel):
    """LangGraph state for harness synthesis.

    Attributes
    ----------
    source_path:
        Absolute path to the C/C++ source file being analysed.
    source_code:
        The file contents (loaded once during ``AnalyzeCode``).
    language:
        ``"c"`` or ``"cpp"`` — informs the include set & extern "C" wrapping.
    workdir:
        Directory in which intermediate harness files and binaries live.
    entry_points:
        Candidate functions discovered by the analyser, best-first.
    selected_entry_point:
        The chosen entry point passed to the LLM. ``None`` until selection.
    api_sequences:
        Candidate API lifecycle sequences discovered by sequence builder.
    selected_sequence:
        The chosen API lifecycle sequence. ``None`` until selection.
    harness_code:
        The most recent harness source produced by ``GenerateHarness``.
    harness_path:
        On-disk location the harness was written to (set after generation).
    last_compile:
        Outcome of the most recent ``ValidateHarness`` invocation.
    retry_count:
        Number of regeneration attempts so far. Bounded by ``max_retries``.
    max_retries:
        Hard cap on regeneration attempts before falling back to the
        simplest possible harness.
    simplified:
        ``True`` once the agent has fallen back to the trivial harness.
    error_history:
        Compact stderr summaries from previous attempts; passed back to the
        LLM so it doesn't repeat the same mistake.
    done:
        Terminal flag — set when a harness compiles or fallback is final.
    """

    # ── Inputs ───────────────────────────────────────────────────────────────
    source_path: Path
    source_code: str = ""
    language: str = "cpp"
    workdir: Path
    engine: str = "libfuzzer"
    """Fuzzer engine: 'libfuzzer' or 'aflpp'. Determines harness format."""

    # ── Analysis ─────────────────────────────────────────────────────────────
    entry_points: list[EntryPoint] = Field(default_factory=list)
    selected_entry_point: EntryPoint | None = None
    api_sequences: list[ApiSequence] = Field(default_factory=list)
    selected_sequence: ApiSequence | None = None

    # ── Generation ───────────────────────────────────────────────────────────
    harness_code: str = ""
    harness_path: Path | None = None

    # ── Validation / retry loop ─────────────────────────────────────────────
    last_compile: CompileResult | None = None
    retry_count: int = Field(default=0, ge=0)
    max_retries: int = Field(default=4, ge=0, le=10)
    simplified: bool = False
    error_history: list[str] = Field(default_factory=list)

    # ── Phase 16: Target Profile ─────────────────────────────────────────────
    target_profile: dict[str, object] = Field(default_factory=dict)
    """Optional :class:`TargetProfile` dict injected by the profiler to tailor
    the harness prompt (domain, attack surface, dangerous functions)."""

    # ── Feedback loop (Phase 6) ──────────────────────────────────────────────
    feedback: str = ""
    """Structured feedback from the coverage analyzer; injected into the
    LLM prompt so the next harness iteration addresses stall conditions."""

    # ── Operation Hydra Phase 2: ReAct loop state ────────────────────────────
    crash_diagnosis: str = ""
    """GDB backtrace and crash analysis from debug_engine when sanity gate
    detects a crash. Fed back to the LLM for self-correction."""

    usage_example: str = ""
    """Code snippet from tests/examples showing how the target API is
    properly called. Provides the LLM with a reference pattern."""

    # ── Operation Hydra Phase 3: Type definitions ────────────────────────────
    type_definitions: str = ""
    """Extracted struct/typedef definitions for custom types used in the
    selected entry point's signature. Gives the LLM exact field layouts."""

    # ── Terminal ─────────────────────────────────────────────────────────────
    done: bool = False

    # ── Convenience ──────────────────────────────────────────────────────────
    @property
    def succeeded(self) -> bool:
        """True when the most recent compile is a clean success."""
        return self.last_compile is not None and self.last_compile.success


__all__ = [
    "ApiFunction",
    "ApiParam",
    "ApiSequence",
    "CompileResult",
    "EntryPoint",
    "HarnessState",
    "_StrictModel",
]
