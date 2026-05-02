# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Harness Synthesis Agent (Phase 2).

A LangGraph state machine that:
    1. Reads a target C/C++ codebase.
    2. Identifies promising attack-surface entry points.
    3. Drafts compilable libFuzzer / AFL++ harnesses.
    4. Compiles, captures stderr, self-corrects on failure, and retries.

Public API:
    :func:`synthesize_harness` — one-shot agent invocation.
    :class:`HarnessSynthesisResult` — typed outcome.
"""

from __future__ import annotations

from crashwise.agents.harness_synth.synth import (
    HarnessSynthesisResult,
    synthesize_harness,
)

__all__ = ["HarnessSynthesisResult", "synthesize_harness"]
