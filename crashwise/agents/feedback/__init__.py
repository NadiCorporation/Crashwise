# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Feedback agent — coverage-driven harness mutation hints.

Public API:
    :func:`analyze_campaign`   — decide next action from coverage metrics.
    :func:`agentic_enrich`    — LLM-powered stall reasoning (enriches stalled state).
    :func:`agentic_analyze`   — standalone agentic feedback analysis.
    :func:`parse_afl_stats`    — read AFL++ fuzzer_stats files.
    :func:`parse_libfuzzer_stats` — read libFuzzer stdout logs.
"""

from __future__ import annotations

from crashwise.agents.feedback.agentic_analyzer import (
    AgenticFeedbackResult,
    IterationSnapshot,
    agentic_analyze,
)
from crashwise.agents.feedback.analyzer import (
    agentic_enrich,
    analyze_campaign,
    parse_afl_stats,
    parse_libfuzzer_stats,
)

__all__ = [
    "AgenticFeedbackResult",
    "IterationSnapshot",
    "agentic_analyze",
    "agentic_enrich",
    "analyze_campaign",
    "parse_afl_stats",
    "parse_libfuzzer_stats",
]
