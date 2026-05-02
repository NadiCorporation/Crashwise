# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Feedback agent — coverage-driven harness mutation hints.

Public API:
    :func:`analyze_campaign`   — decide next action from coverage metrics.
    :func:`parse_afl_stats`    — read AFL++ fuzzer_stats files.
    :func:`parse_libfuzzer_stats` — read libFuzzer stdout logs.
"""

from __future__ import annotations

from crashwise.agents.feedback.analyzer import (
    analyze_campaign,
    parse_afl_stats,
    parse_libfuzzer_stats,
)

__all__ = [
    "analyze_campaign",
    "parse_afl_stats",
    "parse_libfuzzer_stats",
]
