# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""CrashWise reporting agents — CVSS calculation and report generation."""

from crashwise.agents.reporting.cvss import calculate_cvss
from crashwise.agents.reporting.generator import generate_report

__all__ = ["calculate_cvss", "generate_report"]
