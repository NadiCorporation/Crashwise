"""
Gitleaks Detection Workflow
"""

# Copyright (c) 2026 Crashwise
#
# Licensed under the MIT License. See the LICENSE file for details.

from .workflow import GitleaksDetectionWorkflow
from .activities import scan_with_gitleaks

__all__ = ["GitleaksDetectionWorkflow", "scan_with_gitleaks"]
