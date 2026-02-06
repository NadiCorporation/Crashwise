"""
Crashwise SDK - Python client for Crashwise security testing platform

A comprehensive SDK for interacting with the Crashwise API, providing
workflow management, real-time fuzzing monitoring, and SARIF findings retrieval.
"""
# Copyright (c) 2026 Crashwise
#
# Licensed under the MIT License. See the LICENSE file for details.


from .client import CrashwiseClient
from .models import (
    WorkflowSubmission,
    WorkflowMetadata,
    WorkflowListItem,
    WorkflowStatus,
    WorkflowFindings,
    FuzzingStats,
    CrashReport,
    RunSubmissionResponse,
)
from .exceptions import (
    CrashwiseError,
    CrashwiseHTTPError,
    WorkflowNotFoundError,
    RunNotFoundError,
    ValidationError,
)
from .testing import (
    WorkflowTester,
    TestResult,
    TestSummary,
    format_test_summary,
    DEFAULT_TEST_CONFIG,
)

__version__ = "0.7.3"
__all__ = [
    "CrashwiseClient",
    "WorkflowSubmission",
    "WorkflowMetadata",
    "WorkflowListItem",
    "WorkflowStatus",
    "WorkflowFindings",
    "FuzzingStats",
    "CrashReport",
    "RunSubmissionResponse",
    "CrashwiseError",
    "CrashwiseHTTPError",
    "WorkflowNotFoundError",
    "RunNotFoundError",
    "ValidationError",
    "WorkflowTester",
    "TestResult",
    "TestSummary",
    "format_test_summary",
    "DEFAULT_TEST_CONFIG",
]


def main() -> None:
    """Entry point for the CLI (not implemented yet)"""
    print("Crashwise SDK - Use as a library to interact with Crashwise API")
