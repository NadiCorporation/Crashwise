# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Temporal-based orchestration layer.

This package keeps its ``__init__`` deliberately empty: importing the
parent package must NOT pull in ``client.py`` (and its tenacity / structlog
dependencies), because the Temporal workflow sandbox walks parent
packages on workflow validation and rejects non-deterministic transitive
imports such as ``rich.style`` (uses ``random.getrandbits``).

Public API:
    from crashwise.orchestration.client    import connect, start_main_workflow
    from crashwise.orchestration.worker    import run_worker
    from crashwise.orchestration.workflows import MainFuzzingWorkflow, ALL_WORKFLOWS
    from crashwise.orchestration.activities import ALL_ACTIVITIES
"""

from __future__ import annotations

__all__: list[str] = []
