# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""CrashWise — autonomous AI-powered fuzzing & crash triage platform.

CrashWise merges traditional low-level fuzzing (AFL++, libFuzzer) with LLM
orchestration (LangGraph) and durable distributed execution (Temporal) to
autonomously explore codebases, synthesise harnesses, run fuzz campaigns,
and produce root-cause analyses for the resulting crashes.

Top-level subpackages
---------------------
:mod:`crashwise.core`
    Shared Pydantic models, configuration, structured logging.
:mod:`crashwise.orchestration`
    Temporal client, workers, workflows, and activities.
:mod:`crashwise.agents`
    LangGraph cognitive engines (harness synthesis, triage).
:mod:`crashwise.execution`
    Fuzzer runners (AFL++, libFuzzer) and sandboxed execution helpers.
:mod:`crashwise.kernelbridge`
    Linux-kernel-specific fuzzing workflows (e.g., syzkaller integration).
"""

from __future__ import annotations

__all__ = ["__version__"]
__version__: str = "0.2.0.dev0"
