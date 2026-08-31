# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""CrashWise Healing Engine.

A unified LangGraph state machine that drives two autonomous loops on top
of a sandboxed openhands-sdk runtime:

* **Adaptive Build** — discover the project's build system, install
  missing system dependencies, inject ASAN/UBSan/coverage flags and
  iterate compilation until a clean instrumented binary is produced.

* **Autonomous Repair** — given a unique ASAN/KASAN crash log, run GDB
  inside the sandbox, locate the offending source line, generate a
  targeted patch, recompile and verify the crash no longer reproduces.

The healing engine intentionally shares the *same* graph topology and
the *same* sandboxed toolset for both loops; only the system prompt and
termination heuristics change. This keeps the cognitive surface area
small, the test matrix shallow, and the LLM's behaviour predictable.

Public API:
    :class:`HealingMode`           — enum literal of "build" | "repair".
    :class:`HealingState`          — Pydantic-backed graph state.
    :func:`build_healing_graph`    — compile the LangGraph executable.
    :class:`OpenHandsSandbox`      — runtime handle wrapping openhands-sdk.
    :func:`execute_sandbox_command`— LangChain terminal tool.
    :func:`edit_sandbox_file`      — LangChain file-edit tool.
"""

from __future__ import annotations

from crashwise.agents.healing.graph import (
    HealingMode,
    HealingState,
    build_healing_graph,
)
from crashwise.agents.healing.tools import (
    HEALING_TOOLS,
    OpenHandsSandbox,
    edit_sandbox_file,
    execute_sandbox_command,
)

__all__ = [
    "HEALING_TOOLS",
    "HealingMode",
    "HealingState",
    "OpenHandsSandbox",
    "build_healing_graph",
    "edit_sandbox_file",
    "execute_sandbox_command",
]
