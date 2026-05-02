# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Compile-time wiring of the harness-synthesis LangGraph state machine.

┌───────────────┐
│  AnalyzeCode  │
└──────┬────────┘
       ▼
┌─────────────────┐
│ GenerateHarness │◀────────┐
└──────┬──────────┘         │
       ▼                    │ retry
┌─────────────────┐         │
│ ValidateHarness │─────────┘
└──────┬──────────┘
       ▼
      END
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from crashwise.agents.harness_synth.nodes import (
    analyze_code,
    generate_harness,
    should_retry,
    validate_harness,
)
from crashwise.agents.harness_synth.state import HarnessState


def build_graph() -> Any:
    """Return a compiled LangGraph executable."""
    graph: StateGraph[HarnessState, Any, HarnessState, HarnessState] = StateGraph(
        state_schema=HarnessState,
    )
    graph.add_node("analyze", analyze_code)
    graph.add_node("generate", generate_harness)
    graph.add_node("validate", validate_harness)

    graph.set_entry_point("analyze")
    graph.add_edge("analyze", "generate")
    graph.add_edge("generate", "validate")
    graph.add_conditional_edges(
        "validate",
        should_retry,
        {
            "generate": "generate",
            "__end__": END,
        },
    )
    return graph.compile()


__all__ = ["build_graph"]
