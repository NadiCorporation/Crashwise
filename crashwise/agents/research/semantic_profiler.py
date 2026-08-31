# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Semantic Target Profiler — LLM-powered attack surface analysis.

This module provides semantic enrichment for the regex-based profiler by
using an LLM agent to reason about:

* Which functions accept untrusted input (parsers, decoders, validators)
* Data flow complexity (transformations before reaching dangerous operations)
* Memory management patterns (manual alloc/free, RAII, smart pointers)
* Attack surface size and exploitability likelihood

The semantic profiler runs as an enrichment step after the regex profiler.
If the LLM is unavailable, the system falls back to regex-only analysis
(autonomy guarantee).

Architecture:
    collect_context → analyze_attack_surface → score_entry_points → generate_profile
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field

from crashwise.core.llm_factory import get_llm_provider
from crashwise.core.logging import get_logger
from crashwise.core.models import TargetProfile

log = get_logger(__name__)


# ── State Model ──────────────────────────────────────────────────────────────


class SemanticProfilerState(BaseModel):
    """State flowing through the semantic profiler graph."""

    workdir: Path
    header_files: list[Path] = Field(default_factory=list)
    source_snippets: dict[str, str] = Field(default_factory=dict)
    attack_surface_analysis: str = ""
    entry_point_scores: dict[str, float] = Field(default_factory=dict)
    semantic_insights: dict[str, Any] = Field(default_factory=dict)
    error: str = ""


# ── Prompts ──────────────────────────────────────────────────────────────────

ATTACK_SURFACE_PROMPT = """You are a security researcher analyzing a C/C++ codebase to identify the attack surface for fuzzing.

Given the following header files and source snippets, identify:

1. **Functions that accept untrusted input**: Look for functions that:
   - Take buffers, strings, or byte arrays as parameters
   - Parse file formats, network protocols, or structured data
   - Decode, decompress, or deserialize data
   - Handle user-controlled input (e.g., from files, sockets, stdin)

2. **Data flow complexity**: For each entry point, estimate:
   - How many transformations the input undergoes before reaching dangerous operations
   - Whether there are validation checks before memory operations
   - If the function calls other parsers or decoders

3. **Memory management patterns**:
   - Manual malloc/free vs RAII/smart pointers
   - Custom allocators or memory pools
   - Buffer size tracking mechanisms

4. **High-risk patterns**:
   - Functions that allocate memory based on input size
   - Nested parsing (parser calls another parser)
   - State machines that process input incrementally

Output a structured analysis with:
- List of high-value fuzzing targets (function names + rationale)
- Estimated complexity (low/medium/high) for each target
- Recommended fuzzing strategy (e.g., "focus on malformed headers", "test boundary conditions")

Be specific and cite function names from the code.
"""

SCORE_ENTRY_POINTS_PROMPT = """You are a vulnerability researcher scoring C/C++ functions by their likelihood of containing memory safety bugs.

Given the following function signatures and context, score each function from 0.0 to 1.0 based on:

**High score (0.8-1.0)**:
- Parses complex formats (images, archives, protocols)
- Manual memory management with input-derived sizes
- Nested parsing or state machines
- History of similar functions having vulnerabilities

**Medium score (0.4-0.7)**:
- Simple parsers or validators
- Uses safe abstractions but has edge cases
- Moderate complexity with some manual memory ops

**Low score (0.0-0.3)**:
- Simple getters/setters
- Well-abstracted with RAII/smart pointers
- No direct input processing

For each function, provide:
- Function name
- Score (0.0-1.0)
- Rationale (1-2 sentences)

Output as a JSON object: {"function_name": {"score": 0.8, "rationale": "..."}}
"""


# ── Graph Nodes ──────────────────────────────────────────────────────────────


async def collect_context(state: SemanticProfilerState) -> dict[str, Any]:
    """Collect header files and key source snippets for analysis."""
    log.info("semantic_profiler.collect_context", workdir=str(state.workdir))

    header_files = []
    source_snippets = {}

    # Find all header files
    for pattern in ["**/*.h", "**/*.hpp", "**/*.hxx"]:
        header_files.extend(state.workdir.glob(pattern))

    # Limit to first 20 headers to avoid context overflow
    header_files = sorted(header_files)[:20]

    # Read header contents
    for header in header_files:
        try:
            content = header.read_text(encoding="utf-8", errors="replace")
            # Truncate large headers
            if len(content) > 8000:
                content = content[:8000] + "\n... [truncated]"
            source_snippets[str(header.relative_to(state.workdir))] = content
        except OSError as e:
            log.warning("semantic_profiler.read_failed", file=str(header), error=str(e))

    # Also collect key source files (parsers, decoders)
    source_patterns = [
        "**/parse*.c", "**/parse*.cpp",
        "**/decode*.c", "**/decode*.cpp",
        "**/read*.c", "**/read*.cpp",
    ]
    source_files = []
    for pattern in source_patterns:
        source_files.extend(state.workdir.glob(pattern))

    for src in sorted(source_files)[:10]:
        try:
            content = src.read_text(encoding="utf-8", errors="replace")
            if len(content) > 8000:
                content = content[:8000] + "\n... [truncated]"
            source_snippets[str(src.relative_to(state.workdir))] = content
        except OSError:
            pass

    log.info(
        "semantic_profiler.context_collected",
        headers=len(header_files),
        snippets=len(source_snippets),
    )

    return {
        "header_files": header_files,
        "source_snippets": source_snippets,
    }


async def analyze_attack_surface(state: SemanticProfilerState) -> dict[str, Any]:
    """Use LLM to analyze which functions accept untrusted input."""
    log.info("semantic_profiler.analyze_attack_surface")

    if not state.source_snippets:
        return {"attack_surface_analysis": "No source snippets available for analysis."}

    # Build context from snippets
    context_parts = []
    for filename, content in list(state.source_snippets.items())[:15]:
        context_parts.append(f"=== {filename} ===\n{content}\n")

    context = "\n".join(context_parts)

    try:
        provider = get_llm_provider()
        chat = provider.chat_model

        messages = [
            SystemMessage(content=ATTACK_SURFACE_PROMPT),
            HumanMessage(content=f"Analyze this codebase:\n\n{context}"),
        ]

        response = await chat.ainvoke(messages)
        analysis = response.content if hasattr(response, "content") else str(response)

        log.info("semantic_profiler.analysis_complete", length=len(analysis))
        return {"attack_surface_analysis": analysis}

    except Exception as e:
        log.warning("semantic_profiler.llm_failed", error=str(e))
        return {
            "attack_surface_analysis": "LLM analysis unavailable. Using regex-only profiling.",
            "error": str(e),
        }


async def score_entry_points(state: SemanticProfilerState) -> dict[str, Any]:
    """Use LLM to score entry points by exploitability likelihood."""
    log.info("semantic_profiler.score_entry_points")

    if not state.source_snippets or state.error:
        return {"entry_point_scores": {}}

    # Extract function signatures from headers
    signatures = []
    func_pattern = re.compile(
        r"^\s*(?:extern\s+)?(?:[\w\s\*]+)\s+(\w+)\s*\([^)]*\)\s*;",
        re.MULTILINE,
    )

    for filename, content in state.source_snippets.items():
        if filename.endswith((".h", ".hpp", ".hxx")):
            for match in func_pattern.finditer(content):
                func_name = match.group(1)
                # Skip common non-entry-point functions
                if func_name not in {"main", "printf", "malloc", "free"}:
                    signatures.append(f"{filename}: {match.group(0).strip()}")

    if not signatures:
        return {"entry_point_scores": {}}

    # Limit to first 50 signatures
    signatures = signatures[:50]
    context = "\n".join(signatures)

    try:
        provider = get_llm_provider()
        chat = provider.chat_model

        messages = [
            SystemMessage(content=SCORE_ENTRY_POINTS_PROMPT),
            HumanMessage(content=f"Score these functions:\n\n{context}"),
        ]

        response = await chat.ainvoke(messages)
        content = response.content if hasattr(response, "content") else str(response)

        # Parse JSON response
        import json

        try:
            # Try to extract JSON from response (handle nested objects)
            # Find the outermost balanced braces
            json_str = _extract_json_object(content)
            if json_str:
                scores_data = json.loads(json_str)
                # Normalize to {func_name: score}
                entry_point_scores = {}
                for func_name, data in scores_data.items():
                    if isinstance(data, dict) and "score" in data:
                        entry_point_scores[func_name] = float(data["score"])
                    elif isinstance(data, (int, float)):
                        entry_point_scores[func_name] = float(data)

                log.info("semantic_profiler.scores_parsed", count=len(entry_point_scores))
                return {"entry_point_scores": entry_point_scores}
        except (json.JSONDecodeError, ValueError) as e:
            log.warning("semantic_profiler.parse_failed", error=str(e))

        return {"entry_point_scores": {}}

    except Exception as e:
        log.warning("semantic_profiler.scoring_failed", error=str(e))
        return {"entry_point_scores": {}, "error": str(e)}


async def generate_profile(state: SemanticProfilerState) -> dict[str, Any]:
    """Merge semantic insights into a structured format."""
    log.info("semantic_profiler.generate_profile")

    insights = {
        "attack_surface_analysis": state.attack_surface_analysis,
        "entry_point_scores": state.entry_point_scores,
        "high_value_targets": [],
    }

    # Extract high-value targets from scores
    if state.entry_point_scores:
        sorted_targets = sorted(
            state.entry_point_scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        insights["high_value_targets"] = [
            {"function": name, "score": score}
            for name, score in sorted_targets[:10]
            if score >= 0.6
        ]

    log.info(
        "semantic_profiler.profile_generated",
        high_value_count=len(insights["high_value_targets"]),
    )

    return {"semantic_insights": insights}


def _extract_json_object(text: str) -> str | None:
    """Extract the outermost balanced JSON object from text.

    Handles nested objects and arrays by tracking brace depth.
    Returns None if no valid JSON object is found.
    """
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i in range(start, len(text)):
        char = text[i]

        if escape_next:
            escape_next = False
            continue

        if char == "\\":
            escape_next = True
            continue

        if char == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]

    return None


# ── Graph Construction ───────────────────────────────────────────────────────


def build_semantic_profiler_graph() -> StateGraph:
    """Build the semantic profiler LangGraph."""
    graph = StateGraph(SemanticProfilerState)

    graph.add_node("collect_context", collect_context)
    graph.add_node("analyze_attack_surface", analyze_attack_surface)
    graph.add_node("score_entry_points", score_entry_points)
    graph.add_node("generate_profile", generate_profile)

    graph.set_entry_point("collect_context")
    graph.add_edge("collect_context", "analyze_attack_surface")
    graph.add_edge("analyze_attack_surface", "score_entry_points")
    graph.add_edge("score_entry_points", "generate_profile")
    graph.add_edge("generate_profile", END)

    return graph.compile()


# ── Public API ───────────────────────────────────────────────────────────────


async def enrich_profile_with_semantics(
    workdir: Path,
    base_profile: TargetProfile,
) -> TargetProfile:
    """Enrich a regex-based TargetProfile with semantic LLM analysis.

    Parameters
    ----------
    workdir:
        Path to the cloned target repository.
    base_profile:
        The regex-based profile to enrich.

    Returns
    -------
    Enriched TargetProfile with semantic insights merged into notes.
    """
    log.info("semantic_profiler.enrich_start", workdir=str(workdir))

    try:
        graph = build_semantic_profiler_graph()
        initial_state = SemanticProfilerState(workdir=workdir)
        final_state = await graph.ainvoke(initial_state)

        # Merge semantic insights into base profile
        if final_state.semantic_insights:
            high_value = final_state.semantic_insights.get("high_value_targets", [])
            if high_value:
                # Add high-value targets to attack surface
                for target in high_value[:5]:
                    func_name = target["function"]
                    if func_name not in base_profile.attack_surface:
                        base_profile.attack_surface.append(func_name)

                # Update notes with semantic insights
                semantic_note = (
                    f"\n\nSemantic Analysis: Identified {len(high_value)} high-value targets "
                    f"(score >= 0.6): {', '.join(t['function'] for t in high_value[:5])}"
                )
                base_profile.notes += semantic_note

                # Adjust complexity score based on semantic analysis
                avg_score = sum(t["score"] for t in high_value) / len(high_value)
                if avg_score > 0.7:
                    base_profile.complexity_score = min(10.0, base_profile.complexity_score + 1.0)
                    base_profile.recommended_strategy = "aggressive"
            else:
                # Semantic analysis ran but found no high-value targets
                base_profile.notes += "\n\nSemantic Analysis: No high-value targets identified (all scores < 0.6)"

        log.info("semantic_profiler.enrich_complete", high_value_count=len(high_value))

    except Exception as e:
        log.warning("semantic_profiler.enrich_failed", error=str(e))
        # Autonomy guarantee: return base profile unchanged
        base_profile.notes += f"\n\nSemantic enrichment unavailable: {e}"

    return base_profile


__all__ = ["enrich_profile_with_semantics"]
