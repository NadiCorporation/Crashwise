# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Tests for the semantic target profiler."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from crashwise.agents.research.semantic_profiler import (
    SemanticProfilerState,
    analyze_attack_surface,
    collect_context,
    enrich_profile_with_semantics,
    generate_profile,
    score_entry_points,
)
from crashwise.core.models import TargetDomain, TargetProfile

# ── State Model Tests ────────────────────────────────────────────────────────


def test_semantic_profiler_state_defaults(tmp_path: Path) -> None:
    """State initializes with empty collections."""
    state = SemanticProfilerState(workdir=tmp_path)
    assert state.header_files == []
    assert state.source_snippets == {}
    assert state.attack_surface_analysis == ""
    assert state.entry_point_scores == {}
    assert state.semantic_insights == {}
    assert state.error == ""


# ── collect_context Tests ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_collect_context_finds_headers(tmp_path: Path) -> None:
    """collect_context discovers header files in the workdir."""
    # Create test files
    (tmp_path / "parser.h").write_text("int parse(const char *buf);")
    (tmp_path / "decoder.hpp").write_text("void decode(uint8_t *data);")
    (tmp_path / "main.c").write_text("int main() { return 0; }")

    state = SemanticProfilerState(workdir=tmp_path)
    result = await collect_context(state)

    assert len(result["header_files"]) == 2
    assert "parser.h" in result["source_snippets"]
    assert "decoder.hpp" in result["source_snippets"]


@pytest.mark.asyncio
async def test_collect_context_truncates_large_files(tmp_path: Path) -> None:
    """collect_context truncates files larger than 8000 chars."""
    large_content = "x" * 10000
    (tmp_path / "large.h").write_text(large_content)

    state = SemanticProfilerState(workdir=tmp_path)
    result = await collect_context(state)

    assert "large.h" in result["source_snippets"]
    assert len(result["source_snippets"]["large.h"]) < 10000
    assert "[truncated]" in result["source_snippets"]["large.h"]


@pytest.mark.asyncio
async def test_collect_context_empty_workdir(tmp_path: Path) -> None:
    """collect_context handles empty workdir gracefully."""
    state = SemanticProfilerState(workdir=tmp_path)
    result = await collect_context(state)

    assert result["header_files"] == []
    assert result["source_snippets"] == {}


# ── analyze_attack_surface Tests ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_attack_surface_no_snippets() -> None:
    """analyze_attack_surface returns message when no snippets available."""
    state = SemanticProfilerState(workdir=Path("/tmp"), source_snippets={})
    result = await analyze_attack_surface(state)

    assert "No source snippets" in result["attack_surface_analysis"]


@pytest.mark.asyncio
async def test_analyze_attack_surface_llm_success(tmp_path: Path) -> None:
    """analyze_attack_surface calls LLM and returns analysis."""
    state = SemanticProfilerState(
        workdir=tmp_path,
        source_snippets={"parser.h": "int parse(const char *buf);"},
    )

    mock_chat = AsyncMock()
    mock_response = MagicMock()
    mock_response.content = "High-value target: parse() - accepts untrusted buffer input"
    mock_chat.ainvoke.return_value = mock_response

    mock_provider = MagicMock()
    mock_provider.chat_model = mock_chat

    with patch("crashwise.agents.research.semantic_profiler.get_llm_provider", return_value=mock_provider):
        result = await analyze_attack_surface(state)

    assert "parse()" in result["attack_surface_analysis"]
    mock_chat.ainvoke.assert_called_once()


@pytest.mark.asyncio
async def test_analyze_attack_surface_llm_failure(tmp_path: Path) -> None:
    """analyze_attack_surface handles LLM failure gracefully."""
    state = SemanticProfilerState(
        workdir=tmp_path,
        source_snippets={"parser.h": "int parse(const char *buf);"},
    )

    with patch("crashwise.agents.research.semantic_profiler.get_llm_provider", side_effect=Exception("LLM unavailable")):
        result = await analyze_attack_surface(state)

    assert "unavailable" in result["attack_surface_analysis"].lower()
    assert "error" in result


# ── score_entry_points Tests ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_score_entry_points_no_snippets() -> None:
    """score_entry_points returns empty dict when no snippets available."""
    state = SemanticProfilerState(workdir=Path("/tmp"), source_snippets={})
    result = await score_entry_points(state)

    assert result["entry_point_scores"] == {}


@pytest.mark.asyncio
async def test_score_entry_points_llm_success(tmp_path: Path) -> None:
    """score_entry_points parses LLM JSON response."""
    state = SemanticProfilerState(
        workdir=tmp_path,
        source_snippets={"parser.h": "int parse(const char *buf, size_t len);"},
    )

    mock_chat = AsyncMock()
    mock_response = MagicMock()
    mock_response.content = '{"parse": {"score": 0.85, "rationale": "Parses untrusted buffer"}}'
    mock_chat.ainvoke.return_value = mock_response

    mock_provider = MagicMock()
    mock_provider.chat_model = mock_chat

    with patch("crashwise.agents.research.semantic_profiler.get_llm_provider", return_value=mock_provider):
        result = await score_entry_points(state)

    assert "parse" in result["entry_point_scores"]
    assert result["entry_point_scores"]["parse"] == 0.85


@pytest.mark.asyncio
async def test_score_entry_points_invalid_json(tmp_path: Path) -> None:
    """score_entry_points handles invalid JSON gracefully."""
    state = SemanticProfilerState(
        workdir=tmp_path,
        source_snippets={"parser.h": "int parse(const char *buf);"},
    )

    mock_chat = AsyncMock()
    mock_response = MagicMock()
    mock_response.content = "This is not valid JSON"
    mock_chat.ainvoke.return_value = mock_response

    mock_provider = MagicMock()
    mock_provider.chat_model = mock_chat

    with patch("crashwise.agents.research.semantic_profiler.get_llm_provider", return_value=mock_provider):
        result = await score_entry_points(state)

    assert result["entry_point_scores"] == {}


# ── generate_profile Tests ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_profile_extracts_high_value_targets() -> None:
    """generate_profile identifies high-value targets from scores."""
    state = SemanticProfilerState(
        workdir=Path("/tmp"),
        entry_point_scores={
            "parse": 0.85,
            "decode": 0.75,
            "validate": 0.45,
        },
    )

    result = await generate_profile(state)

    assert "high_value_targets" in result["semantic_insights"]
    high_value = result["semantic_insights"]["high_value_targets"]
    assert len(high_value) == 2  # Only parse and decode (>= 0.6)
    assert high_value[0]["function"] == "parse"
    assert high_value[0]["score"] == 0.85


@pytest.mark.asyncio
async def test_generate_profile_empty_scores() -> None:
    """generate_profile handles empty scores gracefully."""
    state = SemanticProfilerState(workdir=Path("/tmp"), entry_point_scores={})
    result = await generate_profile(state)

    assert result["semantic_insights"]["high_value_targets"] == []


# ── enrich_profile_with_semantics Tests ──────────────────────────────────────


@pytest.mark.asyncio
async def test_enrich_profile_adds_high_value_targets(tmp_path: Path) -> None:
    """enrich_profile_with_semantics merges high-value targets into base profile."""
    base_profile = TargetProfile(
        domain=TargetDomain.PARSER,
        attack_surface=["init", "cleanup"],
        complexity_score=5.0,
        notes="Base profile",
    )

    # Mock the graph to return specific insights
    mock_final_state = SemanticProfilerState(
        workdir=tmp_path,
        semantic_insights={
            "high_value_targets": [
                {"function": "parse", "score": 0.85},
                {"function": "decode", "score": 0.75},
            ]
        },
    )

    with patch(
        "crashwise.agents.research.semantic_profiler.build_semantic_profiler_graph"
    ) as mock_build:
        mock_graph = AsyncMock()
        mock_graph.ainvoke.return_value = mock_final_state
        mock_build.return_value = mock_graph

        enriched = await enrich_profile_with_semantics(tmp_path, base_profile)

    assert "parse" in enriched.attack_surface
    assert "decode" in enriched.attack_surface
    assert "Semantic Analysis" in enriched.notes
    assert enriched.complexity_score > 5.0  # Should be bumped up


@pytest.mark.asyncio
async def test_enrich_profile_handles_failure(tmp_path: Path) -> None:
    """enrich_profile_with_semantics returns base profile on failure."""
    base_profile = TargetProfile(
        domain=TargetDomain.GENERAL,
        notes="Base profile",
    )

    with patch(
        "crashwise.agents.research.semantic_profiler.build_semantic_profiler_graph",
        side_effect=Exception("Graph build failed"),
    ):
        enriched = await enrich_profile_with_semantics(tmp_path, base_profile)

    # Autonomy guarantee: base profile is returned unchanged
    assert enriched.domain == TargetDomain.GENERAL
    assert "unavailable" in enriched.notes.lower()


@pytest.mark.asyncio
async def test_enrich_profile_no_high_value_targets(tmp_path: Path) -> None:
    """enrich_profile_with_semantics handles case with no high-value targets."""
    base_profile = TargetProfile(
        domain=TargetDomain.GENERAL,
        attack_surface=["init"],
        notes="Base profile",
    )

    mock_final_state = SemanticProfilerState(
        workdir=tmp_path,
        semantic_insights={"high_value_targets": []},
    )

    with patch(
        "crashwise.agents.research.semantic_profiler.build_semantic_profiler_graph"
    ) as mock_build:
        mock_graph = AsyncMock()
        mock_graph.ainvoke.return_value = mock_final_state
        mock_build.return_value = mock_graph

        enriched = await enrich_profile_with_semantics(tmp_path, base_profile)

    # Profile should be unchanged except for semantic note
    assert enriched.attack_surface == ["init"]
    assert "Semantic Analysis" in enriched.notes
