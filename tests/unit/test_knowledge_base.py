# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Tests for cross-campaign learning knowledge base."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from crashwise.agents.research.knowledge_base import (
    StrategyEffectiveness,
    TargetKnowledge,
    VulnerabilityPattern,
    inject_target_knowledge,
    query_effective_strategies,
    query_similar_targets,
    query_vulnerability_patterns,
    store_strategy_effectiveness,
    store_target_knowledge,
    store_vulnerability_pattern,
)
from crashwise.core.models import TargetDomain, TargetProfile

# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def sample_profile() -> TargetProfile:
    """Sample target profile for testing."""
    return TargetProfile(
        domain=TargetDomain.IMAGE_PROCESSING,
        complexity_score=7.5,
        attack_surface=["decode_png", "decode_jpeg", "parse_header"],
        dangerous_functions=["memcpy", "malloc"],
        language="c",
        lines_of_code=15000,
        file_count=42,
        has_custom_allocator=False,
        has_syscall_handlers=False,
        has_network_parsers=False,
        recommended_sanitizers="address,undefined",
        recommended_strategy="aggressive",
        notes="Test profile",
    )


@pytest.fixture
def sample_campaign_outcome() -> dict:
    """Sample campaign outcome for testing."""
    return {
        "crashes_found": 3,
        "coverage_edges": 1250,
        "strategies_used": ["afl_default", "libfuzzer_custom"],
        "harness_patterns": [
            {"name": "buffer_parser", "description": "Parse buffer with length prefix"},
            {"name": "struct_decoder", "description": "Decode struct from bytes"},
        ],
        "blockers_encountered": [
            {"type": "magic_value", "location": "parser.c:42", "bypass": "prefix_magic_bytes"},
            {"type": "length_check", "location": "decoder.c:100", "bypass": "ensure_min_length"},
        ],
    }


# ── store_target_knowledge Tests ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_store_target_knowledge_new_target(
    sample_profile: TargetProfile,
    sample_campaign_outcome: dict,
) -> None:
    """store_target_knowledge creates new entry for new target."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    with patch("crashwise.agents.research.knowledge_base.get_session") as mock_get_session:
        mock_get_session.return_value.__aenter__.return_value = mock_session

        await store_target_knowledge(
            target_name="libpng",
            profile=sample_profile,
            campaign_outcome=sample_campaign_outcome,
        )

    # Verify new knowledge was added
    mock_session.add.assert_called_once()
    added_knowledge = mock_session.add.call_args[0][0]
    assert isinstance(added_knowledge, TargetKnowledge)
    assert added_knowledge.target_name == "libpng"
    assert added_knowledge.domain == "image_processing"
    assert added_knowledge.campaign_count == 1
    assert added_knowledge.success_rate == 1.0  # crashes_found > 0
    assert added_knowledge.avg_coverage_edges == 1250
    assert added_knowledge.avg_crashes_found == 3.0
    assert len(added_knowledge.successful_harness_patterns) == 2
    assert len(added_knowledge.common_blockers) == 2
    assert len(added_knowledge.effective_strategies) == 2

    mock_session.commit.assert_called_once()


@pytest.mark.asyncio
async def test_store_target_knowledge_existing_target(
    sample_profile: TargetProfile,
    sample_campaign_outcome: dict,
) -> None:
    """store_target_knowledge updates existing entry."""
    existing_knowledge = TargetKnowledge(
        target_name="libpng",
        domain="image_processing",
        complexity_score=7.0,
        attack_surface=["decode_png"],
        successful_harness_patterns=[{"name": "old_pattern"}],
        common_blockers=[{"type": "old_blocker"}],
        effective_strategies=["old_strategy"],
        campaign_count=2,
        success_rate=0.5,
        avg_coverage_edges=1000,
        avg_crashes_found=1.5,
    )

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_knowledge

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.commit = AsyncMock()

    with patch("crashwise.agents.research.knowledge_base.get_session") as mock_get_session:
        mock_get_session.return_value.__aenter__.return_value = mock_session

        await store_target_knowledge(
            target_name="libpng",
            profile=sample_profile,
            campaign_outcome=sample_campaign_outcome,
        )

    # Verify existing knowledge was updated
    assert existing_knowledge.campaign_count == 3
    assert existing_knowledge.success_rate == pytest.approx(0.667, rel=1e-2)  # (0.5*2 + 1.0) / 3
    assert existing_knowledge.avg_coverage_edges == pytest.approx(1083.33, rel=1e-2)
    assert existing_knowledge.avg_crashes_found == pytest.approx(2.0, rel=1e-2)
    # Patterns should be merged (deduplicated)
    assert len(existing_knowledge.successful_harness_patterns) == 3  # old + 2 new
    assert len(existing_knowledge.common_blockers) == 3  # old + 2 new
    assert len(existing_knowledge.effective_strategies) == 3  # old + 2 new

    mock_session.commit.assert_called_once()


# ── store_vulnerability_pattern Tests ────────────────────────────────────────


@pytest.mark.asyncio
async def test_store_vulnerability_pattern_new() -> None:
    """store_vulnerability_pattern creates new pattern."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    with patch("crashwise.agents.research.knowledge_base.get_session") as mock_get_session:
        mock_get_session.return_value.__aenter__.return_value = mock_session

        await store_vulnerability_pattern(
            target_domain="image_processing",
            bug_type="heap-buffer-overflow",
            severity="high",
            severity_score=8,
            location_pattern="parser.c:decode_buffer",
            root_cause="Buffer overflow in PNG decoder",
            bypass_strategy="Ensure buffer size >= width * height * 4",
            crash_id="crash-123",
        )

    mock_session.add.assert_called_once()
    added_pattern = mock_session.add.call_args[0][0]
    assert isinstance(added_pattern, VulnerabilityPattern)
    assert added_pattern.target_domain == "image_processing"
    assert added_pattern.bug_type == "heap-buffer-overflow"
    assert added_pattern.severity == "high"
    assert added_pattern.severity_score == 8
    assert added_pattern.frequency == 1
    assert added_pattern.example_crash_ids == ["crash-123"]

    mock_session.commit.assert_called_once()


@pytest.mark.asyncio
async def test_store_vulnerability_pattern_existing() -> None:
    """store_vulnerability_pattern updates existing pattern."""
    existing_pattern = VulnerabilityPattern(
        target_domain="image_processing",
        bug_type="heap-buffer-overflow",
        severity="high",
        severity_score=8,
        location_pattern="parser.c:decode_buffer",
        root_cause_summary="Buffer overflow",
        bypass_strategy="Check size",
        frequency=2,
        example_crash_ids=["crash-1", "crash-2"],
    )

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_pattern

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.commit = AsyncMock()

    with patch("crashwise.agents.research.knowledge_base.get_session") as mock_get_session:
        mock_get_session.return_value.__aenter__.return_value = mock_session

        await store_vulnerability_pattern(
            target_domain="image_processing",
            bug_type="heap-buffer-overflow",
            severity="high",
            severity_score=8,
            location_pattern="parser.c:decode_buffer",
            root_cause="Updated root cause",
            bypass_strategy="Updated bypass",
            crash_id="crash-3",
        )

    # Verify existing pattern was updated
    assert existing_pattern.frequency == 3
    assert existing_pattern.example_crash_ids == ["crash-1", "crash-2", "crash-3"]

    mock_session.commit.assert_called_once()


# ── store_strategy_effectiveness Tests ───────────────────────────────────────


@pytest.mark.asyncio
async def test_store_strategy_effectiveness_new() -> None:
    """store_strategy_effectiveness creates new entry."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    with patch("crashwise.agents.research.knowledge_base.get_session") as mock_get_session:
        mock_get_session.return_value.__aenter__.return_value = mock_session

        await store_strategy_effectiveness(
            target_domain="image_processing",
            strategy_arm_id="afl_default",
            success=True,
            coverage_gain=1500.0,
            time_to_crash=3600.0,
        )

    mock_session.add.assert_called_once()
    added_entry = mock_session.add.call_args[0][0]
    assert isinstance(added_entry, StrategyEffectiveness)
    assert added_entry.target_domain == "image_processing"
    assert added_entry.strategy_arm_id == "afl_default"
    assert added_entry.success_count == 1
    assert added_entry.total_count == 1
    assert added_entry.avg_coverage_gain == 1500.0
    assert added_entry.avg_time_to_crash == 3600.0
    assert added_entry.effectiveness_score > 0.0

    mock_session.commit.assert_called_once()


@pytest.mark.asyncio
async def test_store_strategy_effectiveness_existing() -> None:
    """store_strategy_effectiveness updates existing entry."""
    existing_entry = StrategyEffectiveness(
        target_domain="image_processing",
        strategy_arm_id="afl_default",
        success_count=2,
        total_count=3,
        avg_coverage_gain=1000.0,
        avg_time_to_crash=4000.0,
        effectiveness_score=0.6,
    )

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_entry

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.commit = AsyncMock()

    with patch("crashwise.agents.research.knowledge_base.get_session") as mock_get_session:
        mock_get_session.return_value.__aenter__.return_value = mock_session

        await store_strategy_effectiveness(
            target_domain="image_processing",
            strategy_arm_id="afl_default",
            success=True,
            coverage_gain=2000.0,
            time_to_crash=3000.0,
        )

    # Verify existing entry was updated
    assert existing_entry.total_count == 4
    assert existing_entry.success_count == 3
    assert existing_entry.avg_coverage_gain == pytest.approx(1250.0, rel=1e-2)
    assert existing_entry.avg_time_to_crash == pytest.approx(3750.0, rel=1e-2)

    mock_session.commit.assert_called_once()


# ── query_similar_targets Tests ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_query_similar_targets() -> None:
    """query_similar_targets returns matching targets."""
    mock_knowledge = [
        TargetKnowledge(
            target_name="libpng",
            domain="image_processing",
            complexity_score=7.5,
            attack_surface=["decode_png"],
            successful_harness_patterns=[{"name": "pattern1"}],
            common_blockers=[{"type": "magic_value"}],
            effective_strategies=["afl_default"],
            success_rate=0.8,
            avg_coverage_edges=1200,
            avg_crashes_found=2.5,
        ),
        TargetKnowledge(
            target_name="libjpeg",
            domain="image_processing",
            complexity_score=8.0,
            attack_surface=["decode_jpeg"],
            successful_harness_patterns=[{"name": "pattern2"}],
            common_blockers=[{"type": "length_check"}],
            effective_strategies=["libfuzzer_custom"],
            success_rate=0.6,
            avg_coverage_edges=1000,
            avg_crashes_found=1.5,
        ),
    ]

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = mock_knowledge

    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    with patch("crashwise.agents.research.knowledge_base.get_session") as mock_get_session:
        mock_get_session.return_value.__aenter__.return_value = mock_session

        results = await query_similar_targets(domain="image_processing", limit=5)

    assert len(results) == 2
    assert results[0]["target_name"] == "libpng"
    assert results[0]["success_rate"] == 0.8
    assert results[1]["target_name"] == "libjpeg"
    assert results[1]["success_rate"] == 0.6


# ── query_vulnerability_patterns Tests ───────────────────────────────────────


@pytest.mark.asyncio
async def test_query_vulnerability_patterns() -> None:
    """query_vulnerability_patterns returns matching patterns."""
    mock_patterns = [
        VulnerabilityPattern(
            target_domain="image_processing",
            bug_type="heap-buffer-overflow",
            severity="high",
            severity_score=8,
            location_pattern="parser.c:decode_buffer",
            root_cause_summary="Buffer overflow",
            bypass_strategy="Check size",
            frequency=5,
        ),
    ]

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = mock_patterns

    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    with patch("crashwise.agents.research.knowledge_base.get_session") as mock_get_session:
        mock_get_session.return_value.__aenter__.return_value = mock_session

        results = await query_vulnerability_patterns(
            target_domain="image_processing",
            bug_type="heap-buffer-overflow",
            limit=10,
        )

    assert len(results) == 1
    assert results[0]["bug_type"] == "heap-buffer-overflow"
    assert results[0]["frequency"] == 5


# ── query_effective_strategies Tests ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_query_effective_strategies() -> None:
    """query_effective_strategies returns matching strategies."""
    mock_strategies = [
        StrategyEffectiveness(
            target_domain="image_processing",
            strategy_arm_id="afl_default",
            success_count=8,
            total_count=10,
            avg_coverage_gain=1500.0,
            avg_time_to_crash=3600.0,
            effectiveness_score=0.75,
        ),
    ]

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = mock_strategies

    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    with patch("crashwise.agents.research.knowledge_base.get_session") as mock_get_session:
        mock_get_session.return_value.__aenter__.return_value = mock_session

        results = await query_effective_strategies(
            target_domain="image_processing",
            limit=5,
        )

    assert len(results) == 1
    assert results[0]["strategy_arm_id"] == "afl_default"
    assert results[0]["success_rate"] == 0.8
    assert results[0]["effectiveness_score"] == 0.75


# ── inject_target_knowledge Tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_inject_target_knowledge_with_similar_targets() -> None:
    """inject_target_knowledge aggregates knowledge from similar targets."""
    mock_similar = [
        {
            "target_name": "libpng",
            "successful_harness_patterns": [
                {"name": "buffer_parser"},
                {"name": "struct_decoder"},
            ],
            "common_blockers": [
                {"type": "magic_value"},
                {"type": "length_check"},
            ],
            "effective_strategies": ["afl_default", "libfuzzer_custom"],
        },
        {
            "target_name": "libjpeg",
            "successful_harness_patterns": [
                {"name": "buffer_parser"},  # Duplicate
                {"name": "image_decoder"},
            ],
            "common_blockers": [
                {"type": "magic_value"},  # Duplicate
                {"type": "checksum"},
            ],
            "effective_strategies": ["afl_default"],  # Duplicate
        },
    ]

    with patch(
        "crashwise.agents.research.knowledge_base.query_similar_targets",
        new_callable=AsyncMock,
    ) as mock_query:
        mock_query.return_value = mock_similar

        result = await inject_target_knowledge(domain="image_processing")

    assert result["similar_targets_count"] == 2
    # Patterns should be deduplicated and ranked by frequency
    assert len(result["harness_patterns"]) == 3  # buffer_parser (2x), struct_decoder, image_decoder
    assert result["harness_patterns"][0]["name"] == "buffer_parser"  # Most frequent first
    # Blockers should be deduplicated
    assert len(result["common_blockers"]) == 3  # magic_value (2x), length_check, checksum
    assert result["common_blockers"][0]["type"] == "magic_value"  # Most frequent first
    # Strategies should be deduplicated
    assert len(result["effective_strategies"]) == 2  # afl_default (2x), libfuzzer_custom
    assert result["effective_strategies"][0] == "afl_default"  # Most frequent first


@pytest.mark.asyncio
async def test_inject_target_knowledge_no_similar_targets() -> None:
    """inject_target_knowledge returns empty when no similar targets."""
    with patch(
        "crashwise.agents.research.knowledge_base.query_similar_targets",
        new_callable=AsyncMock,
    ) as mock_query:
        mock_query.return_value = []

        result = await inject_target_knowledge(domain="unknown_domain")

    assert result["similar_targets_count"] == 0
    assert result["harness_patterns"] == []
    assert result["common_blockers"] == []
    assert result["effective_strategies"] == []
