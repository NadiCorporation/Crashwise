# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Cross-Campaign Learning — knowledge base for storing and reusing campaign insights.

This module enables CrashWise to learn from past campaigns and improve future
targeting by storing:

* **Target profiles** with successful harness patterns and common blockers
* **Vulnerability patterns** discovered across campaigns
* **Strategy effectiveness** metrics for different target domains

The knowledge base feeds into:
* Harness synthesis (inject successful patterns from similar targets)
* MAB initialization (bias toward effective strategies for the domain)
* Coverage analysis (suggest bypass strategies that worked before)

Architecture:
    store_knowledge → query_similar_targets → inject_knowledge
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, Float, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from crashwise.core.database import Base, get_session
from crashwise.core.logging import get_logger
from crashwise.core.models import TargetProfile

log = get_logger(__name__)


# ── SQLAlchemy Models ────────────────────────────────────────────────────────


class TargetKnowledge(Base):
    """Aggregated knowledge about a specific target or target family."""

    __tablename__ = "target_knowledge"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    target_name: Mapped[str] = mapped_column(String(128), index=True)
    domain: Mapped[str] = mapped_column(String(64), index=True)
    complexity_score: Mapped[float] = mapped_column(Float, default=0.0)
    attack_surface: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Successful patterns
    successful_harness_patterns: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list
    )
    common_blockers: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    effective_strategies: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Statistics
    campaign_count: Mapped[int] = mapped_column(Integer, default=0)
    success_rate: Mapped[float] = mapped_column(Float, default=0.0)
    avg_coverage_edges: Mapped[int] = mapped_column(Integer, default=0)
    avg_crashes_found: Mapped[float] = mapped_column(Float, default=0.0)

    # Metadata
    last_updated: Mapped[datetime] = mapped_column(
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
    notes: Mapped[str] = mapped_column(Text, default="")


class VulnerabilityPattern(Base):
    """Vulnerability patterns discovered across campaigns."""

    __tablename__ = "vulnerability_patterns"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    target_domain: Mapped[str] = mapped_column(String(64), index=True)
    bug_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32))
    severity_score: Mapped[int] = mapped_column(Integer, default=0)

    # Pattern details
    location_pattern: Mapped[str] = mapped_column(String(256), default="")
    root_cause_summary: Mapped[str] = mapped_column(Text, default="")
    bypass_strategy: Mapped[str] = mapped_column(Text, default="")

    # Statistics
    frequency: Mapped[int] = mapped_column(Integer, default=1)
    last_seen: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    # Example crashes
    example_crash_ids: Mapped[list[str]] = mapped_column(JSON, default=list)


class StrategyEffectiveness(Base):
    """Effectiveness of MAB strategies for different target domains."""

    __tablename__ = "strategy_effectiveness"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    target_domain: Mapped[str] = mapped_column(String(64), index=True)
    strategy_arm_id: Mapped[str] = mapped_column(String(64), index=True)

    # Statistics
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    total_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_coverage_gain: Mapped[float] = mapped_column(Float, default=0.0)
    avg_time_to_crash: Mapped[float] = mapped_column(Float, default=0.0)
    effectiveness_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Metadata
    last_updated: Mapped[datetime] = mapped_column(
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ── Knowledge Extraction ─────────────────────────────────────────────────────


async def store_target_knowledge(
    target_name: str,
    profile: TargetProfile,
    campaign_outcome: dict[str, Any],
) -> None:
    """Store or update knowledge about a target based on campaign results.

    Parameters
    ----------
    target_name:
        Name of the target (e.g., "libpng", "zlib").
    profile:
        The TargetProfile from profiling.
    campaign_outcome:
        Dict with keys: crashes_found, coverage_edges, strategies_used,
        harness_patterns, blockers_encountered.
    """
    log.info("knowledge_base.store_target_knowledge", target=target_name)

    async with get_session() as session:
        # Check if we already have knowledge for this target
        result = await session.execute(
            select(TargetKnowledge).where(TargetKnowledge.target_name == target_name)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Update existing knowledge
            existing.campaign_count += 1
            existing.success_rate = (
                (existing.success_rate * (existing.campaign_count - 1))
                + (1.0 if campaign_outcome.get("crashes_found", 0) > 0 else 0.0)
            ) / existing.campaign_count

            existing.avg_coverage_edges = int(
                (existing.avg_coverage_edges * (existing.campaign_count - 1))
                + campaign_outcome.get("coverage_edges", 0)
            ) / existing.campaign_count

            existing.avg_crashes_found = (
                (existing.avg_crashes_found * (existing.campaign_count - 1))
                + campaign_outcome.get("crashes_found", 0)
            ) / existing.campaign_count

            # Merge successful patterns (deduplicate)
            new_patterns = campaign_outcome.get("harness_patterns", [])
            existing_patterns = existing.successful_harness_patterns or []
            pattern_names = {p.get("name") for p in existing_patterns}
            for pattern in new_patterns:
                if pattern.get("name") not in pattern_names:
                    existing_patterns.append(pattern)
            existing.successful_harness_patterns = existing_patterns[:20]  # Cap at 20

            # Merge blockers
            new_blockers = campaign_outcome.get("blockers_encountered", [])
            existing_blockers = existing.common_blockers or []
            blocker_types = {b.get("type") for b in existing_blockers}
            for blocker in new_blockers:
                if blocker.get("type") not in blocker_types:
                    existing_blockers.append(blocker)
            existing.common_blockers = existing_blockers[:20]  # Cap at 20

            # Merge strategies
            new_strategies = campaign_outcome.get("strategies_used", [])
            existing_strategies = existing.effective_strategies or []
            for strategy in new_strategies:
                if strategy not in existing_strategies:
                    existing_strategies.append(strategy)
            existing.effective_strategies = existing_strategies[:10]  # Cap at 10

        else:
            # Create new knowledge entry
            knowledge = TargetKnowledge(
                target_name=target_name,
                domain=profile.domain.value,
                complexity_score=profile.complexity_score,
                attack_surface=profile.attack_surface[:20],
                successful_harness_patterns=campaign_outcome.get("harness_patterns", [])[:20],
                common_blockers=campaign_outcome.get("blockers_encountered", [])[:20],
                effective_strategies=campaign_outcome.get("strategies_used", [])[:10],
                campaign_count=1,
                success_rate=1.0 if campaign_outcome.get("crashes_found", 0) > 0 else 0.0,
                avg_coverage_edges=campaign_outcome.get("coverage_edges", 0),
                avg_crashes_found=campaign_outcome.get("crashes_found", 0),
                notes=f"Learned from campaign on {datetime.now(UTC).isoformat()}",
            )
            session.add(knowledge)

        await session.commit()
        log.info("knowledge_base.target_knowledge_stored", target=target_name)


async def store_vulnerability_pattern(
    target_domain: str,
    bug_type: str,
    severity: str,
    severity_score: int,
    location_pattern: str,
    root_cause: str,
    bypass_strategy: str,
    crash_id: str,
) -> None:
    """Store or update a vulnerability pattern.

    Parameters
    ----------
    target_domain:
        Domain of the target (e.g., "image_processing").
    bug_type:
        Type of bug (e.g., "heap-buffer-overflow").
    severity:
        Severity level (e.g., "high").
    severity_score:
        Numeric severity (0-10).
    location_pattern:
        Pattern of where the bug was found (e.g., "parser.c:decode_buffer").
    root_cause:
        Summary of the root cause.
    bypass_strategy:
        Strategy that found this bug.
    crash_id:
        ID of the crash that exemplifies this pattern.
    """
    log.info(
        "knowledge_base.store_vulnerability_pattern",
        domain=target_domain,
        bug_type=bug_type,
    )

    async with get_session() as session:
        # Check if we already have this pattern
        result = await session.execute(
            select(VulnerabilityPattern).where(
                VulnerabilityPattern.target_domain == target_domain,
                VulnerabilityPattern.bug_type == bug_type,
                VulnerabilityPattern.location_pattern == location_pattern,
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Update existing pattern
            existing.frequency += 1
            existing.last_seen = datetime.now(UTC)
            if crash_id not in (existing.example_crash_ids or []):
                example_ids = existing.example_crash_ids or []
                example_ids.append(crash_id)
                existing.example_crash_ids = example_ids[:5]  # Cap at 5 examples
        else:
            # Create new pattern
            pattern = VulnerabilityPattern(
                target_domain=target_domain,
                bug_type=bug_type,
                severity=severity,
                severity_score=severity_score,
                location_pattern=location_pattern,
                root_cause_summary=root_cause[:1000],
                bypass_strategy=bypass_strategy[:1000],
                frequency=1,
                example_crash_ids=[crash_id],
            )
            session.add(pattern)

        await session.commit()
        log.info("knowledge_base.vulnerability_pattern_stored", bug_type=bug_type)


async def store_strategy_effectiveness(
    target_domain: str,
    strategy_arm_id: str,
    success: bool,
    coverage_gain: float,
    time_to_crash: float,
) -> None:
    """Store or update strategy effectiveness metrics.

    Parameters
    ----------
    target_domain:
        Domain of the target.
    strategy_arm_id:
        MAB strategy arm ID (e.g., "afl_default").
    success:
        Whether the strategy found crashes.
    coverage_gain:
        Coverage edges gained using this strategy.
    time_to_crash:
        Time in seconds to find first crash (0 if no crash).
    """
    log.info(
        "knowledge_base.store_strategy_effectiveness",
        domain=target_domain,
        strategy=strategy_arm_id,
    )

    async with get_session() as session:
        # Check if we already have this strategy-domain pair
        result = await session.execute(
            select(StrategyEffectiveness).where(
                StrategyEffectiveness.target_domain == target_domain,
                StrategyEffectiveness.strategy_arm_id == strategy_arm_id,
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Update existing metrics
            existing.total_count += 1
            if success:
                existing.success_count += 1

            existing.avg_coverage_gain = (
                (existing.avg_coverage_gain * (existing.total_count - 1))
                + coverage_gain
            ) / existing.total_count

            if time_to_crash > 0:
                existing.avg_time_to_crash = (
                    (existing.avg_time_to_crash * (existing.total_count - 1))
                    + time_to_crash
                ) / existing.total_count

            # Recalculate effectiveness score
            success_rate = existing.success_count / existing.total_count
            coverage_factor = min(1.0, existing.avg_coverage_gain / 1000.0)
            time_factor = 1.0 / (1.0 + existing.avg_time_to_crash / 3600.0) if existing.avg_time_to_crash > 0 else 0.5
            existing.effectiveness_score = (success_rate * 0.5) + (coverage_factor * 0.3) + (time_factor * 0.2)

        else:
            # Create new entry
            success_rate = 1.0 if success else 0.0
            coverage_factor = min(1.0, coverage_gain / 1000.0)
            time_factor = 1.0 / (1.0 + time_to_crash / 3600.0) if time_to_crash > 0 else 0.5
            effectiveness_score = (success_rate * 0.5) + (coverage_factor * 0.3) + (time_factor * 0.2)

            entry = StrategyEffectiveness(
                target_domain=target_domain,
                strategy_arm_id=strategy_arm_id,
                success_count=1 if success else 0,
                total_count=1,
                avg_coverage_gain=coverage_gain,
                avg_time_to_crash=time_to_crash,
                effectiveness_score=effectiveness_score,
            )
            session.add(entry)

        await session.commit()
        log.info("knowledge_base.strategy_effectiveness_stored", strategy=strategy_arm_id)


# ── Knowledge Query ──────────────────────────────────────────────────────────


async def query_similar_targets(
    domain: str,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Query knowledge about similar targets in the same domain.

    Parameters
    ----------
    domain:
        Target domain to search for.
    limit:
        Maximum number of results to return.

    Returns
    -------
    List of dicts with target knowledge, sorted by success_rate desc.
    """
    log.info("knowledge_base.query_similar_targets", domain=domain)

    async with get_session() as session:
        result = await session.execute(
            select(TargetKnowledge)
            .where(TargetKnowledge.domain == domain)
            .order_by(TargetKnowledge.success_rate.desc())
            .limit(limit)
        )
        targets = list(result.scalars().all())

        return [
            {
                "target_name": t.target_name,
                "domain": t.domain,
                "complexity_score": t.complexity_score,
                "attack_surface": t.attack_surface,
                "successful_harness_patterns": t.successful_harness_patterns,
                "common_blockers": t.common_blockers,
                "effective_strategies": t.effective_strategies,
                "success_rate": t.success_rate,
                "avg_coverage_edges": t.avg_coverage_edges,
                "avg_crashes_found": t.avg_crashes_found,
            }
            for t in targets
        ]


async def query_vulnerability_patterns(
    target_domain: str,
    bug_type: str | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Query vulnerability patterns for a domain.

    Parameters
    ----------
    target_domain:
        Domain to search for.
    bug_type:
        Optional filter by bug type.
    limit:
        Maximum number of results.

    Returns
    -------
    List of vulnerability patterns, sorted by frequency desc.
    """
    log.info("knowledge_base.query_vulnerability_patterns", domain=target_domain)

    async with get_session() as session:
        query = select(VulnerabilityPattern).where(
            VulnerabilityPattern.target_domain == target_domain
        )
        if bug_type:
            query = query.where(VulnerabilityPattern.bug_type == bug_type)

        query = query.order_by(VulnerabilityPattern.frequency.desc()).limit(limit)
        result = await session.execute(query)
        patterns = list(result.scalars().all())

        return [
            {
                "bug_type": p.bug_type,
                "severity": p.severity,
                "severity_score": p.severity_score,
                "location_pattern": p.location_pattern,
                "root_cause_summary": p.root_cause_summary,
                "bypass_strategy": p.bypass_strategy,
                "frequency": p.frequency,
            }
            for p in patterns
        ]


async def query_effective_strategies(
    target_domain: str,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Query most effective strategies for a domain.

    Parameters
    ----------
    target_domain:
        Domain to search for.
    limit:
        Maximum number of results.

    Returns
    -------
    List of strategy effectiveness data, sorted by effectiveness_score desc.
    """
    log.info("knowledge_base.query_effective_strategies", domain=target_domain)

    async with get_session() as session:
        result = await session.execute(
            select(StrategyEffectiveness)
            .where(StrategyEffectiveness.target_domain == target_domain)
            .order_by(StrategyEffectiveness.effectiveness_score.desc())
            .limit(limit)
        )
        strategies = list(result.scalars().all())

        return [
            {
                "strategy_arm_id": s.strategy_arm_id,
                "effectiveness_score": s.effectiveness_score,
                "success_rate": s.success_count / s.total_count if s.total_count > 0 else 0.0,
                "avg_coverage_gain": s.avg_coverage_gain,
                "avg_time_to_crash": s.avg_time_to_crash,
                "total_campaigns": s.total_count,
            }
            for s in strategies
        ]


# ── Knowledge Injection ──────────────────────────────────────────────────────


async def inject_target_knowledge(
    domain: str,
) -> dict[str, Any]:
    """Inject knowledge from similar targets into a new campaign.

    Parameters
    ----------
    domain:
        Target domain to search for similar targets.

    Returns
    -------
    Dict with aggregated knowledge: harness_patterns, blockers, strategies.
    """
    log.info("knowledge_base.inject_target_knowledge", domain=domain)

    similar_targets = await query_similar_targets(domain, limit=5)

    if not similar_targets:
        log.info("knowledge_base.no_similar_targets_found", domain=domain)
        return {
            "harness_patterns": [],
            "common_blockers": [],
            "effective_strategies": [],
            "similar_targets_count": 0,
        }

    # Aggregate patterns from similar targets
    all_patterns = []
    all_blockers = []
    all_strategies = []

    for target in similar_targets:
        all_patterns.extend(target.get("successful_harness_patterns", []))
        all_blockers.extend(target.get("common_blockers", []))
        all_strategies.extend(target.get("effective_strategies", []))

    # Deduplicate and rank by frequency
    pattern_names = {}
    for pattern in all_patterns:
        name = pattern.get("name", "")
        pattern_names[name] = pattern_names.get(name, 0) + 1

    top_patterns = sorted(
        pattern_names.items(),
        key=lambda x: x[1],
        reverse=True,
    )[:10]

    # Get full pattern details for top patterns (deduplicated)
    top_pattern_names = {name for name, _ in top_patterns}
    seen_pattern_names = set()
    deduped_patterns = []
    for p in all_patterns:
        name = p.get("name", "")
        if name in top_pattern_names and name not in seen_pattern_names:
            deduped_patterns.append(p)
            seen_pattern_names.add(name)

    blocker_types = {}
    for blocker in all_blockers:
        btype = blocker.get("type", "")
        blocker_types[btype] = blocker_types.get(btype, 0) + 1

    top_blockers = sorted(
        blocker_types.items(),
        key=lambda x: x[1],
        reverse=True,
    )[:10]

    # Deduplicate blockers by type
    top_blocker_types = {btype for btype, _ in top_blockers}
    seen_blocker_types = set()
    deduped_blockers = []
    for b in all_blockers:
        btype = b.get("type", "")
        if btype in top_blocker_types and btype not in seen_blocker_types:
            deduped_blockers.append(b)
            seen_blocker_types.add(btype)

    strategy_counts = {}
    for strategy in all_strategies:
        strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1

    top_strategies = sorted(
        strategy_counts.items(),
        key=lambda x: x[1],
        reverse=True,
    )[:5]
    deduped_strategies = [s for s, _ in top_strategies]

    result = {
        "harness_patterns": deduped_patterns,
        "common_blockers": deduped_blockers,
        "effective_strategies": deduped_strategies,
        "similar_targets_count": len(similar_targets),
    }

    log.info(
        "knowledge_base.knowledge_injected",
        domain=domain,
        similar_count=len(similar_targets),
        patterns=len(deduped_patterns),
        blockers=len(deduped_blockers),
        strategies=len(deduped_strategies),
    )

    return result


__all__ = [
    "StrategyEffectiveness",
    "TargetKnowledge",
    "VulnerabilityPattern",
    "inject_target_knowledge",
    "query_effective_strategies",
    "query_similar_targets",
    "query_vulnerability_patterns",
    "store_strategy_effectiveness",
    "store_target_knowledge",
    "store_vulnerability_pattern",
]
