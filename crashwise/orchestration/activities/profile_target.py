# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``profile_target`` activity — static analysis pass that characterises a
target codebase before fuzzing begins.

The activity delegates to :func:`crashwise.agents.research.profiler.profile_target`
and optionally enriches the result with semantic LLM analysis via
:func:`crashwise.agents.research.semantic_profiler.enrich_profile_with_semantics`.

Additionally, it injects knowledge from similar past targets via
:func:`crashwise.agents.research.knowledge_base.inject_target_knowledge`
to improve harness synthesis and strategy selection.

This is the first activity in a target-aware fuzzing campaign: the profile
feeds into harness synthesis, execution dispatch, and root-cause analysis.
"""

from __future__ import annotations

from temporalio import activity

from crashwise.agents.research.knowledge_base import inject_target_knowledge
from crashwise.agents.research.profiler import profile_target as _profile_target
from crashwise.agents.research.semantic_profiler import enrich_profile_with_semantics
from crashwise.core.logging import get_logger
from crashwise.core.models import ProfileTargetInput, ProfileTargetOutput

log = get_logger(__name__)


@activity.defn(name="profile_target")
async def profile_target(payload: ProfileTargetInput) -> ProfileTargetOutput:
    """Profile a target codebase and optionally persist to the DB.

    Parameters
    ----------
    payload:
        ``workdir`` (cloned repo path), optional file restrictions, and
        ``enable_semantic_profiling`` flag to control LLM enrichment.

    Returns
    -------
    Structured profile with domain, complexity, attack surface, and
    execution recommendations. Includes semantic insights when enabled
    and knowledge from similar past targets.
    """
    info = activity.info()
    log.info(
        "profile_target.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        workdir=str(payload.workdir),
        semantic_enabled=payload.enable_semantic_profiling,
    )

    # Step 1: Regex-based profiling (fast, always works)
    result = await _profile_target(payload)

    # Step 2: Semantic enrichment (LLM-powered, optional)
    if payload.enable_semantic_profiling:
        log.info("profile_target.semantic_enrichment_start")
        result.profile = await enrich_profile_with_semantics(
            workdir=payload.workdir,
            base_profile=result.profile,
        )
        log.info("profile_target.semantic_enrichment_complete")

    # Step 3: Inject knowledge from similar past targets
    try:
        log.info("profile_target.knowledge_injection_start", domain=result.profile.domain.value)
        injected_knowledge = await inject_target_knowledge(
            domain=result.profile.domain.value,
        )

        if injected_knowledge["similar_targets_count"] > 0:
            # Merge injected knowledge into profile notes
            knowledge_note = (
                f"\n\nCross-Campaign Learning: Found {injected_knowledge['similar_targets_count']} "
                f"similar past targets. "
            )

            if injected_knowledge["harness_patterns"]:
                knowledge_note += f"{len(injected_knowledge['harness_patterns'])} successful harness patterns. "

            if injected_knowledge["common_blockers"]:
                knowledge_note += f"{len(injected_knowledge['common_blockers'])} common blockers. "

            if injected_knowledge["effective_strategies"]:
                knowledge_note += f"Effective strategies: {', '.join(injected_knowledge['effective_strategies'][:3])}. "

            result.profile.notes += knowledge_note

            # Store injected knowledge for downstream use
            # (harness synthesis can access this via the profile)
            if not hasattr(result.profile, "injected_knowledge"):
                # Add as a dynamic attribute
                object.__setattr__(result.profile, "injected_knowledge", injected_knowledge)

            log.info(
                "profile_target.knowledge_injection_complete",
                similar_count=injected_knowledge["similar_targets_count"],
                patterns=len(injected_knowledge["harness_patterns"]),
                blockers=len(injected_knowledge["common_blockers"]),
                strategies=len(injected_knowledge["effective_strategies"]),
            )
        else:
            log.info("profile_target.knowledge_injection_no_similar_targets")
    except Exception as exc:
        log.warning(
            "profile_target.knowledge_injection_failed",
            error=str(exc)[:200],
        )
        # Knowledge injection is best-effort — don't fail the profiling

    log.info(
        "profile_target.complete",
        domain=result.profile.domain.value,
        complexity=result.profile.complexity_score,
        files=result.files_scanned,
        duration=result.duration_seconds,
    )

    return result


__all__ = ["profile_target"]
