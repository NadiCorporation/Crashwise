# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``store_campaign_knowledge`` activity — persist campaign insights for cross-campaign learning.

This activity stores knowledge about a completed campaign in the knowledge base,
enabling future campaigns to learn from past successes and failures.

Stored knowledge includes:
- Target profile and domain
- Successful harness patterns
- Common blockers encountered
- Effective strategies used
- Vulnerability patterns discovered
"""

from __future__ import annotations

from typing import Any

from temporalio import activity

from crashwise.agents.research.knowledge_base import (
    store_strategy_effectiveness,
    store_target_knowledge,
    store_vulnerability_pattern,
)
from crashwise.core.logging import get_logger
from crashwise.core.models import TargetProfile

log = get_logger(__name__)


@activity.defn(name="store_campaign_knowledge")
async def store_campaign_knowledge(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Store campaign knowledge for cross-campaign learning.

    Parameters
    ----------
    payload:
        Dict with keys:
        - target_name: str
        - target_profile: dict (TargetProfile serialized)
        - campaign_outcome: dict with:
            - crashes_found: int
            - coverage_edges: int
            - strategies_used: list[str]
            - harness_patterns: list[dict]
            - blockers_encountered: list[dict]
        - vulnerabilities: list[dict] (optional)
        - strategy_metrics: list[dict] (optional)

    Returns
    -------
    Dict with keys:
        - stored: bool
        - target_knowledge_stored: bool
        - vulnerability_patterns_stored: int
        - strategy_effectiveness_stored: int
    """
    info = activity.info()
    log.info(
        "store_campaign_knowledge.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        target_name=payload.get("target_name", "unknown"),
    )

    result = {
        "stored": False,
        "target_knowledge_stored": False,
        "vulnerability_patterns_stored": 0,
        "strategy_effectiveness_stored": 0,
    }

    try:
        # Store target knowledge
        target_name = payload.get("target_name", "")
        target_profile_dict = payload.get("target_profile", {})
        campaign_outcome = payload.get("campaign_outcome", {})

        if target_name and target_profile_dict and campaign_outcome:
            # Reconstruct TargetProfile from dict
            target_profile = TargetProfile(**target_profile_dict)
            await store_target_knowledge(
                target_name=target_name,
                profile=target_profile,
                campaign_outcome=campaign_outcome,
            )
            result["target_knowledge_stored"] = True
            log.info(
                "store_campaign_knowledge.target_stored",
                target_name=target_name,
            )

        # Store vulnerability patterns
        vulnerabilities = payload.get("vulnerabilities", [])
        target_domain = target_profile_dict.get("domain", "unknown")

        for vuln in vulnerabilities:
            try:
                await store_vulnerability_pattern(
                    target_domain=target_domain,
                    bug_type=vuln.get("bug_type", "unknown"),
                    severity=vuln.get("severity", "unknown"),
                    severity_score=vuln.get("severity_score", 0),
                    location_pattern=vuln.get("location_pattern", ""),
                    root_cause=vuln.get("root_cause", ""),
                    bypass_strategy=vuln.get("bypass_strategy", ""),
                    crash_id=vuln.get("crash_id", ""),
                )
                result["vulnerability_patterns_stored"] += 1
            except Exception as exc:
                log.warning(
                    "store_campaign_knowledge.vuln_pattern_failed",
                    error=str(exc)[:200],
                )

        # Store strategy effectiveness
        strategy_metrics = payload.get("strategy_metrics", [])

        for metric in strategy_metrics:
            try:
                await store_strategy_effectiveness(
                    target_domain=target_domain,
                    strategy_arm_id=metric.get("strategy_arm_id", ""),
                    success=metric.get("success", False),
                    coverage_gain=metric.get("coverage_gain", 0.0),
                    time_to_crash=metric.get("time_to_crash", 0.0),
                )
                result["strategy_effectiveness_stored"] += 1
            except Exception as exc:
                log.warning(
                    "store_campaign_knowledge.strategy_effectiveness_failed",
                    error=str(exc)[:200],
                )

        result["stored"] = True
        log.info(
            "store_campaign_knowledge.complete",
            target_name=target_name,
            vuln_patterns=result["vulnerability_patterns_stored"],
            strategy_metrics=result["strategy_effectiveness_stored"],
        )

    except Exception as exc:
        log.error(
            "store_campaign_knowledge.failed",
            error=str(exc)[:500],
            exc_info=True,
        )
        # Don't raise — knowledge storage is best-effort

    return result


__all__ = ["store_campaign_knowledge"]
