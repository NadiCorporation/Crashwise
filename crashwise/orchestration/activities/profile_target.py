# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``profile_target`` activity — static analysis pass that characterises a
target codebase before fuzzing begins.

The activity delegates to :func:`crashwise.agents.research.profiler.profile_target`
and persists the resulting :class:`TargetProfile` to the campaign record.

This is the first activity in a target-aware fuzzing campaign: the profile
feeds into harness synthesis, execution dispatch, and root-cause analysis.
"""

from __future__ import annotations

from temporalio import activity

from crashwise.agents.research.profiler import profile_target as _profile_target
from crashwise.core.database import Campaign, get_session
from crashwise.core.logging import get_logger
from crashwise.core.models import ProfileTargetInput, ProfileTargetOutput

log = get_logger(__name__)


@activity.defn(name="profile_target")
async def profile_target(payload: ProfileTargetInput) -> ProfileTargetOutput:
    """Profile a target codebase and optionally persist to the DB.

    Parameters
    ----------
    payload:
        ``workdir`` (cloned repo path) and optional file restrictions.

    Returns
    -------
    Structured profile with domain, complexity, attack surface, and
    execution recommendations.
    """
    info = activity.info()
    log.info(
        "profile_target.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        workdir=str(payload.workdir),
    )

    result = await _profile_target(payload)

    log.info(
        "profile_target.complete",
        domain=result.profile.domain.value,
        complexity=result.profile.complexity_score,
        files=result.files_scanned,
        duration=result.duration_seconds,
    )

    return result


__all__ = ["profile_target"]
