# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``notify_stakeholders`` activity — dispatches vulnerability alerts after
successful verification.

Triggered automatically by :class:`VerifyPatchWorkflow` when a bug is
verified as ``fixed`` and the CVSS score exceeds the configured threshold.
"""

from __future__ import annotations

from temporalio import activity

from crashwise.core.logging import get_logger
from crashwise.core.notifications import NotificationConfig, NotificationRouter

log = get_logger(__name__)


@activity.defn(name="notify_stakeholders")
async def notify_stakeholders(
    title: str,
    body: str,
    severity: str,
    cvss_score: float,
    cvss_vector: str,
    target: str,
    crash_id: str,
) -> dict[str, bool]:
    """Send notifications to configured channels.

    Parameters
    ----------
    title, body, severity, cvss_score, cvss_vector, target, crash_id:
        Report metadata used to build notification payloads.

    Returns
    -------
    dict mapping channel name → success bool.
    """
    info = activity.info()
    log.info(
        "notify_stakeholders.start",
        workflow_id=info.workflow_id,
        crash_id=crash_id,
        cvss=cvss_score,
    )

    router = NotificationRouter()
    results = await router.send(
        title=title,
        body=body,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        target=target,
        crash_id=crash_id,
    )

    log.info("notify_stakeholders.complete", results=results)
    return results


__all__ = ["notify_stakeholders"]
