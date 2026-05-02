# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Auto-patcher — suggests minimal C/C++ fixes from root-cause analyses.

The patcher consumes the output of the triage / RCA agent and produces
a production-quality code diff.  It is deliberately conservative: when
the root cause is ambiguous it returns a low-confidence explanation
rather than a potentially dangerous patch.
"""

from __future__ import annotations

from crashwise.core.ai_provider import BaseInference, get_provider
from crashwise.core.logging import get_logger

log = get_logger(__name__)


async def suggest_patch(
    root_cause: str,
    *,
    provider: BaseInference | None = None,
) -> dict[str, str | float]:
    """Generate a minimal patch from a root-cause analysis.

    Parameters
    ----------
    root_cause:
        One-paragraph technical explanation of the bug (from triage).
    provider:
        Optional inference provider.  When ``None``, the default provider
        is resolved from settings.

    Returns
    -------
    dict with keys ``patch`` (str), ``explanation`` (str), ``confidence`` (float).
    """
    if not root_cause or root_cause.strip().lower().startswith("ai provider not configured"):
        log.debug("patcher.no_root_cause")
        return {
            "patch": "",
            "explanation": "No root cause available — skipping patch generation",
            "confidence": 0.0,
        }

    provider = provider or get_provider()
    result = await provider.suggest_patch(root_cause)

    log.info(
        "patcher.complete",
        confidence=result.get("confidence", 0.0),
        patch_len=len(result.get("patch", "")),
    )
    return {
        "patch": str(result.get("patch", "")),
        "explanation": str(result.get("explanation", "")),
        "confidence": float(result.get("confidence", 0.0)),
    }


__all__ = ["suggest_patch"]
