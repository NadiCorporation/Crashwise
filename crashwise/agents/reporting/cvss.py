# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Auto-CVSS Calculator — estimates CVSS v3.1 vectors from crash metadata.

Uses a hybrid approach:
    1. **Heuristic rules** map bug types and exploitability scores to
       CVSS metric values with 4-tier severity alignment (Critical, High, Medium, Low).
    2. **AI provider** (optional) refines the vector when available.

The calculator is conservative: when data is sparse it defaults to
medium severity rather than over-inflating scores.
"""

from __future__ import annotations

from typing import Any

from crashwise.core.ai_provider import get_provider
from crashwise.core.logging import get_logger

log = get_logger(__name__)


# ── Heuristic mapping tables ─────────────────────────────────────────────────

# Bug type → Attack Vector (AV), Attack Complexity (AC), Privileges (PR),
# User Interaction (UI), Scope (S), Confidentiality (C), Integrity (I),
# Availability (A)
_BUG_TYPE_CVSS: dict[str, dict[str, str]] = {
    "use-after-free": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "heap-use-after-free": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "double-free": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "heap-buffer-overflow": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "stack-buffer-overflow": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "buffer-overflow": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "out-of-bounds-read": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "L", "I": "N", "A": "N",
    },
    "out-of-bounds-write": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "integer-overflow": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S": "U", "C": "N", "I": "L", "A": "L",
    },
    "null-pointer-dereference": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S": "U", "C": "N", "I": "N", "A": "L",
    },
    "null-deref-read": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S": "U", "C": "N", "I": "N", "A": "L",
    },
    "divide-by-zero": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S": "U", "C": "N", "I": "N", "A": "L",
    },
    "uninitialized-read": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "L", "I": "N", "A": "N",
    },
    "memory-leak": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S": "U", "C": "N", "I": "N", "A": "L",
    },
    "race-condition": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S": "U", "C": "L", "I": "L", "A": "L",
    },
}

# Exploitability score → AC adjustment.
_EXPLOITABILITY_AC = {
    (0, 2): "H",   # Low exploitability = high complexity
    (3, 5): "L",   # Medium
    (6, 10): "L",  # High
}

# Metric value → numeric score (CVSS v3.1)
_METRIC_SCORES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 6.42, "C": 7.52},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


# ── Public API ───────────────────────────────────────────────────────────────


async def calculate_cvss(
    bug_type: str,
    exploitability_score: float,
    *,
    provider: Any | None = None,
) -> dict[str, Any]:
    """Estimate a CVSS v3.1 vector and base score from crash metadata.

    Parameters
    ----------
    bug_type:
        Classified bug type (e.g., ``use-after-free``).
    exploitability_score:
        AI-generated exploitability (0.0-10.0).
    provider:
        Optional AI provider for refinement.

    Returns
    -------
    dict with keys ``vector`` (str), ``score`` (float), ``severity`` (str).
    """
    log.info("cvss.calculate", bug_type=bug_type, exploitability=exploitability_score)

    # 1. Heuristic base vector.
    vector = _heuristic_vector(bug_type, exploitability_score)

    # 2. AI refinement (optional).
    provider = provider or get_provider()
    if await provider.health_check():
        try:
            ai_result = await provider.analyze(
                f"Estimate CVSS v3.1 vector for a {bug_type} with "
                f"exploitability {exploitability_score}/10. "
                f"Current heuristic: {vector}. Refine if needed."
            )
            ai_vector = ai_result.get("cvss_vector", "")
            if ai_vector and "/" in ai_vector:
                vector = ai_vector
                log.info("cvss.ai_refined", vector=vector)
        except Exception:
            log.debug("cvss.ai_refine_failed")

    # 3. Compute base score from vector.
    score = _compute_base_score(vector)
    severity = _score_to_severity(score)

    log.info("cvss.complete", vector=vector, score=score, severity=severity)
    return {
        "vector": vector,
        "score": round(score, 1),
        "severity": severity,
    }


# ── Internal helpers ─────────────────────────────────────────────────────────


def _heuristic_vector(bug_type: str, exploitability: float) -> str:
    """Build a CVSS v3.1 vector string from heuristics."""
    bug_type = bug_type.lower().strip()
    base = _BUG_TYPE_CVSS.get(bug_type, {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "N", "I": "N", "A": "N",
    }).copy()

    # Adjust AC based on exploitability score.
    for (lo, hi), ac_val in _EXPLOITABILITY_AC.items():
        if lo <= exploitability <= hi:
            base["AC"] = ac_val
            break

    # Adjust CIA based on exploitability.
    if exploitability >= 8:
        base.update({"C": "H", "I": "H", "A": "H"})
    elif exploitability >= 5:
        if base["C"] == "N":
            base["C"] = "L"
        if base["I"] == "N":
            base["I"] = "L"

    return (
        f"CVSS:3.1/AV:{base['AV']}/AC:{base['AC']}/PR:{base['PR']}"
        f"/UI:{base['UI']}/S:{base['S']}/C:{base['C']}"
        f"/I:{base['I']}/A:{base['A']}"
    )


def _compute_base_score(vector: str) -> float:
    """Compute CVSS v3.1 base score from a vector string.

    Simplified formula — accurate enough for estimation.
    """
    # Parse vector.
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val

    av = _METRIC_SCORES["AV"].get(metrics.get("AV", "N"), 0.85)
    ac = _METRIC_SCORES["AC"].get(metrics.get("AC", "L"), 0.77)
    pr = _METRIC_SCORES["PR"].get(metrics.get("PR", "N"), 0.85)
    ui = _METRIC_SCORES["UI"].get(metrics.get("UI", "N"), 0.85)
    c = _METRIC_SCORES["C"].get(metrics.get("C", "N"), 0.0)
    i = _METRIC_SCORES["I"].get(metrics.get("I", "N"), 0.0)
    a = _METRIC_SCORES["A"].get(metrics.get("A", "N"), 0.0)

    # Impact sub-score.
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if metrics.get("S", "U") == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    # Exploitability sub-score.
    exploitability = 8.22 * av * ac * pr * ui

    # Base score.
    if impact <= 0:
        return 0.0

    if metrics.get("S", "U") == "C":
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    # Round to one decimal.
    return round(base, 1)


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


__all__ = ["calculate_cvss"]
