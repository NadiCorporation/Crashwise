# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Triage analyzer — classify crashes from ASAN / GDB output.

The agent consumes raw crash logs, parses them into :class:`CrashReport`
objects, and uses an LLM (with deterministic fallback heuristics) to
classify the bug type, severity, and root cause.

Autonomy guarantee: if the LLM is unreachable or returns garbage, the
fallback regex heuristics still produce a valid :class:`TriageResult`.
"""

from __future__ import annotations

import json
import re

from langchain_core.messages import HumanMessage, SystemMessage

from crashwise.agents.harness_synth.llm import get_chat_model
from crashwise.agents.triage.dedup import CrashDeduper
from crashwise.agents.triage.models import (
    BugType,
    CrashReport,
    TriageResult,
)
from crashwise.core.logging import get_logger

log = get_logger(__name__)

_SYSTEM_PROMPT = """\
You are a senior vulnerability researcher specialising in crash triage.
You analyse AddressSanitizer (ASAN) and GDB crash logs to classify memory
safety bugs.

You MUST respond with a single JSON object (no markdown fences, no prose):

{
  "bug_type": "<one of: use-after-free|double-free|heap-buffer-overflow|stack-buffer-overflow|buffer-overflow|out-of-bounds-read|out-of-bounds-write|integer-overflow|null-pointer-dereference|divide-by-zero|uninitialized-read|memory-leak|race-condition|unknown>",
  "severity": "<low|medium|high|critical>",
  "root_cause": "<one-paragraph technical explanation>",
  "confidence": <0.0-1.0>,
  "recommendations": ["<actionable step 1>", "<actionable step 2>"]
}

Rules:
  • If ASAN says "heap-buffer-overflow" → bug_type must be heap-buffer-overflow.
  • If ASAN says "use-after-free" → bug_type must be use-after-free.
  • If GDB shows SIGSEGV inside a free() call chain → likely double-free.
  • If the PC is 0x0 or near-null → null-pointer-dereference.
  • Be conservative: when uncertain set confidence < 0.5 and bug_type "unknown".
"""

# ── Regex heuristics (fallback when LLM is unavailable) ──────────────────────
_ASAN_BUG_RE = re.compile(r"ERROR:\s*AddressSanitizer:\s*(\S+)", re.IGNORECASE)
_SIGNAL_RE = re.compile(r"(SIG[A-Z]+|signal\s+\d+)", re.IGNORECASE)


async def triage_crash(report: CrashReport, *, deduper: CrashDeduper | None = None) -> TriageResult:
    """Analyse a single crash and return a structured triage result.

    Parameters
    ----------
    report:
        Parsed crash data (raw text, stack frames, ASAN/GDB blocks).
    deduper:
        Optional deduplication engine. If ``None``, a fresh one is created.
    """
    if deduper is None:
        deduper = CrashDeduper()

    dedup_result = deduper.check(report)
    if dedup_result.duplicate_of is not None:
        log.info(
            "triage.analyzer.duplicate",
            crash_id=report.crash_id,
            duplicate_of=dedup_result.duplicate_of,
        )
        return TriageResult(
            bug_type=BugType.UNKNOWN,
            severity="unknown",
            root_cause=f"Duplicate of {dedup_result.duplicate_of}",
            confidence=1.0,
            stack_hash=dedup_result.stack_hash,
            duplicate_of=dedup_result.duplicate_of,
            recommendations=[],
        )

    # Try LLM first.
    llm_result = await _llm_triage(report)
    if llm_result is not None:
        llm_result.stack_hash = dedup_result.stack_hash
        return llm_result

    # Fallback: regex heuristics.
    fallback = _heuristic_triage(report)
    fallback.stack_hash = dedup_result.stack_hash
    log.info(
        "triage.analyzer.fallback",
        crash_id=report.crash_id,
        bug_type=fallback.bug_type.value,
    )
    return fallback


# ── LLM path ───────────────────────────────────────────────────────────────────
async def _llm_triage(report: CrashReport) -> TriageResult | None:
    """Ask the LLM for a structured classification. Returns ``None`` on failure."""
    try:
        chat = get_chat_model()
        user_text = _build_user_prompt(report)
        messages = [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=user_text),
        ]
        response = await chat.ainvoke(messages)
    except Exception as exc:
        log.warning("triage.analyzer.llm_error", error=str(exc))
        return None

    raw = _extract_text(response)
    parsed = _safe_parse_json(raw)
    if parsed is None:
        log.warning("triage.analyzer.llm_unparseable", raw_preview=raw[:200])
        return None

    bt_raw = str(parsed.get("bug_type", "unknown"))
    try:
        bug_type = BugType(bt_raw)
    except ValueError:
        bug_type = BugType.UNKNOWN

    sev_raw = str(parsed.get("severity", "unknown")).lower()
    severity = sev_raw if sev_raw in {"low", "medium", "high", "critical", "unknown"} else "unknown"

    conf_raw = parsed.get("confidence", 0.0)
    try:
        confidence = float(conf_raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        confidence = 0.0

    recs_raw = parsed.get("recommendations", [])
    recommendations = [str(r) for r in recs_raw] if isinstance(recs_raw, list) else []

    return TriageResult(
        bug_type=bug_type,
        severity=severity,
        root_cause=str(parsed.get("root_cause", "")),
        confidence=confidence,
        recommendations=recommendations,
    )


def _build_user_prompt(report: CrashReport) -> str:
    parts: list[str] = [
        f"Crash ID: {report.crash_id}",
        f"Signal: {report.signal or 'N/A'}",
    ]
    if report.asan_output:
        parts.append(f"ASAN output:\n{report.asan_output}")
    if report.gdb_output:
        parts.append(f"GDB output:\n{report.gdb_output}")
    if not report.asan_output and not report.gdb_output:
        parts.append(f"Raw log:\n{report.raw_text[:4000]}")
    return "\n\n".join(parts)


def _extract_text(response: object) -> str:
    """Unwrap LangChain AIMessage content."""
    if hasattr(response, "content"):
        content = response.content
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            texts = [str(x) if isinstance(x, str) else str(x.get("text", "")) for x in content]
            return "\n".join(texts)
    return str(response)


def _safe_parse_json(text: str) -> dict[str, object] | None:
    """Best-effort JSON extraction from an LLM response."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    try:
        data: object = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                data = json.loads(text[start : end + 1])
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass
    return None


# ── Heuristic fallback ───────────────────────────────────────────────────────
def _heuristic_triage(report: CrashReport) -> TriageResult:
    """Rule-based classification when the LLM is unavailable."""
    text = f"{report.asan_output}\n{report.gdb_output}\n{report.raw_text}".lower()

    # ASAN gives us the most reliable signal.
    asan_match = _ASAN_BUG_RE.search(report.asan_output)
    if asan_match:
        asan_type = asan_match.group(1).lower()
        bug_map: dict[str, BugType] = {
            "heap-buffer-overflow": BugType.HEAP_BUFFER_OVERFLOW,
            "stack-buffer-overflow": BugType.STACK_BUFFER_OVERFLOW,
            "buffer-overflow": BugType.BUFFER_OVERFLOW,
            "heap-use-after-free": BugType.HEAP_USE_AFTER_FREE,
            "use-after-free": BugType.USE_AFTER_FREE,
            "double-free": BugType.DOUBLE_FREE,
            "memory-leak": BugType.MEMORY_LEAK,
            "initialization-order-fiasco": BugType.UNINITIALIZED_READ,
        }
        bug_type = bug_map.get(asan_type, BugType.UNKNOWN)
        severity = _severity_from_bug_type(bug_type)
        return TriageResult(
            bug_type=bug_type,
            severity=severity,
            root_cause=f"ASAN detected: {asan_match.group(1)}",
            confidence=0.85,
            recommendations=["Review ASAN report for exact allocation site"],
        )

    # Signal-based heuristics.
    if "sigsegv" in text or "segmentation fault" in text:
        # Distinguish null-deref vs general OOB by looking at PC.
        if report.registers.get("pc", "") == "0x0" or "pc=0x0" in text:
            return TriageResult(
                bug_type=BugType.NULL_POINTER_DEREF,
                severity="high",
                root_cause="SIGSEGV at null PC — null pointer dereference",
                confidence=0.7,
                recommendations=["Audit pointer validation before dereference"],
            )
        return TriageResult(
            bug_type=BugType.OUT_OF_BOUNDS_WRITE,
            severity="high",
            root_cause="SIGSEGV during memory access — likely out-of-bounds",
            confidence=0.5,
            recommendations=["Check array bounds and pointer arithmetic"],
        )

    if "sigfpe" in text or "divide by zero" in text:
        return TriageResult(
            bug_type=BugType.DIVIDE_BY_ZERO,
            severity="medium",
            root_cause="SIGFPE — division by zero or integer overflow",
            confidence=0.7,
            recommendations=["Validate denominator before division"],
        )

    if "sigabrt" in text or "assertion failed" in text:
        return TriageResult(
            bug_type=BugType.UNKNOWN,
            severity="low",
            root_cause="SIGABRT / assertion failure — logic bug, not necessarily memory safety",
            confidence=0.6,
            recommendations=["Review assertion conditions and invariants"],
        )

    return TriageResult(
        bug_type=BugType.UNKNOWN,
        severity="unknown",
        root_cause="Insufficient information for heuristic classification",
        confidence=0.0,
        recommendations=["Re-run with ASAN for clearer diagnostics"],
    )


def _severity_from_bug_type(bug_type: BugType) -> str:
    """Map bug class to coarse severity."""
    critical = {
        BugType.USE_AFTER_FREE,
        BugType.DOUBLE_FREE,
        BugType.HEAP_USE_AFTER_FREE,
        BugType.HEAP_BUFFER_OVERFLOW,
        BugType.STACK_BUFFER_OVERFLOW,
    }
    high = {
        BugType.OUT_OF_BOUNDS_WRITE,
        BugType.NULL_POINTER_DEREF,
        BugType.BUFFER_OVERFLOW,
    }
    medium = {
        BugType.OUT_OF_BOUNDS_READ,
        BugType.INTEGER_OVERFLOW,
        BugType.UNINITIALIZED_READ,
        BugType.RACE_CONDITION,
    }
    if bug_type in critical:
        return "critical"
    if bug_type in high:
        return "high"
    if bug_type in medium:
        return "medium"
    return "low"


# ── Public batch API ─────────────────────────────────────────────────────────
async def triage_batch(
    reports: list[CrashReport],
) -> list[TriageResult]:
    """Triage multiple crashes with a shared deduplication table."""
    deduper = CrashDeduper()
    results: list[TriageResult] = []
    for report in reports:
        result = await triage_crash(report, deduper=deduper)
        results.append(result)
    return results


__all__ = ["triage_batch", "triage_crash"]
