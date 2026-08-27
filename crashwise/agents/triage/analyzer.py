# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Triage analyzer — classify crashes from ASAN / GDB output with 4-tier severity.

The agent consumes raw crash logs, parses them into :class:`CrashReport`
objects, and classifies the bug type, 4-tier severity (CRITICAL, HIGH, MEDIUM, LOW),
and root cause.

Severity Tiers:
  • CRITICAL (9.0 - 10.0): Write-what-where, out-of-bounds write, controlled IP.
  • HIGH (7.0 - 8.9): Use-after-free, double-free.
  • MEDIUM (4.0 - 6.9): Out-of-bounds read, uninitialized read.
  • LOW (1.0 - 3.9): Null pointer dereference on read, divide by zero, assertion abort.

Autonomy guarantee: if the LLM is unreachable or returns garbage, the
deterministic fallback heuristics produce a valid :class:`TriageResult`.
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
from crashwise.core.models import CrashSeverity

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

Severity Rules:
  • CRITICAL: Write-what-where primitives (WRITE of size X), out-of-bounds writes, controlled instruction pointer (pc 0x41414141).
  • HIGH: Heap use-after-free, double-free.
  • MEDIUM: Out-of-bounds read (READ of size X), uninitialized memory read.
  • LOW: Null pointer dereference on read, division by zero, logic assertion failure.
"""

# ── Regex heuristics (fallback when LLM is unavailable) ──────────────────────
_ASAN_BUG_RE = re.compile(r"ERROR:\s*AddressSanitizer:\s*(\S+)", re.IGNORECASE)
_SIGNAL_RE = re.compile(r"(SIG[A-Z]+|signal\s+\d+)", re.IGNORECASE)


def classify_crash_severity(
    *,
    bug_type: BugType | str = BugType.UNKNOWN,
    asan_output: str = "",
    registers: dict[str, str] | None = None,
    raw_text: str = "",
    gdb_output: str = "",
) -> tuple[CrashSeverity, float, str]:
    """Classify crash severity into the 4-tier hierarchy.

    Tiers:
      • CRITICAL (9.0 - 10.0): Controlled instruction pointer, write-what-where primitives,
        heap/stack/buffer overflow on WRITE.
      • HIGH (7.0 - 8.9): Heap use-after-free, double-free.
      • MEDIUM (4.0 - 6.9): Out-of-bounds read (READ of size X), uninitialized memory read,
        integer overflow.
      • LOW (1.0 - 3.9): Null pointer dereference on read, division by zero, assertion failure /
        abort without corruption.
      • UNKNOWN (0.0): Incomplete or unclassifiable logs.

    Returns
    -------
    tuple[CrashSeverity, float, str]
        (severity_level, numeric_score, primitive_description)
    """
    text = f"{asan_output}\n{gdb_output}\n{raw_text}".lower()
    regs = registers or {}

    # 1. Controlled Instruction Pointer (Highest Tier - Critical 10.0)
    pc = regs.get("pc", "") or regs.get("rip", "") or regs.get("eip", "")
    is_controlled_ip = False
    if pc:
        pc_clean = pc.lower().strip()
        if pc_clean in ("0x41414141", "0x4141414141414141", "0x42424242", "0x4242424242424242", "0x43434343") or "41414141" in pc_clean:
            is_controlled_ip = True
    if "pc 0x41414141" in text or "pc=0x41414141" in text or "rip 0x41414141" in text:
        is_controlled_ip = True

    if is_controlled_ip:
        return CrashSeverity.CRITICAL, 10.0, "controlled-ip"

    # Normalize bug_type
    bt_enum = bug_type if isinstance(bug_type, BugType) else None
    if bt_enum is None and isinstance(bug_type, str):
        try:
            bt_enum = BugType(bug_type.lower())
        except ValueError:
            bt_enum = BugType.UNKNOWN

    # 2. Write-what-where primitives & buffer overflow on write (Critical 9.0 - 9.8)
    if bt_enum == BugType.OUT_OF_BOUNDS_WRITE or "out-of-bounds-write" in text:
        return CrashSeverity.CRITICAL, 9.5, "out-of-bounds-write"

    if "write of size" in text:
        return CrashSeverity.CRITICAL, 9.5, "write-what-where"

    if bt_enum in (BugType.HEAP_BUFFER_OVERFLOW, BugType.STACK_BUFFER_OVERFLOW, BugType.BUFFER_OVERFLOW):
        if "read of size" in text and "write of size" not in text:
            return CrashSeverity.MEDIUM, 5.5, "heap-buffer-overflow-read"
        return CrashSeverity.CRITICAL, 9.2, "heap-buffer-overflow-write"

    # 3. Use-after-free & Double-free (High 7.0 - 8.9)
    if bt_enum in (BugType.HEAP_USE_AFTER_FREE, BugType.USE_AFTER_FREE) or "use-after-free" in text or "heap-use-after-free" in text:
        return CrashSeverity.HIGH, 8.5, "use-after-free"

    if bt_enum == BugType.DOUBLE_FREE or "double-free" in text:
        return CrashSeverity.HIGH, 8.0, "double-free"

    # 4. Out-of-bounds read & Uninitialized read & Integer overflow (Medium 4.0 - 6.9)
    if bt_enum == BugType.OUT_OF_BOUNDS_READ or "out-of-bounds-read" in text or "read of size" in text:
        return CrashSeverity.MEDIUM, 5.5, "out-of-bounds-read"

    if bt_enum == BugType.UNINITIALIZED_READ or "uninitialized" in text or "initialization-order-fiasco" in text:
        return CrashSeverity.MEDIUM, 5.0, "uninitialized-read"

    if bt_enum == BugType.INTEGER_OVERFLOW or "integer-overflow" in text:
        return CrashSeverity.MEDIUM, 4.5, "integer-overflow"

    if bt_enum == BugType.RACE_CONDITION or "race" in text:
        return CrashSeverity.MEDIUM, 4.5, "race-condition"

    # 5. Null pointer dereference on read & Division by zero & Logic abort (Low 1.0 - 3.9)
    if (
        bt_enum == BugType.NULL_POINTER_DEREF
        or "null-deref" in text
        or "null pointer" in text
        or "null-pointer" in text
        or (regs.get("pc") in ("0x0", "0x00000000", "0x0000000000000000") and "sigsegv" in text)
        or ("segv on unknown address 0x0" in text)
        or ("pc=0x0" in text)
    ):
        return CrashSeverity.LOW, 2.5, "null-deref-read"

    if bt_enum == BugType.DIVIDE_BY_ZERO or "divide-by-zero" in text or "sigfpe" in text or "divide by zero" in text:
        return CrashSeverity.LOW, 2.0, "divide-by-zero"

    if bt_enum == BugType.MEMORY_LEAK or "memory-leak" in text:
        return CrashSeverity.LOW, 1.5, "memory-leak"

    if "sigabrt" in text or "assertion failed" in text:
        return CrashSeverity.LOW, 1.5, "assertion-failure"

    if "sigsegv" in text:
        return CrashSeverity.MEDIUM, 5.0, "segmentation-fault"

    return CrashSeverity.UNKNOWN, 0.0, "unknown"


def _severity_from_bug_type(bug_type: BugType) -> str:
    """Map bug class to 4-tier coarse severity."""
    critical = {
        BugType.OUT_OF_BOUNDS_WRITE,
        BugType.HEAP_BUFFER_OVERFLOW,
        BugType.STACK_BUFFER_OVERFLOW,
        BugType.BUFFER_OVERFLOW,
    }
    high = {
        BugType.USE_AFTER_FREE,
        BugType.HEAP_USE_AFTER_FREE,
        BugType.DOUBLE_FREE,
    }
    medium = {
        BugType.OUT_OF_BOUNDS_READ,
        BugType.INTEGER_OVERFLOW,
        BugType.UNINITIALIZED_READ,
        BugType.RACE_CONDITION,
    }
    low = {
        BugType.NULL_POINTER_DEREF,
        BugType.DIVIDE_BY_ZERO,
        BugType.MEMORY_LEAK,
    }
    if bug_type in critical:
        return "critical"
    if bug_type in high:
        return "high"
    if bug_type in medium:
        return "medium"
    if bug_type in low:
        return "low"
    return "low"


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
        severity=fallback.severity,
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

    # Check for controlled IP first
    sev_level, _sev_score, prim = classify_crash_severity(
        bug_type=BugType.UNKNOWN,
        asan_output=report.asan_output,
        registers=report.registers,
        raw_text=report.raw_text,
        gdb_output=report.gdb_output,
    )
    if sev_level == CrashSeverity.CRITICAL and prim == "controlled-ip":
        return TriageResult(
            bug_type=BugType.OUT_OF_BOUNDS_WRITE,
            severity="critical",
            root_cause="Controlled instruction pointer / PC corruption detected",
            confidence=0.95,
            recommendations=["Check buffer bounds and return address integrity"],
        )

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
            "out-of-bounds-write": BugType.OUT_OF_BOUNDS_WRITE,
            "out-of-bounds-read": BugType.OUT_OF_BOUNDS_READ,
            "null-pointer-dereference": BugType.NULL_POINTER_DEREF,
        }
        bug_type = bug_map.get(asan_type, BugType.UNKNOWN)
        sev_level, _sev_score, _prim_desc = classify_crash_severity(
            bug_type=bug_type,
            asan_output=report.asan_output,
            registers=report.registers,
            raw_text=report.raw_text,
            gdb_output=report.gdb_output,
        )
        return TriageResult(
            bug_type=bug_type,
            severity=sev_level.value,
            root_cause=f"ASAN detected: {asan_match.group(1)}",
            confidence=0.85,
            recommendations=["Review ASAN report for exact allocation site"],
        )

    # Signal-based heuristics.
    if "sigsegv" in text or "segmentation fault" in text:
        # Distinguish null-deref vs general OOB by looking at PC or near-null address.
        if report.registers.get("pc", "") in ("0x0", "0x00000000", "0x0000000000000000") or "pc=0x0" in text or "0x00000000" in text or "0x0" in text:
            return TriageResult(
                bug_type=BugType.NULL_POINTER_DEREF,
                severity="low",
                root_cause="SIGSEGV at null PC — null pointer dereference on read",
                confidence=0.7,
                recommendations=["Audit pointer validation before dereference"],
            )
        return TriageResult(
            bug_type=BugType.OUT_OF_BOUNDS_WRITE,
            severity="critical" if "write" in text else "medium",
            root_cause="SIGSEGV during memory access — likely out-of-bounds",
            confidence=0.5,
            recommendations=["Check array bounds and pointer arithmetic"],
        )

    if "sigfpe" in text or "divide by zero" in text:
        return TriageResult(
            bug_type=BugType.DIVIDE_BY_ZERO,
            severity="low",
            root_cause="SIGFPE — division by zero",
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


__all__ = [
    "classify_crash_severity",
    "triage_batch",
    "triage_crash",
]
