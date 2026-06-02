# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``triage_results`` activity — Phase 3 implementation.

Reads crash artefacts from the ``crashes_dir``, drives the triage agent
(LLM + heuristic fallback), deduplicates by normalised stack trace, and
emits a structured :class:`TriageOutput`.
"""

from __future__ import annotations

from pathlib import Path

from temporalio import activity

from crashwise.agents.triage.analyzer import triage_batch
from crashwise.agents.triage.models import CrashReport, StackFrame, TriageResult
from crashwise.core.logging import get_logger
from crashwise.core.models import (
    CrashSeverity,
    TriagedCrashRef,
    TriageInput,
    TriageOutput,
)

log = get_logger(__name__)


def _parse_gdb_backtrace(raw: str) -> list[StackFrame]:
    """Best-effort GDB backtrace parser.

    Handles the classic ``#0  func() at file:line`` format and the
    ``#0  0xaddr in func () from module`` format.
    """
    frames: list[StackFrame] = []
    # Pattern 1: #0  function(args) at file:line
    pat1 = __import__("re").compile(r"#\d+\s+(.+?)\s+at\s+([^:]+):(\d+)")
    # Pattern 2: #0  0xaddr in function () from module
    pat2 = __import__("re").compile(
        r"#\d+\s+(0x[0-9a-fA-F]+\s+)?in\s+(.+?)\s+\(\)\s+(from\s+(.+))?"
    )

    for line in raw.splitlines():
        line = line.strip()
        m1 = pat1.search(line)
        if m1:
            func = m1.group(1).strip()
            # Strip "0xaddr in " prefix if present.
            if " in " in func:
                func = func.split(" in ", 1)[1]
            frames.append(
                StackFrame(
                    function=func,
                    file=m1.group(2).strip(),
                    line=int(m1.group(3)),
                )
            )
            continue
        m2 = pat2.search(line)
        if m2:
            frames.append(
                StackFrame(
                    function=m2.group(2).strip() if m2.group(2) else "??",
                    module=m2.group(4).strip() if m2.group(4) else "",
                    offset=m2.group(1).strip() if m2.group(1) else "",
                )
            )
    return frames


def _harvest_reports(crashes_dir: Path, logs_path: Path | None = None) -> list[CrashReport]:
    """Walk ``crashes_dir`` and build :class:`CrashReport` objects.

    Also parses the fuzzer log (fuzz.log) for ASAN output, since AFL++
    writes raw crash inputs to crashes_dir (not ASAN logs). The actual
    ASAN report is in the fuzzer's stderr captured in fuzz.log.
    """
    reports: list[CrashReport] = []
    if not crashes_dir.exists():
        log.warning("triage_results.crashes_dir_missing", path=str(crashes_dir))
        return reports

    # Extract ASAN blocks from fuzz.log (fuzzer stderr).
    log_asan_blocks: list[str] = []
    if logs_path and logs_path.exists():
        try:
            log_text = logs_path.read_text(encoding="utf-8", errors="replace")
            # Simpler approach: find all ASAN blocks.
            idx = 0
            while True:
                start = log_text.find("ERROR: AddressSanitizer", idx)
                if start == -1:
                    break
                end = log_text.find("SUMMARY: AddressSanitizer", start)
                if end == -1:
                    end = min(start + 4096, len(log_text))
                else:
                    end = log_text.find("\n", end) + 1 or end + 50
                log_asan_blocks.append(log_text[start:end])
                idx = end
        except OSError:
            pass

    for entry in sorted(crashes_dir.iterdir()):
        if not entry.is_file():
            continue
        raw = entry.read_text(encoding="utf-8", errors="replace")

        # Heuristic: if the file itself looks like a GDB/ASAN log, parse it.
        gdb_frames: list[StackFrame] = []
        if "#0" in raw and ("in " in raw or "at " in raw):
            gdb_frames = _parse_gdb_backtrace(raw)

        # Extract ASAN block from the file itself (if it's a log, not binary).
        asan_block = ""
        if "ERROR: AddressSanitizer" in raw:
            start = raw.find("ERROR: AddressSanitizer")
            end = raw.find("SUMMARY: AddressSanitizer")
            if end == -1:
                end = len(raw)
            asan_block = raw[start:end]

        # If no ASAN in the crash file (it's a raw binary input from AFL++),
        # try to match it with an ASAN block from fuzz.log.
        if not asan_block and log_asan_blocks:
            # Use the next available ASAN block (order matches crash order).
            asan_block = log_asan_blocks.pop(0)
            gdb_frames = gdb_frames or _parse_gdb_backtrace(asan_block)

        reports.append(
            CrashReport(
                crash_id=entry.name,
                raw_text=raw if asan_block in raw else asan_block or raw,
                asan_output=asan_block,
                gdb_output=asan_block if gdb_frames else "",
                stack_frames=gdb_frames,
                crash_file=entry,
            )
        )
    return reports


@activity.defn(name="triage_results")
async def triage_results(payload: TriageInput) -> TriageOutput:
    """Classify each crash artefact and produce a rollup."""
    info = activity.info()
    log.info(
        "triage_results.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        crash_count=payload.crash_count,
        logs_path=str(payload.logs_path),
        crashes_dir=str(payload.crashes_dir),
    )

    reports = _harvest_reports(payload.crashes_dir, payload.logs_path)
    if not reports:
        # No crash files on disk — fall back to stub semantics.
        severity = _severity_from_count(payload.crash_count)
        return TriageOutput(
            severity=severity,
            summary=f"No crash artefacts found in {payload.crashes_dir}; {payload.crash_count} crash(es) reported by fuzzer.",
            triaged_crash_count=payload.crash_count,
            unique_crashes=[],
        )

    results = await triage_batch(reports)

    # Aggregate.
    distinct = sum(1 for r in results if r.duplicate_of is None)
    duplicates = len(results) - distinct
    severities = [r.severity for r in results]
    max_sev = max(severities, key=_severity_rank) if severities else "unknown"
    from crashwise.agents.triage.models import BugType

    bug_types = {r.bug_type.value for r in results if r.bug_type != BugType.UNKNOWN}

    summary_parts = [
        f"Triaged {len(results)} crash report(s): {distinct} distinct, {duplicates} duplicate(s).",
        f"Highest severity: {max_sev}.",
    ]
    if bug_types:
        summary_parts.append(f"Bug classes observed: {', '.join(sorted(bug_types))}.")
    for report, result in zip(reports, results, strict=True):
        if result.root_cause:
            summary_parts.append(
                f"  • {report.crash_id}: {result.bug_type.value} — {result.root_cause[:120]}"
            )

    # Build the workflow-visible per-crash references for every *unique*
    # crash. Phase 22 healing engine consumes these so the workflow can
    # invoke ``run_autonomous_repair_activity`` *before* persistence.
    unique_crashes = _build_unique_crash_refs(reports, results)

    output = TriageOutput(
        severity=CrashSeverity(max_sev)
        if max_sev in {s.value for s in CrashSeverity}
        else CrashSeverity.UNKNOWN,
        summary="\n".join(summary_parts),
        triaged_crash_count=distinct,
        unique_crashes=unique_crashes,
    )

    log.info(
        "triage_results.complete",
        workflow_id=info.workflow_id,
        distinct=distinct,
        duplicates=duplicates,
        max_severity=max_sev,
        defer_persistence=payload.defer_persistence,
    )

    # Persist crashes to DB when campaign_id is provided AND the workflow
    # has not asked us to defer (Phase 22: the workflow takes over so it
    # can interleave the per-crash autonomous repair step).
    if payload.campaign_id is not None and results and not payload.defer_persistence:
        await _persist_crashes(payload.campaign_id, reports, results)

    return output


async def _persist_crashes(
    campaign_id: str,
    reports: list[CrashReport],
    results: list[TriageResult],
) -> None:
    """Write triaged crashes to the DB, with Redis dedup cache."""
    from crashwise.core.database import Crash, get_session
    from crashwise.core.redis import incr_crash_counter, is_stack_hash_known

    try:
        async with get_session() as session:
            persisted = 0
            for report, result in zip(reports, results, strict=True):
                if result.duplicate_of is not None:
                    continue  # Skip duplicates.

                stack_hash = _compute_stack_hash(report)

                # Fast-path dedup via Redis.
                if await is_stack_hash_known(campaign_id, stack_hash):
                    log.debug(
                        "triage_results.redis_dedup",
                        campaign_id=campaign_id,
                        stack_hash=stack_hash,
                    )
                    continue

                crash = Crash(
                    # run_id is nullable for now — we link by campaign.
                    crash_type=result.bug_type.value,
                    severity=result.severity,
                    stack_trace="\n".join(str(f) for f in report.stack_frames),
                    stack_hash=stack_hash,
                    signal=report.signal or "",
                    logs_path=str(report.crash_file) if report.crash_file else "",
                )
                session.add(crash)
                persisted += 1

                # Operation Hydra Phase 5: Persist to web control plane.
                try:
                    from crashwise.web.hooks import persist_crash_to_web

                    await persist_crash_to_web(
                        campaign_id=campaign_id,
                        crash_type=result.bug_type.value,
                        crash_state=f"{report.crash_file}:{report.stack_frames[0] if report.stack_frames else 'unknown'}",
                        severity=result.severity,
                        sanitizer_log="\n".join(str(f) for f in report.stack_frames),
                        gdb_backtrace="",
                        reproducer_path=str(report.crash_file) if report.crash_file else "",
                    )
                except Exception:
                    pass  # Non-fatal — web DB may not be available.

            await session.commit()
            if persisted > 0:
                await incr_crash_counter(campaign_id, count=persisted)
            log.info(
                "triage_results.db_persisted",
                campaign_id=campaign_id,
                count=persisted,
            )
    except Exception:
        log.warning("triage_results.db_persist_failed", exc_info=True)


def _compute_stack_hash(report: CrashReport) -> str:
    """Deterministic 16-char SHA256 of the normalised stack frames.

    The same hash is emitted by ``_build_unique_crash_refs`` (workflow
    path) and the legacy ``_persist_crashes`` (in-activity path), so
    Redis dedup keys remain stable across both code paths.
    """
    if not report.stack_frames:
        return ""
    import hashlib

    stack_str = "|".join(f.function for f in report.stack_frames)
    return hashlib.sha256(stack_str.encode()).hexdigest()[:16]


def _build_unique_crash_refs(
    reports: list[CrashReport],
    results: list[TriageResult],
) -> list[TriagedCrashRef]:
    """Project unique reports/results into wire-friendly refs for the workflow.

    Duplicates (per ``TriageResult.duplicate_of``) are filtered out so
    the workflow's per-crash repair loop only spends LLM budget on
    net-new findings.
    """
    refs: list[TriagedCrashRef] = []
    for report, result in zip(reports, results, strict=True):
        if result.duplicate_of is not None:
            continue

        # Choose the richest available text blob as the asan_log payload
        # the repair agent will diagnose. Prefer ASAN, then GDB, then raw.
        log_blob = report.asan_output or report.gdb_output or report.raw_text

        # Clamp to the model's max_length so model_validate doesn't reject
        # genuinely-large fuzzer logs at the wire boundary. We keep the
        # tail (where the most recent crash context lives) when truncating.
        if len(log_blob) > 65_536:
            log_blob = log_blob[-65_536:]

        stack_trace = "\n".join(str(f) for f in report.stack_frames)
        if len(stack_trace) > 8_192:
            stack_trace = stack_trace[:8_192]

        refs.append(
            TriagedCrashRef(
                crash_id=report.crash_id,
                stack_hash=_compute_stack_hash(report),
                asan_log=log_blob,
                crash_file_path=str(report.crash_file) if report.crash_file else "",
                bug_type=result.bug_type.value,
                severity=CrashSeverity(result.severity)
                if result.severity in {s.value for s in CrashSeverity}
                else CrashSeverity.UNKNOWN,
                signal=str(report.signal or "")[:32],
                stack_trace=stack_trace,
                root_cause=result.root_cause[:4_096],
            )
        )
    return refs


def _severity_from_count(n: int) -> CrashSeverity:
    if n <= 0:
        return CrashSeverity.UNKNOWN
    if n == 1:
        return CrashSeverity.LOW
    if n <= 5:
        return CrashSeverity.MEDIUM
    if n <= 20:
        return CrashSeverity.HIGH
    return CrashSeverity.CRITICAL


def _severity_rank(sev: str) -> int:
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(sev, 0)


__all__ = ["triage_results"]
