# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Coverage Analysis Agent — identifies blockers that prevent the fuzzer
from reaching new code paths.

The agent consumes coverage reports (lcov, ASAN coverage output, or simple
line-coverage data) and produces a ranked list of :class:`CoverageBlocker`
objects. Each blocker describes a specific condition (magic value check,
length validation, null pointer guard, etc.) that the fuzzer is failing
to satisfy.

Autonomy guarantee: the agent works with any coverage format that provides
line-level hit/miss data. When no coverage tool is available, it falls back
to static regex analysis of the source code.
"""

from __future__ import annotations

import re
from pathlib import Path

from crashwise.core.logging import get_logger
from crashwise.core.models import (
    BlockerType,
    CoverageAnalysis,
    CoverageBlocker,
)

log = get_logger(__name__)

# ── Blocker detection patterns ──────────────────────────────────────────────

_BLOCKER_PATTERNS: list[tuple[BlockerType, re.Pattern[str], str]] = [
    # Check memcmp/strcmp with literals FIRST (magic value), before generic format check.
    (
        BlockerType.MAGIC_VALUE,
        re.compile(
            r"(?:memcmp|strcmp|strncmp|strcasecmp)\s*\([^)]*?"
            r"(0x[0-9a-fA-F]+|\d+|'[^']+'|\"[^\"]+\")[^)]*\)",
            re.IGNORECASE,
        ),
        "Magic value in memcmp/strcmp",
    ),
    (
        BlockerType.MAGIC_VALUE,
        re.compile(
            r"if\s*\(\s*(\w+)\s*(?:==|!=)\s*(0x[0-9a-fA-F]+|\d+|'[^']+'|\"[^\"]+\")\s*\)",
            re.IGNORECASE,
        ),
        "Magic value comparison",
    ),
    (
        BlockerType.LENGTH_CHECK,
        re.compile(
            r"if\s*\(\s*(\w+)\s*(?:<|>|<=|>=)\s*(\d+|\w+)\s*\)",
            re.IGNORECASE,
        ),
        "Length or size comparison",
    ),
    (
        BlockerType.NULL_CHECK,
        re.compile(
            r"if\s*\(\s*(\w+)\s*(?:==|!=)\s*(?:NULL|nullptr|0)\s*\)",
            re.IGNORECASE,
        ),
        "Null pointer guard",
    ),
    (
        BlockerType.FORMAT_CHECK,
        re.compile(
            r"if\s*\(\s*(?:strncmp|memcmp|strcmp|strcasecmp)\s*\(",
            re.IGNORECASE,
        ),
        "String or format comparison",
    ),
    (
        BlockerType.CHECKSUM,
        re.compile(
            r"if\s*\(\s*(?:crc|checksum|hash|md5|sha)\w*\s*\(",
            re.IGNORECASE,
        ),
        "Checksum or hash validation",
    ),
    (
        BlockerType.STATE_MACHINE,
        re.compile(
            r"if\s*\(\s*state\s*(?:==|!=)\s*\w+\s*\)",
            re.IGNORECASE,
        ),
        "State machine transition check",
    ),
    (
        BlockerType.INITIALIZATION,
        re.compile(
            r"if\s*\(\s*!\s*(?:initialized|init|ready|setup)\s*\)",
            re.IGNORECASE,
        ),
        "Initialization guard",
    ),
]


# ── Public API ───────────────────────────────────────────────────────────────

async def analyze_coverage(
    source_path: Path,
    coverage_data: str = "",
    *,
    hit_lines: set[int] | None = None,
    missed_lines: set[int] | None = None,
) -> CoverageAnalysis:
    """Analyze coverage data and identify blockers.

    Parameters
    ----------
    source_path:
        Path to the source file being analyzed.
    coverage_data:
        Raw coverage report text (lcov, gcov, ASAN coverage, etc.).
    hit_lines:
        Optional set of line numbers that were executed.
    missed_lines:
        Optional set of line numbers that were NOT executed.

    Returns
    -------
    CoverageAnalysis with blockers, hit rate, and unreachable functions.
    """
    log.info(
        "coverage_analyzer.start",
        source_path=str(source_path),
        has_coverage_data=bool(coverage_data),
    )

    # 1. Parse coverage data if provided.
    if coverage_data.strip():
        hit, missed = _parse_coverage_text(coverage_data)
    elif hit_lines is not None and missed_lines is not None:
        hit, missed = hit_lines, missed_lines
    else:
        # Fallback: treat all lines as missed (worst case, but still useful).
        hit, missed = set(), set()

    # 2. Read source code.
    try:
        source_text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("coverage_analyzer.read_failed", path=str(source_path), error=str(exc))
        return CoverageAnalysis(notes=f"Could not read source: {exc}")

    lines = source_text.splitlines()
    total_lines = len(lines)
    hit_count = len(hit)
    missed_count = len(missed) if missed else total_lines - hit_count

    # 3. Identify blockers in missed regions.
    blockers: list[CoverageBlocker] = []
    for line_num in missed:
        if line_num < 1 or line_num > len(lines):
            continue
        line_text = lines[line_num - 1]
        blocker = _identify_blocker(line_num, line_text, source_text)
        if blocker:
            blockers.append(blocker)

    # 4. If no coverage data, do static analysis on all conditional lines.
    if not coverage_data.strip() and hit_lines is None:
        blockers = _static_blocker_analysis(source_text)

    # 5. Sort by confidence, then by distance from entry.
    blockers.sort(key=lambda b: (-b.confidence, b.distance_from_entry))

    # 6. Find unreachable functions.
    unreachable = _find_unreachable_functions(source_text, hit)

    hit_rate = hit_count / total_lines if total_lines > 0 else 0.0

    analysis = CoverageAnalysis(
        total_edges=total_lines,  # proxy: lines as edges
        edges_hit=hit_count,
        edges_missed=missed_count,
        hit_rate=round(hit_rate, 3),
        blockers=blockers[:20],  # cap at 20
        unreachable_functions=unreachable[:20],
        notes=f"Analyzed {total_lines} lines. Hit rate: {hit_rate:.1%}. "
              f"Found {len(blockers)} potential blockers. "
              f"{len(unreachable)} unreachable functions.",
    )

    log.info(
        "coverage_analyzer.complete",
        hit_rate=analysis.hit_rate,
        blockers=len(analysis.blockers),
        unreachable=len(analysis.unreachable_functions),
    )
    return analysis


# ── Coverage parsing ─────────────────────────────────────────────────────────

def _parse_coverage_text(text: str) -> tuple[set[int], set[int]]:
    """Best-effort parse of lcov/gcov/ASAN/AFL++/libFuzzer coverage text.

    Supports:
      • lcov: SF:<file>, DA:<line>,<hits>
      • gcov: <hits>:<line>:<text>
      • Simple: line numbers prefixed with + (hit) or - (missed)
      • AFL++ fuzzer_stats: edges_found / total_edges → synthetic hit/miss
      • AFL++ plot_data: CSV with edges_found column
      • AFL++ queue files: +cov markers indicate new coverage paths
      • libFuzzer: exec_count,cov_edges,cov_features CSV
    """
    hit: set[int] = set()
    missed: set[int] = set()

    # Check if this is AFL++ stats-based coverage data.
    if "# AFL++ fuzzer_stats coverage data" in text or "# AFL++ plot_data" in text:
        return _parse_afl_coverage_summary(text)

    # Check if this is libFuzzer coverage data.
    if "# libFuzzer coverage data" in text:
        return _parse_libfuzzer_coverage_summary(text)

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # lcov format: DA:line,hits
        if line.startswith("DA:"):
            parts = line[3:].split(",")
            if len(parts) == 2:
                try:
                    ln = int(parts[0])
                    hits = int(parts[1])
                    if hits > 0:
                        hit.add(ln)
                    else:
                        missed.add(ln)
                except ValueError:
                    pass
            continue

        # gcov format: hits:line:text
        if ":" in line and line[0].isdigit():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                try:
                    hits = int(parts[0].strip("-#"))
                    ln = int(parts[1])
                    if hits > 0:
                        hit.add(ln)
                    else:
                        missed.add(ln)
                except ValueError:
                    pass
            continue

        # Simple +/- format
        if line.startswith("+"):
            try:
                hit.add(int(line[1:]))
            except ValueError:
                pass
        elif line.startswith("-"):
            try:
                missed.add(int(line[1:]))
            except ValueError:
                pass

    return hit, missed


def _parse_afl_coverage_summary(text: str) -> tuple[set[int], set[int]]:
    """Parse AFL++ coverage summary generated by execute_fuzzing.

    AFL++ doesn't give us line-level coverage directly, but it tells us:
    - edges_found: how many unique edges the fuzzer has discovered
    - total_edges: total instrumented edges in the binary
    - Queue files with +cov: which corpus entries triggered new coverage

    We use this to create a synthetic hit/miss set that represents the
    proportion of code explored. The +cov queue entries are mapped to
    sequential "virtual line numbers" representing discovered paths.
    """
    hit: set[int] = set()
    missed: set[int] = set()

    edges_found = 0
    total_edges = 0

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            # Parse edges from comment metadata
            if "edges_found:" in line:
                try:
                    edges_found = int(line.split("edges_found:")[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            if "total_edges:" in line:
                try:
                    total_edges = int(line.split("total_edges:")[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            continue

        # Parse key: value format from fuzzer_stats section
        if ":" in line and not line.startswith("+"):
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip().split()[0] if val.strip() else ""
            try:
                num = int(float(val.rstrip("%").replace(",", "")))
            except ValueError:
                continue
            if key == "edges_found":
                edges_found = num
            elif key == "total_edges":
                total_edges = num

        # Parse +cov queue file entries as hit markers
        if line.startswith("+") and "+cov" in line:
            # Extract the id number from AFL queue filename
            # Format: +id:000042,time:12345,execs:67890,op:havoc,rep:4,+cov
            try:
                id_match = re.search(r"id:(\d+)", line)
                if id_match:
                    hit.add(int(id_match.group(1)))
            except (ValueError, AttributeError):
                pass

    # Generate synthetic coverage based on edges_found / total_edges ratio.
    if total_edges > 0 and edges_found > 0:
        # Mark edge indices as hit/missed.
        for i in range(1, edges_found + 1):
            hit.add(i)
        for i in range(edges_found + 1, total_edges + 1):
            missed.add(i)
    elif edges_found > 0:
        # No total_edges info — just mark what we found as hit.
        for i in range(1, edges_found + 1):
            hit.add(i)

    return hit, missed


def _parse_libfuzzer_coverage_summary(text: str) -> tuple[set[int], set[int]]:
    """Parse libFuzzer coverage summary generated by execute_fuzzing.

    libFuzzer reports coverage as (exec_count, cov_edges, cov_features).
    We use the final coverage count to create a synthetic hit set.
    """
    hit: set[int] = set()
    missed: set[int] = set()

    max_cov = 0
    max_ft = 0

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # CSV format: exec_count,cov_edges,cov_features
        parts = line.split(",")
        if len(parts) >= 3:
            try:
                cov = int(parts[1])
                ft = int(parts[2])
                max_cov = max(max_cov, cov)
                max_ft = max(max_ft, ft)
            except ValueError:
                pass

    # Generate synthetic line coverage from edge/feature counts.
    if max_cov > 0:
        for i in range(1, max_cov + 1):
            hit.add(i)
        # Estimate missed as ~30% beyond discovered (heuristic).
        estimated_total = int(max_cov * 1.3) if max_cov > 0 else 0
        for i in range(max_cov + 1, estimated_total + 1):
            missed.add(i)

    return hit, missed


# ── Blocker identification ───────────────────────────────────────────────────

def _identify_blocker(line_num: int, line_text: str, source_text: str) -> CoverageBlocker | None:
    """Analyze a single missed line and return a blocker if it matches patterns."""
    stripped = line_text.strip()
    if not stripped.startswith("if") and not stripped.startswith("switch"):
        return None

    for btype, pattern, description in _BLOCKER_PATTERNS:
        match = pattern.search(line_text)
        if match:
            expected = _extract_expected_value(line_text, btype)
            distance = _estimate_distance_from_entry(line_num, source_text)
            return CoverageBlocker(
                blocker_type=btype,
                line_number=line_num,
                function_name=_find_containing_function(line_num, source_text),
                condition_text=stripped,
                expected_value=expected,
                distance_from_entry=distance,
                confidence=_confidence_for_type(btype),
            )

    return None


def _extract_expected_value(line_text: str, btype: BlockerType) -> str:
    """Try to extract the literal value needed to pass the check."""
    if btype == BlockerType.MAGIC_VALUE:
        match = re.search(r"(?:==|!=)\s*(0x[0-9a-fA-F]+|\d+|'[^']+'|\"[^\"]+\")", line_text)
        if match:
            return match.group(1)
    if btype == BlockerType.LENGTH_CHECK:
        match = re.search(r"(?:<|>|<=|>=)\s*(\d+)", line_text)
        if match:
            return f">= {match.group(1)}"
    if btype == BlockerType.NULL_CHECK:
        return "non-null pointer"
    return ""


def _confidence_for_type(btype: BlockerType) -> float:
    """Heuristic confidence based on blocker type recognisability."""
    return {
        BlockerType.MAGIC_VALUE: 0.9,
        BlockerType.LENGTH_CHECK: 0.85,
        BlockerType.NULL_CHECK: 0.8,
        BlockerType.FORMAT_CHECK: 0.75,
        BlockerType.CHECKSUM: 0.7,
        BlockerType.STATE_MACHINE: 0.65,
        BlockerType.INITIALIZATION: 0.7,
        BlockerType.UNKNOWN: 0.3,
    }.get(btype, 0.5)


def _estimate_distance_from_entry(line_num: int, source_text: str) -> int:
    """Estimate distance from entry point by counting function boundaries."""
    lines = source_text.splitlines()
    distance = 0
    for i in range(min(line_num, len(lines))):
        if "{" in lines[i]:
            distance += 1
    return distance


def _find_containing_function(line_num: int, source_text: str) -> str:
    """Find the function name that contains ``line_num``."""
    lines = source_text.splitlines()
    func_name = "unknown"
    for i in range(min(line_num - 1, len(lines) - 1), -1, -1):
        match = re.match(r"^\s*(?:[\w\s\*]+\s+)?(\w+)\s*\(", lines[i])
        if match:
            candidate = match.group(1)
            if candidate not in {"if", "while", "for", "switch", "return", "sizeof"}:
                func_name = candidate
                break
    return func_name


# ── Static analysis fallback ─────────────────────────────────────────────────

def _static_blocker_analysis(source_text: str) -> list[CoverageBlocker]:
    """When no coverage data is available, analyze all conditional lines."""
    blockers: list[CoverageBlocker] = []
    lines = source_text.splitlines()
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("if") and not stripped.startswith("switch"):
            continue
        for btype, pattern, _ in _BLOCKER_PATTERNS:
            if pattern.search(line):
                expected = _extract_expected_value(line, btype)
                blockers.append(
                    CoverageBlocker(
                        blocker_type=btype,
                        line_number=i,
                        function_name=_find_containing_function(i, source_text),
                        condition_text=stripped,
                        expected_value=expected,
                        distance_from_entry=_estimate_distance_from_entry(i, source_text),
                        confidence=_confidence_for_type(btype) * 0.7,  # lower confidence without coverage
                    )
                )
                break
    return blockers


# ── Unreachable function detection ───────────────────────────────────────────

def _find_unreachable_functions(source_text: str, hit_lines: set[int]) -> list[str]:
    """Find functions whose bodies were never executed."""
    unreachable: list[str] = []
    func_pattern = re.compile(
        r"^\s*(?:[\w\s\*\&:<>,]+\s+)?(\w+)\s*\([^)]*\)\s*(?:\{|\n\{)",
        re.MULTILINE,
    )
    for match in func_pattern.finditer(source_text):
        name = match.group(1)
        if name in {"if", "while", "for", "switch", "return", "sizeof"}:
            continue
        # Check if any line in this function was hit.
        start_line = source_text[: match.start()].count("\n") + 1
        func_hit = False
        for ln in range(start_line, min(start_line + 200, len(source_text.splitlines()) + 1)):
            if ln in hit_lines:
                func_hit = True
                break
        if not func_hit:
            unreachable.append(name)
    return unreachable


__all__ = ["analyze_coverage"]
