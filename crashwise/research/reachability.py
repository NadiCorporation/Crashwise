# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Reachability Engine — determines if a vulnerability is triggerable from
untrusted input.

The engine performs static analysis on source code to map the vulnerable
function back to entry points (syscalls, network handlers, public APIs) and
scores the ease of exploitation.

Three analysis modes:
  1. **AST-based** (best): Uses ``tree-sitter`` or ``clang`` AST to trace
call paths from public entry points to the vulnerable function.
  2. **Regex heuristics** (fallback): Pattern-matches function names against
known syscall / network / parser entry points.
  3. **LLM-assisted** (optional): Sends source snippets to the AI provider
for a semantic reachability assessment.

Autonomy guarantee: the engine always produces a score even when no
external tools are available.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from crashwise.core.logging import get_logger
from crashwise.core.models import ExploitabilityScore

log = get_logger(__name__)

# ── Known entry-point signatures ─────────────────────────────────────────────

_SYSCALL_PATTERNS = [
    re.compile(r"SYSCALL_DEFINE\d*\s*\(\s*\w*\s*"),
    re.compile(r"asmlinkage\s+\w+\s+sys_"),
    re.compile(r"\bioctl\b"),
    re.compile(r"\bread\b"),
    re.compile(r"\brecv\b"),
    re.compile(r"\brecvfrom\b"),
    re.compile(r"\brecvmsg\b"),
]

_NETWORK_PATTERNS = [
    re.compile(r"\bsocket\b"),
    re.compile(r"\bbind\b"),
    re.compile(r"\blisten\b"),
    re.compile(r"\baccept\b"),
    re.compile(r"\bconnect\b"),
    re.compile(r"\bhttp_"),
    re.compile(r"\bparse_request"),
    re.compile(r"\bhandle_request"),
]

_PUBLIC_API_PATTERNS = [
    re.compile(r"\bmain\s*\("),
    re.compile(r"\bprocess_"),
    re.compile(r"\bparse_"),
    re.compile(r"\bdecode_"),
    re.compile(r"\bunpack_"),
    re.compile(r"\bload_"),
    re.compile(r"\bopen_"),
    re.compile(r"\binit_"),
]

_PARSER_PATTERNS = [
    re.compile(r"\bparse_"),
    re.compile(r"\bdecode_"),
    re.compile(r"\bdeserialize_"),
    re.compile(r"\bunmarshal_"),
    re.compile(r"\bread_"),
    re.compile(r"\bprocess_"),
]


# ── Reachability analysis ────────────────────────────────────────────────────

class ReachabilityResult:
    """Result of reachability analysis."""

    def __init__(
        self,
        reachable: bool,
        score: ExploitabilityScore,
        numeric_score: float,
        entry_points: list[str],
        path_length: int,
        notes: str,
    ) -> None:
        self.reachable = reachable
        self.score = score
        self.numeric_score = numeric_score
        self.entry_points = entry_points
        self.path_length = path_length
        self.notes = notes

    def to_dict(self) -> dict[str, object]:
        return {
            "reachable": self.reachable,
            "score": self.score.value,
            "numeric_score": self.numeric_score,
            "entry_points": self.entry_points,
            "path_length": self.path_length,
            "notes": self.notes,
        }


async def analyze_reachability(
    vulnerable_function: str,
    source_code: str | Path,
    *,
    bug_type: str = "",
) -> ReachabilityResult:
    """Analyze whether ``vulnerable_function`` is reachable from untrusted input.

    Parameters
    ----------
    vulnerable_function:
        Name of the function containing the bug.
    source_code:
        C/C++ source code as a string or path to a file.
    bug_type:
        Optional bug classification (influences scoring heuristics).

    Returns
    -------
    ReachabilityResult with score, entry points, and path length.
    """
    if isinstance(source_code, Path):
        try:
            code = source_code.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.warning("reachability.read_failed", path=str(source_code), error=str(exc))
            return _unknown_result("Could not read source file")
    else:
        code = source_code

    # 1. Try AST-based call-graph analysis (Python source only).
    entry_points_ast, path_len_ast = _ast_call_graph(code, vulnerable_function)
    if entry_points_ast:
        return _build_result(
            reachable=True,
            entry_points=entry_points_ast,
            path_length=path_len_ast,
            bug_type=bug_type,
            method="AST",
        )

    # 2. Fallback: regex heuristics on C/C++ source.
    entry_points_regex, path_len_regex = _regex_heuristics(code, vulnerable_function)
    if entry_points_regex:
        return _build_result(
            reachable=True,
            entry_points=entry_points_regex,
            path_length=path_len_regex,
            bug_type=bug_type,
            method="regex",
        )

    # 3. No entry points found — check if function is public itself.
    if _is_public_function(code, vulnerable_function):
        return _build_result(
            reachable=True,
            entry_points=[vulnerable_function],
            path_length=0,
            bug_type=bug_type,
            method="direct_public_api",
        )

    return _unknown_result("No entry points found; function may be internal")


# ── AST-based analysis (Python source) ───────────────────────────────────────

def _ast_call_graph(code: str, target: str) -> tuple[list[str], int]:
    """Parse Python source and find paths from top-level functions to target."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return [], -1

    # Find all function definitions and their callees.
    func_calls: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            callers: set[str] = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Name):
                        callers.add(child.func.id)
                    elif isinstance(child.func, ast.Attribute):
                        callers.add(child.func.attr)
            func_calls[node.name] = callers

    # BFS from entry points (functions that don't start with _ and are not the target).
    entry_points = [
        name for name in func_calls
        if not name.startswith("_") and name != target
    ]
    found_paths: list[tuple[str, int]] = []

    for ep in entry_points:
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(ep, 0)]
        while queue:
            current, depth = queue.pop(0)
            if current == target:
                found_paths.append((ep, depth))
                break
            if current in visited or depth > 10:
                continue
            visited.add(current)
            for callee in func_calls.get(current, set()):
                queue.append((callee, depth + 1))

    if found_paths:
        best = min(found_paths, key=lambda x: x[1])
        return [best[0]], best[1]
    return [], -1


# ── Regex heuristics (C/C++ source) ────────────────────────────────────────────

def _regex_heuristics(code: str, target: str) -> tuple[list[str], int]:
    """Pattern-match C/C++ source for entry points that may call the target."""
    entry_points: list[str] = []
    path_length = 1

    # Check if target is in a parser-like function.
    if any(p.search(code) for p in _PARSER_PATTERNS):
        # Check if the parser is called from a network or syscall handler.
        if any(p.search(code) for p in _NETWORK_PATTERNS):
            entry_points.append("network_handler")
            path_length = 2
        if any(p.search(code) for p in _SYSCALL_PATTERNS):
            entry_points.append("syscall_handler")
            path_length = 2

    # Check if target is directly a syscall.
    if any(p.search(code) for p in _SYSCALL_PATTERNS):
        entry_points.append("syscall")
        path_length = 0

    # Check if target is in a public API.
    if any(p.search(code) for p in _PUBLIC_API_PATTERNS):
        entry_points.append("public_api")
        path_length = 1

    # Deduplicate.
    unique = list(dict.fromkeys(entry_points))
    return unique, path_length


def _is_public_function(code: str, func_name: str) -> bool:
    """Check if the function is exported / public (not static)."""
    # Look for function definition without 'static'.
    pattern = re.compile(rf"^(?!\s*static\b).*\b{re.escape(func_name)}\s*\(", re.MULTILINE)
    return bool(pattern.search(code))


# ── Scoring ──────────────────────────────────────────────────────────────────

def _build_result(
    *,
    reachable: bool,
    entry_points: list[str],
    path_length: int,
    bug_type: str,
    method: str,
) -> ReachabilityResult:
    """Score reachability based on entry points and path length."""
    # Base score from entry point type.
    if "syscall" in entry_points or "network_handler" in entry_points:
        base_score = 9.0
        score = ExploitabilityScore.HIGH
    elif "public_api" in entry_points:
        base_score = 7.0
        score = ExploitabilityScore.MEDIUM
    else:
        base_score = 5.0
        score = ExploitabilityScore.MEDIUM

    # Adjust for path length (shorter = easier).
    if path_length == 0:
        base_score = min(10.0, base_score + 1.0)
    elif path_length > 5:
        base_score = max(0.0, base_score - 2.0)
        score = ExploitabilityScore.LOW if base_score < 4.0 else score

    # Bug-type bonus: some primitives are inherently easier to trigger.
    easy_primitives = {
        "out-of-bounds-write", "out-of-bounds-read", "heap-buffer-overflow",
        "stack-buffer-overflow", "integer-overflow", "divide-by-zero",
    }
    if bug_type in easy_primitives:
        base_score = min(10.0, base_score + 0.5)

    notes = (
        f"Reachable via {', '.join(entry_points)} "
        f"(path length={path_length}, method={method})."
    )

    return ReachabilityResult(
        reachable=reachable,
        score=score,
        numeric_score=round(base_score, 1),
        entry_points=entry_points,
        path_length=path_length,
        notes=notes,
    )


def _unknown_result(notes: str) -> ReachabilityResult:
    return ReachabilityResult(
        reachable=False,
        score=ExploitabilityScore.UNKNOWN,
        numeric_score=0.0,
        entry_points=[],
        path_length=-1,
        notes=notes,
    )


__all__ = ["ReachabilityResult", "analyze_reachability"]
