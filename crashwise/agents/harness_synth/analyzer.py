# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Static analysis pass — find fuzzable entry points in C/C++ source.

This is intentionally a regex-based heuristic, not a full compiler front-end.
The goal is to produce a *prioritised* list of candidates that the LLM can
then turn into a libFuzzer harness. Picking the right entry point is far
more important than parsing the language perfectly.

Heuristics (descending priority):

1. Functions whose first arg is ``const? uint8_t* / const? unsigned char*``
   followed by a ``size_t`` / ``int`` length argument — drop-in libFuzzer
   shape, score 1.0.
2. Functions whose first arg is ``const? char*`` (NUL-terminated parsers) —
   score 0.7.
3. Functions taking a single buffer-like pointer (``void*`` etc.) plus an
   integer length — score 0.5.
4. Anything else with ``parse``, ``decode``, ``read``, ``deserialize`` in
   its name — score 0.3.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from crashwise.agents.harness_synth.state import EntryPoint
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# Match a C/C++ function definition opener at start-of-line:
#   <return_type>  <name>  ( <args> )
# We capture name + args and then the line number is the byte offset → line.
_FUNC_DEF_RE = re.compile(
    r"""
    ^                                       # start of line
    (?!\s*(?:if|for|while|switch|return|else|using|typedef|struct|class)\b)
    (?P<ret>[A-Za-z_][\w\s\*\&:<>,]*?)      # return type (greedy, multiline-safe)
    \s+
    (?P<name>[A-Za-z_]\w*)                  # function name
    \s*
    \((?P<args>[^)]*)\)                     # arg list (no nested parens)
    \s*
    (?:\{|\n\{)                             # opening brace (same or next line)
    """,
    re.VERBOSE | re.MULTILINE,
)

_BUFFER_HINTS = ("parse", "decode", "read", "deserialize", "process", "consume", "load")

_C_KEYWORDS_RETURN = {
    "void",
    "int",
    "char",
    "long",
    "short",
    "unsigned",
    "signed",
    "size_t",
    "ssize_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "bool",
    "float",
    "double",
    "static",
    "inline",
    "extern",
    "const",
    "auto",
}


def detect_language(path: Path) -> str:
    """Return ``"c"`` or ``"cpp"`` based on the file extension."""
    return "c" if path.suffix.lower() in {".c", ".h"} else "cpp"


def find_entry_points(source_code: str, *, max_results: int = 10) -> list[EntryPoint]:
    """Return entry-point candidates ordered by descending heuristic score."""
    candidates: list[EntryPoint] = []

    for match in _FUNC_DEF_RE.finditer(source_code):
        ret = match.group("ret").strip()
        name = match.group("name")
        args_raw = match.group("args").strip()

        # Skip obvious noise: macro continuations, control-flow tokens that
        # snuck through, trivial `main` redefinitions in test files.
        if not _looks_like_function(ret, name):
            continue

        line = source_code.count("\n", 0, match.start()) + 1
        signature = _normalise_signature(ret, name, args_raw)
        score, takes_buffer = _score(name, args_raw)

        if score == 0.0:
            continue

        candidates.append(
            EntryPoint(
                name=name,
                signature=signature,
                line=line,
                takes_buffer=takes_buffer,
                score=score,
            )
        )

    # Stable sort: highest score first, then earliest declaration.
    candidates.sort(key=lambda ep: (-ep.score, ep.line))
    deduped = _dedupe(candidates)
    log.info(
        "harness_synth.analyzer.found",
        candidates=len(candidates),
        deduped=len(deduped),
    )
    return deduped[:max_results]


# ── Internals ────────────────────────────────────────────────────────────────
def _looks_like_function(ret: str, name: str) -> bool:
    if name in {"if", "while", "for", "switch", "return", "sizeof"}:
        return False
    parts = ret.split()
    if not parts:
        return False
    head = parts[0]
    # Accept known C/C++ type keywords, uppercase typedefs ("MyType"),
    # or any return type containing a pointer/reference (typedef'd C structs).
    is_known_keyword = head in _C_KEYWORDS_RETURN
    is_typedef_like = head[:1].isupper() and head.isidentifier()
    has_pointer = "*" in ret or "&" in ret
    return is_known_keyword or is_typedef_like or has_pointer


def _normalise_signature(ret: str, name: str, args: str) -> str:
    flat = " ".join(ret.split())
    args_flat = ", ".join(a.strip() for a in args.split(",")) if args else ""
    return f"{flat} {name}({args_flat})"


def _split_args(args_raw: str) -> list[str]:
    return [a.strip() for a in args_raw.split(",") if a.strip()]


def _score(name: str, args_raw: str) -> tuple[float, bool]:
    """Return (score, takes_buffer)."""
    args = _split_args(args_raw)
    if not args:
        return (0.0, False)

    first = args[0]
    second = args[1] if len(args) > 1 else ""

    # 1) (const? uint8_t* / unsigned char*, size_t) — perfect libFuzzer shape.
    if _is_byte_buffer(first) and _is_integer_size(second):
        return (1.0, True)

    # 2) Single (const) char* parser
    if _is_c_string(first) and len(args) == 1:
        return (0.7, True)
    if _is_c_string(first) and _is_integer_size(second):
        return (0.85, True)

    # 3) (void*, size_t)
    if _is_void_ptr(first) and _is_integer_size(second):
        return (0.5, True)

    # 4) Name-based hints, lower confidence.
    lname = name.lower()
    if any(h in lname for h in _BUFFER_HINTS):
        return (0.3, False)

    return (0.0, False)


_BYTE_BUFFER_RE = re.compile(r"^(?:const\s+)?(?:unsigned\s+char|uint8_t|u8)\s*\*\s*\w*$")
_C_STRING_RE = re.compile(r"^(?:const\s+)?char\s*\*\s*\w*$")
_VOID_PTR_RE = re.compile(r"^(?:const\s+)?void\s*\*\s*\w*$")
_INT_SIZE_RE = re.compile(
    r"^(?:const\s+)?(?:size_t|ssize_t|unsigned\s+(?:int|long)|int|long|"
    r"u?int(?:8|16|32|64)_t)\s*\w*$"
)


def _is_byte_buffer(arg: str) -> bool:
    return bool(_BYTE_BUFFER_RE.match(arg.strip()))


def _is_c_string(arg: str) -> bool:
    return bool(_C_STRING_RE.match(arg.strip()))


def _is_void_ptr(arg: str) -> bool:
    return bool(_VOID_PTR_RE.match(arg.strip()))


def _is_integer_size(arg: str) -> bool:
    return bool(_INT_SIZE_RE.match(arg.strip()))


def _dedupe(eps: Iterable[EntryPoint]) -> list[EntryPoint]:
    seen: set[str] = set()
    out: list[EntryPoint] = []
    for ep in eps:
        if ep.name in seen:
            continue
        seen.add(ep.name)
        out.append(ep)
    return out


__all__ = ["detect_language", "find_entry_points"]
