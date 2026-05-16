# SPDX-License-Identifier: MIT
"""Static type extraction from C/C++ headers.

Operation Hydra Phase 3: The Navigator Hand.
Extracts struct/typedef definitions so the LLM knows exact field layouts
when generating harnesses for APIs that use custom types.
"""
from __future__ import annotations

import re
from pathlib import Path

from crashwise.core.logging import get_logger

log = get_logger(__name__)

# Matches: struct name {, typedef struct {, typedef struct name {
_STRUCT_RE = re.compile(
    r"(?:typedef\s+)?struct\s+(?P<name>\w+)?\s*\{",
    re.MULTILINE,
)

# Matches: typedef <type> <name>;
_TYPEDEF_RE = re.compile(
    r"^\s*typedef\s+(.+?)\s+(\w+)\s*;",
    re.MULTILINE,
)


def extract_type_definition(workdir: Path, type_name: str) -> str | None:
    """Find and return the full definition of a type from project headers.

    Searches .h files for struct definitions and typedefs matching type_name.
    Returns the complete definition string, or None if not found.
    """
    # Search in header directories.
    header_dirs = [workdir]
    for subdir in ("include", "src", "lib"):
        candidate = workdir / subdir
        if candidate.is_dir():
            header_dirs.append(candidate)

    for d in header_dirs:
        for h in d.rglob("*.h"):
            if any(skip in str(h) for skip in (".git", "test")):
                continue
            try:
                content = h.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # Check for typedef (simple alias).
            for m in _TYPEDEF_RE.finditer(content):
                if m.group(2) == type_name:
                    return m.group(0).strip()

            # Check for struct definition.
            result = _extract_struct(content, type_name)
            if result:
                return result

    return None


def extract_types_for_signature(workdir: Path, signature: str) -> str:
    """Extract all custom type definitions referenced in a function signature.

    Parses the signature for non-primitive type names and looks them up.
    Returns a concatenated string of all found definitions.
    """
    # Primitive types that don't need extraction.
    primitives = {
        "void", "int", "char", "short", "long", "float", "double",
        "unsigned", "signed", "const", "size_t", "ssize_t", "bool",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "int8_t", "int16_t", "int32_t", "int64_t",
    }

    # Extract potential type names from signature.
    # Remove pointer/reference markers and split on delimiters.
    cleaned = re.sub(r"[*&\[\]()]", " ", signature)
    tokens = re.findall(r"\b([A-Za-z_]\w*)\b", cleaned)

    types_found: list[str] = []
    seen: set[str] = set()

    for token in tokens:
        if token in primitives or token in seen:
            continue
        if token[0].islower() and len(token) < 4:
            continue  # Skip short lowercase (likely param names)
        seen.add(token)
        defn = extract_type_definition(workdir, token)
        if defn:
            types_found.append(defn)

    if types_found:
        log.info("type_extractor.found", count=len(types_found))

    return "\n\n".join(types_found)


def _extract_struct(content: str, name: str) -> str | None:
    """Extract a struct definition by name, handling nested braces."""
    # Pattern: struct <name> { ... } or typedef struct ... } <name>;
    patterns = [
        rf"((?:typedef\s+)?struct\s+{re.escape(name)}\s*\{{)",
        rf"(typedef\s+struct\s*\{{[^}}]*\}}\s*{re.escape(name)}\s*;)",
    ]

    # Try the typedef struct ... } name; pattern first (single regex).
    typedef_pattern = rf"typedef\s+struct\s*\w*\s*\{{[^}}]*\}}\s*{re.escape(name)}\s*;"
    m = re.search(typedef_pattern, content, re.DOTALL)
    if m:
        return m.group(0).strip()

    # Try struct name { ... } with brace matching.
    pattern = rf"(?:typedef\s+)?struct\s+{re.escape(name)}\s*\{{"
    m = re.search(pattern, content)
    if not m:
        return None

    # Find matching closing brace.
    start = m.start()
    brace_start = content.index("{", m.start())
    depth = 0
    i = brace_start
    while i < len(content):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                # Include up to the semicolon.
                end = content.find(";", i)
                if end == -1:
                    end = i + 1
                else:
                    end += 1
                return content[start:end].strip()
        i += 1

    return None


__all__ = ["extract_type_definition", "extract_types_for_signature"]
