# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Target Profiler Agent — static analysis pass that characterises a codebase
before fuzzing begins.

The profiler runs lightweight heuristics (``cloc``, regex, AST) to determine:

* **Domain** — image processing, network protocol, filesystem, etc.
* **Complexity** — cyclomatic complexity and call-graph depth.
* **Attack surface** — public entry points reachable from untrusted input.
* **Dangerous functions** — ``memcpy``, ``strcpy``, ``kmalloc``, etc.

The resulting :class:`TargetProfile` is consumed by the HarnessSynth agent
and the RootCauseAgent to tailor their prompts and by the execution layer
to select the right Docker image / compiler flags.

Autonomy guarantee: the profiler always returns a valid profile even when
no external tools are installed — it falls back to regex-only analysis.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path

from crashwise.core.logging import get_logger
from crashwise.core.models import (
    DangerousFunction,
    ProfileTargetInput,
    ProfileTargetOutput,
    TargetDomain,
    TargetProfile,
)

log = get_logger(__name__)

# ── Domain detection patterns ─────────────────────────────────────────────────

_DOMAIN_PATTERNS: dict[TargetDomain, list[re.Pattern[str]]] = {
    TargetDomain.IMAGE_PROCESSING: [
        re.compile(r"\b(?:png|jpg|jpeg|gif|bmp|tiff|webp|ppm|pgm|pbm)\b", re.I),
        re.compile(r"\b(?:pixel|rgb|rgba|palette|decode_image|encode_image)\b", re.I),
    ],
    TargetDomain.NETWORK_PROTOCOL: [
        re.compile(r"\b(?:tcp|udp|ip|icmp|http|tls|ssl|dns|packet|frame|socket)\b", re.I),
        re.compile(r"\b(?:parse_packet|handle_request|process_header|checksum)\b", re.I),
    ],
    TargetDomain.FILESYSTEM: [
        re.compile(r"\b(?:inode|dentry|vfs|mount|fs|ext4|xfs|btrfs|ntfs)\b", re.I),
        re.compile(r"\b(?:read_inode|write_inode|lookup|create|mkdir|rmdir)\b", re.I),
    ],
    TargetDomain.CRYPTOGRAPHY: [
        re.compile(r"\b(?:aes|rsa|sha|md5|hmac|cipher|encrypt|decrypt|key|nonce)\b", re.I),
        re.compile(r"\b(?:openssl|libcrypto|gcrypt|botan)\b", re.I),
    ],
    TargetDomain.COMPRESSION: [
        re.compile(r"\b(?:zlib|gzip|bz2|lzma|zstd| deflate|inflate|compress|decompress)\b", re.I),
    ],
    TargetDomain.PARSER: [
        re.compile(r"\b(?:json|xml|yaml|toml|csv|html|css|js|parse|token|lexer|grammar)\b", re.I),
    ],
    TargetDomain.DATABASE: [
        re.compile(r"\b(?:sql|query|table|index|transaction|journal|wal|btree|page)\b", re.I),
    ],
    TargetDomain.MULTIMEDIA: [
        re.compile(r"\b(?:audio|video|codec|ffmpeg|mp3|mp4|aac|h264|h265|av1|opus|vorbis)\b", re.I),
    ],
    TargetDomain.KERNEL: [
        re.compile(r"\b(?:syscall|ioctl|module|kernel|__user|copy_from_user|copy_to_user)\b", re.I),
    ],
}

# ── Dangerous function patterns ───────────────────────────────────────────────

_DANGEROUS_PATTERNS: dict[DangerousFunction, re.Pattern[str]] = {
    DangerousFunction.MEMCPY: re.compile(r"\bmemcpy\s*\("),
    DangerousFunction.STRCPY: re.compile(r"\bstrcpy\s*\("),
    DangerousFunction.STRCAT: re.compile(r"\bstrcat\s*\("),
    DangerousFunction.STRNCPY: re.compile(r"\bstrncpy\s*\("),
    DangerousFunction.MEMMOVE: re.compile(r"\bmemmove\s*\("),
    DangerousFunction.MEMSET: re.compile(r"\bmemset\s*\("),
    DangerousFunction.MALLOC: re.compile(r"\bmalloc\s*\("),
    DangerousFunction.REALLOC: re.compile(r"\brealloc\s*\("),
    DangerousFunction.FREE: re.compile(r"\bfree\s*\("),
    DangerousFunction.KMALLOC: re.compile(r"\bkmalloc\s*\("),
    DangerousFunction.VMALLOC: re.compile(r"\bvmalloc\s*\("),
    DangerousFunction.SPRINTF: re.compile(r"\bsprintf\s*\("),
    DangerousFunction.GETS: re.compile(r"\bgets\s*\("),
    DangerousFunction.READ: re.compile(r"\bread\s*\("),
    DangerousFunction.RECV: re.compile(r"\brecv\b"),
    DangerousFunction.COPY_FROM_USER: re.compile(r"\bcopy_from_user\s*\("),
    DangerousFunction.COPY_TO_USER: re.compile(r"\bcopy_to_user\s*\("),
}

# ── Public entry point patterns ─────────────────────────────────────────────

_PUBLIC_API_PATTERNS = [
    re.compile(r"^\s*(?:extern\s+)?(?:__attribute__\s*\(\(.*\)\)\s+)?[\w\s\*]+\b(main|init|open|read|write|ioctl|connect|accept|parse|decode|process|handle_request|handle_packet)\s*\("),
    re.compile(r"^\s*SYSCALL_DEFINE\d+\s*\("),
    re.compile(r"^\s*asmlinkage\s+"),
]


# ── Public API ─────────────────────────────────────────────────────────────

async def profile_target(payload: ProfileTargetInput) -> ProfileTargetOutput:
    """Analyse a target codebase and return a structured profile.

    Parameters
    ----------
    payload:
        ``workdir`` (cloned repo) and optional ``source_paths`` to restrict
        analysis.  ``max_files`` caps the scan for large repos.

    Returns
    -------
    ProfileTargetOutput with the populated :class:`TargetProfile`.
    """
    import time

    start = time.monotonic()
    workdir = payload.workdir

    if not workdir.exists():
        log.error("profiler.workdir_missing", path=str(workdir))
        return ProfileTargetOutput(
            profile=TargetProfile(notes="Workdir does not exist"),
            duration_seconds=0.0,
            files_scanned=0,
        )

    # 1. Gather source files.
    files = _collect_source_files(workdir, payload.source_paths, payload.max_files)
    log.info("profiler.files_collected", count=len(files), workdir=str(workdir))

    if not files:
        return ProfileTargetOutput(
            profile=TargetProfile(notes="No source files found"),
            duration_seconds=0.0,
            files_scanned=0,
        )

    # 2. Run cloc for LoC and language detection.
    loc_info = _run_cloc(workdir)

    # 3. Regex-based analysis across all source files.
    domain_votes: dict[TargetDomain, int] = dict.fromkeys(TargetDomain, 0)
    dangerous_found: set[DangerousFunction] = set()
    attack_surface: set[str] = set()
    total_complexity = 0
    max_depth = 0
    has_custom_allocator = False
    has_syscall = False
    has_network = False

    for src_file in files:
        try:
            text = src_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Domain voting.
        for domain, patterns in _DOMAIN_PATTERNS.items():
            for pat in patterns:
                if pat.search(text):
                    domain_votes[domain] += 1

        # Dangerous functions.
        for danger, pat in _DANGEROUS_PATTERNS.items():
            if pat.search(text):
                dangerous_found.add(danger)

        # Attack surface (public entry points).
        for match in _FUNC_DEF_RE.finditer(text):
            name = match.group("name")
            if _is_public_entry_point(name, text):
                attack_surface.add(name)

        # Complexity (branching heuristic).
        total_complexity += _estimate_complexity(text)

        # Depth (naïve call-chain depth).
        max_depth = max(max_depth, _estimate_call_depth(text))

        # Custom allocator / syscall / network detection.
        if re.search(r"\b(?:my_alloc|custom_malloc|pool_alloc|arena_alloc)\b", text):
            has_custom_allocator = True
        if re.search(r"\b(?:SYSCALL_DEFINE|ioctl|copy_from_user|copy_to_user)\b", text):
            has_syscall = True
        if re.search(r"\b(?:socket|bind|listen|accept|recv|send|parse_packet|handle_request)\b", text):
            has_network = True

    # 4. Determine dominant domain.
    best_domain = max(domain_votes, key=lambda k: domain_votes[k])
    if domain_votes[best_domain] == 0:
        best_domain = TargetDomain.GENERAL

    # 5. Compute complexity score (0–10).
    avg_complexity = total_complexity / len(files) if files else 0
    complexity_score = min(10.0, avg_complexity / 10.0)

    # 6. Determine recommended sanitizers & strategy.
    sanitizers, strategy = _recommend_config(
        best_domain,
        list(dangerous_found),
        has_custom_allocator,
        has_syscall,
    )

    profile = TargetProfile(
        domain=best_domain,
        complexity_score=round(complexity_score, 1),
        call_graph_depth=max_depth,
        attack_surface=sorted(attack_surface)[:50],  # cap at 50
        dangerous_functions=sorted(dangerous_found),
        language=loc_info.get("language", "c"),
        lines_of_code=loc_info.get("loc", 0),
        file_count=len(files),
        has_custom_allocator=has_custom_allocator,
        has_syscall_handlers=has_syscall,
        has_network_parsers=has_network,
        recommended_sanitizers=sanitizers,
        recommended_strategy=strategy,
        notes=f"Scanned {len(files)} files. Dominant domain: {best_domain.value}. "
              f"Found {len(dangerous_found)} dangerous functions. "
              f"Attack surface: {len(attack_surface)} public entry points.",
    )

    duration = time.monotonic() - start
    log.info(
        "profiler.complete",
        domain=profile.domain.value,
        complexity=profile.complexity_score,
        files=len(files),
        duration_seconds=round(duration, 2),
    )

    return ProfileTargetOutput(
        profile=profile,
        duration_seconds=round(duration, 2),
        files_scanned=len(files),
    )


# ── File collection ────────────────────────────────────────────────────────────

_SOURCE_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".rs", ".go"}


def _collect_source_files(
    workdir: Path,
    explicit_paths: Iterable[Path],
    max_files: int,
) -> list[Path]:
    """Gather up to ``max_files`` source files from ``workdir``."""
    if explicit_paths:
        files = [p for p in explicit_paths if p.suffix.lower() in _SOURCE_EXTENSIONS]
    else:
        files = [
            p
            for p in workdir.rglob("*")
            if p.is_file()
            and p.suffix.lower() in _SOURCE_EXTENSIONS
            and "/test" not in str(p)
            and "/tests" not in str(p)
            and "/examples" not in str(p)
        ]
    return files[:max_files]


# ── cloc wrapper ─────────────────────────────────────────────────────────────

def _run_cloc(workdir: Path) -> dict[str, object]:
    """Run ``cloc`` and return {language, loc, files}. Falls back to manual count."""
    if not shutil.which("cloc"):
        log.debug("profiler.cloc_not_found", fallback="manual")
        return _manual_loc_count(workdir)

    try:
        proc = subprocess.run(
            ["cloc", "--json", str(workdir)],
            capture_output=True,
            text=True,
            timeout=30.0,
        )
        if proc.returncode != 0:
            return _manual_loc_count(workdir)

        import json

        data: dict[str, object] = json.loads(proc.stdout)
        # cloc JSON has a "header" and "SUM" key; languages are the rest.
        total_loc = 0
        total_files = 0
        dominant_lang = "c"
        max_loc = 0
        for key, val in data.items():
            if key in ("header", "SUM"):
                continue
            if isinstance(val, dict):
                loc = int(val.get("code", 0))
                total_loc += loc
                total_files += int(val.get("nFiles", 0))
                if loc > max_loc:
                    max_loc = loc
                    dominant_lang = key.lower()
        return {"language": dominant_lang, "loc": total_loc, "files": total_files}
    except Exception:
        return _manual_loc_count(workdir)


def _manual_loc_count(workdir: Path) -> dict[str, object]:
    """Fallback: count non-comment, non-blank lines in source files."""
    total_loc = 0
    lang_votes: dict[str, int] = {"c": 0, "cpp": 0, "rust": 0, "go": 0}
    for p in workdir.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in _SOURCE_EXTENSIONS:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("//")]
        total_loc += len(lines)
        ext = p.suffix.lower()
        if ext in {".c", ".h"}:
            lang_votes["c"] += len(lines)
        elif ext in {".cpp", ".cc", ".cxx", ".hpp"}:
            lang_votes["cpp"] += len(lines)
        elif ext == ".rs":
            lang_votes["rust"] += len(lines)
        elif ext == ".go":
            lang_votes["go"] += len(lines)
    dominant = max(lang_votes, key=lambda k: lang_votes[k])
    return {"language": dominant, "loc": total_loc, "files": 0}


# ── Complexity & depth heuristics ──────────────────────────────────────────

_BRANCH_KEYWORDS = ("if", "for", "while", "switch", "case", "?:", "&&", "||", "catch")


def _estimate_complexity(text: str) -> int:
    """Naïve cyclomatic-complexity proxy: count branching keywords."""
    count = 0
    for kw in _BRANCH_KEYWORDS:
        count += text.count(kw)
    return count


def _estimate_call_depth(text: str) -> int:
    """Estimate max call depth by looking for nested function calls."""
    max_depth = 0
    current_depth = 0
    for ch in text:
        if ch == "(":
            current_depth += 1
            max_depth = max(max_depth, current_depth)
        elif ch == ")":
            current_depth = max(0, current_depth - 1)
    return max_depth


# ── Entry point detection ────────────────────────────────────────────────────

_FUNC_DEF_RE = re.compile(
    r"""
    ^
    (?!\s*(?:if|for|while|switch|return|else|using|typedef|struct|class)\b)
    (?P<ret>[A-Za-z_][\w\s\*\&:<>,]*?)
    \s+
    (?P<name>[A-Za-z_]\w*)
    \s*
    \((?P<args>[^)]*)\)
    \s*
    (?:\{|\n\{)
    """,
    re.VERBOSE | re.MULTILINE,
)


def _is_public_entry_point(name: str, text: str) -> bool:
    """Check if ``name`` looks like a public API entry point."""
    lname = name.lower()
    # Known public prefixes.
    public_prefixes = (
        "main", "parse", "decode", "process", "handle_", "read_", "write_",
        "open_", "init_", "connect", "accept", "recv", "send", "ioctl",
        "syscall", "sys_",
    )
    if any(lname.startswith(p) for p in public_prefixes):
        return True
    # Check if function is NOT static.
    static_pattern = re.compile(rf"^\s*static\b.*\b{re.escape(name)}\s*\(", re.MULTILINE)
    return not static_pattern.search(text)


# ── Strategy recommendation ─────────────────────────────────────────────────

def _recommend_config(
    domain: TargetDomain,
    dangerous: list[DangerousFunction],
    has_custom_allocator: bool,
    has_syscall: bool,
) -> tuple[str, str]:
    """Return (sanitizers, strategy) based on profile."""
    base = ["address", "undefined"]

    if has_custom_allocator:
        base.append("pointer-compare")
        base.append("pointer-subtract")

    if domain == TargetDomain.KERNEL or has_syscall:
        base = ["address", "undefined", "bounds", "alignment"]
        return ",".join(base), "kernel"

    if domain == TargetDomain.NETWORK_PROTOCOL:
        base.append("cfi")
        return ",".join(base), "network"

    if domain in (TargetDomain.IMAGE_PROCESSING, TargetDomain.PARSER, TargetDomain.COMPRESSION):
        return ",".join(base), "aggressive"

    if len(dangerous) >= 5:
        return ",".join(base), "aggressive"

    return ",".join(base), "standard"


__all__ = ["profile_target"]
