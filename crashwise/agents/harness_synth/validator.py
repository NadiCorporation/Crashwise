# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Harness Validator — semantic safety checks on LLM-generated C/C++ code.

Runs lightweight static analysis on evolved harness source BEFORE
compilation to catch:

1. **Dangerous syscalls** — fork, exec*, system, popen, kill, ptrace
2. **Resource exhaustion** — infinite loops, unbounded recursion
3. **Privilege escalation** — mmap+mprotect (shellcode), /proc writes
4. **Network access** — socket, connect, bind (should be impossible
   with --network none, but defense in depth)
5. **Code size** — reject unreasonably large generated harnesses

This is a defense-in-depth layer. Even if the LLM is tricked via prompt
injection, the harness cannot execute dangerous operations because:
- This validator blocks it before compilation
- The compiler allowlist blocks non-compiler invocation
- The Docker sandbox blocks it at runtime (no network, cap-drop ALL)

Autonomy guarantee: the validator NEVER blocks legitimate fuzzing harness
patterns (fuzz entry points, memory allocation, file I/O for corpus
reading). It only blocks operations that have no legitimate use in a
fuzzing harness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from crashwise.core.logging import get_logger

log = get_logger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────

# Maximum harness source size (bytes). LLM-generated harnesses should be
# compact; anything larger is suspicious or wasteful.
_MAX_HARNESS_SIZE_BYTES: int = 65_536  # 64 KB

# Maximum number of lines. Fuzzing harnesses are typically <200 lines.
_MAX_HARNESS_LINES: int = 2000


# ── Dangerous patterns ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class ValidationIssue:
    """A single validation finding."""

    severity: str  # "block" or "warn"
    category: str
    message: str
    line_number: int = 0
    matched_text: str = ""


@dataclass
class ValidationResult:
    """Aggregate result of harness validation."""

    passed: bool = True
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def blocking_issues(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "block"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "warn"]

    def summary(self) -> str:
        if self.passed:
            return f"Passed ({len(self.warnings)} warnings)"
        blocks = len(self.blocking_issues)
        return f"BLOCKED ({blocks} issue{'s' if blocks != 1 else ''}): {self.blocking_issues[0].message}"


# Functions that should NEVER appear in a fuzzing harness.
# These have no legitimate use case in a fuzz target.
_BLOCKED_FUNCTIONS: dict[str, str] = {
    "fork": "Process creation is prohibited in fuzzing harnesses",
    "vfork": "Process creation is prohibited in fuzzing harnesses",
    "execl": "Process execution is prohibited in fuzzing harnesses",
    "execlp": "Process execution is prohibited in fuzzing harnesses",
    "execle": "Process execution is prohibited in fuzzing harnesses",
    "execv": "Process execution is prohibited in fuzzing harnesses",
    "execvp": "Process execution is prohibited in fuzzing harnesses",
    "execvpe": "Process execution is prohibited in fuzzing harnesses",
    "execve": "Process execution is prohibited in fuzzing harnesses",
    "system": "Shell command execution is prohibited",
    "popen": "Shell command execution is prohibited",
    "pclose": "Shell command execution is prohibited (implies popen use)",
    "dlopen": "Dynamic library loading is prohibited in harnesses",
    "dlsym": "Dynamic symbol resolution is prohibited in harnesses",
    "ptrace": "Process tracing is prohibited in harnesses",
    "kill": "Signal sending is prohibited in harnesses",
    "raise": "Signal raising is prohibited in harnesses",
    "setuid": "Privilege manipulation is prohibited",
    "setgid": "Privilege manipulation is prohibited",
    "seteuid": "Privilege manipulation is prohibited",
    "setegid": "Privilege manipulation is prohibited",
    "chroot": "Filesystem escape attempt detected",
    "unshare": "Namespace manipulation is prohibited",
    "clone": "Process/thread creation via clone is prohibited",
}

# Network functions — should be impossible at runtime due to --network none,
# but block at source level for defense in depth.
_BLOCKED_NETWORK: dict[str, str] = {
    "socket": "Network operations are prohibited in fuzzing harnesses",
    "connect": "Network operations are prohibited in fuzzing harnesses",
    "bind": "Network operations are prohibited in fuzzing harnesses",
    "listen": "Network operations are prohibited in fuzzing harnesses",
    "accept": "Network operations are prohibited in fuzzing harnesses",
    "sendto": "Network operations are prohibited in fuzzing harnesses",
    "recvfrom": "Network operations are prohibited in fuzzing harnesses",
}

# Patterns that suggest shellcode construction or ROP gadget setup.
_SHELLCODE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"mprotect\s*\(.*PROT_EXEC", re.IGNORECASE),
        "mprotect with PROT_EXEC suggests shellcode injection",
    ),
    (
        re.compile(r"mmap\s*\([^)]*PROT_EXEC", re.IGNORECASE),
        "mmap with PROT_EXEC suggests executable memory allocation",
    ),
    (
        re.compile(r"/proc/self/mem", re.IGNORECASE),
        "Writing to /proc/self/mem is a code injection technique",
    ),
    (
        re.compile(r"/proc/self/maps", re.IGNORECASE),
        "Reading /proc/self/maps suggests memory layout reconnaissance",
    ),
    (
        re.compile(r"__asm__|asm\s*\(|asm\s+volatile", re.IGNORECASE),
        "Inline assembly is prohibited in fuzzing harnesses",
    ),
]

# Infinite loop patterns (heuristic — may have false positives, so these
# are warnings, not blocks).
_INFINITE_LOOP_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\bwhile\s*\(\s*1\s*\)\s*\{?\s*$"),
        "Potential infinite loop: while(1) without visible break",
    ),
    (
        re.compile(r"\bwhile\s*\(\s*true\s*\)\s*\{?\s*$", re.IGNORECASE),
        "Potential infinite loop: while(true) without visible break",
    ),
    (
        re.compile(r"\bfor\s*\(\s*;\s*;\s*\)\s*\{?\s*$"),
        "Potential infinite loop: for(;;) without visible break",
    ),
]

# File paths that should never appear in a harness (escape attempts).
_BLOCKED_PATHS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r'"/etc/(?:passwd|shadow|sudoers)"'),
        "Access to system authentication files is prohibited",
    ),
    (
        re.compile(r'"(?:\.\./){3,}'),
        "Deep path traversal suggests filesystem escape attempt",
    ),
    (
        re.compile(r'"/dev/(?:mem|kmem|port)"'),
        "Access to raw memory devices is prohibited",
    ),
]


# ── Public API ───────────────────────────────────────────────────────────────

def validate_harness(source_code: str) -> ValidationResult:
    """Run all safety checks on a harness source code string.

    Parameters
    ----------
    source_code:
        The C/C++ source code to validate.

    Returns
    -------
    ValidationResult with passed=True if safe to compile, or passed=False
    with blocking issues that explain why compilation was refused.
    """
    result = ValidationResult()

    # ── Size checks ──────────────────────────────────────────────────────
    if len(source_code) > _MAX_HARNESS_SIZE_BYTES:
        result.issues.append(ValidationIssue(
            severity="block",
            category="size",
            message=f"Harness source exceeds {_MAX_HARNESS_SIZE_BYTES} bytes "
                    f"({len(source_code)} bytes). LLM may have generated "
                    "excessive or repeated code.",
        ))
        result.passed = False
        return result

    lines = source_code.splitlines()
    if len(lines) > _MAX_HARNESS_LINES:
        result.issues.append(ValidationIssue(
            severity="block",
            category="size",
            message=f"Harness exceeds {_MAX_HARNESS_LINES} lines ({len(lines)} lines).",
        ))
        result.passed = False
        return result

    # ── Function call checks ─────────────────────────────────────────────
    # Strip single-line comments and string literals for more accurate matching.
    cleaned = _strip_comments_and_strings(source_code)

    for func_name, reason in _BLOCKED_FUNCTIONS.items():
        # Match function call pattern: word boundary + name + optional whitespace + (
        pattern = re.compile(rf"\b{re.escape(func_name)}\s*\(")
        for i, line in enumerate(cleaned.splitlines(), start=1):
            if pattern.search(line):
                result.issues.append(ValidationIssue(
                    severity="block",
                    category="dangerous_call",
                    message=reason,
                    line_number=i,
                    matched_text=func_name,
                ))
                result.passed = False

    for func_name, reason in _BLOCKED_NETWORK.items():
        pattern = re.compile(rf"\b{re.escape(func_name)}\s*\(")
        for i, line in enumerate(cleaned.splitlines(), start=1):
            if pattern.search(line):
                result.issues.append(ValidationIssue(
                    severity="block",
                    category="network",
                    message=reason,
                    line_number=i,
                    matched_text=func_name,
                ))
                result.passed = False

    # ── Shellcode / exploitation patterns ────────────────────────────────
    for pattern, reason in _SHELLCODE_PATTERNS:
        for i, line in enumerate(cleaned.splitlines(), start=1):
            if pattern.search(line):
                result.issues.append(ValidationIssue(
                    severity="block",
                    category="shellcode",
                    message=reason,
                    line_number=i,
                    matched_text=line.strip()[:80],
                ))
                result.passed = False

    # ── Blocked file paths ───────────────────────────────────────────────
    for pattern, reason in _BLOCKED_PATHS:
        for i, line in enumerate(source_code.splitlines(), start=1):
            if pattern.search(line):
                result.issues.append(ValidationIssue(
                    severity="block",
                    category="path_escape",
                    message=reason,
                    line_number=i,
                    matched_text=line.strip()[:80],
                ))
                result.passed = False

    # ── Infinite loop detection (warning only — fuzzer harnesses sometimes
    # use event loops that the fuzzer's timeout will catch) ────────────────
    for pattern, reason in _INFINITE_LOOP_PATTERNS:
        for i, line in enumerate(cleaned.splitlines(), start=1):
            if pattern.search(line):
                # Check if there's a break/return within the next 10 lines.
                block = "\n".join(cleaned.splitlines()[i:i+10])
                if "break" not in block and "return" not in block:
                    result.issues.append(ValidationIssue(
                        severity="warn",
                        category="infinite_loop",
                        message=reason,
                        line_number=i,
                        matched_text=line.strip()[:80],
                    ))

    # ── Verify harness has a fuzz entry point ────────────────────────────
    has_entry = (
        "LLVMFuzzerTestOneInput" in source_code
        or "AFL_FUZZ" in source_code
        or "main(" in source_code
    )
    if not has_entry:
        result.issues.append(ValidationIssue(
            severity="warn",
            category="missing_entry",
            message="No recognized fuzz entry point found "
                    "(LLVMFuzzerTestOneInput, main, AFL_FUZZ)",
        ))

    if result.passed:
        log.debug(
            "harness_validator.passed",
            lines=len(lines),
            warnings=len(result.warnings),
        )
    else:
        log.warning(
            "harness_validator.blocked",
            issues=len(result.blocking_issues),
            first_issue=result.blocking_issues[0].message if result.blocking_issues else "",
        )

    return result


# ── Helpers ──────────────────────────────────────────────────────────────────

def _strip_comments_and_strings(source: str) -> str:
    """Remove C/C++ comments and string literals for pattern matching.

    This prevents false positives from comments like:
        // Don't use system() here — use our safe wrapper instead
    or string literals like:
        const char *help = "Use fork() for parallel processing";
    """
    # Remove block comments /* ... */
    result = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    # Remove single-line comments // ...
    result = re.sub(r"//[^\n]*", " ", result)
    # Remove string literals (simple approach — doesn't handle escaped quotes
    # perfectly but good enough for security scanning)
    result = re.sub(r'"(?:[^"\\]|\\.)*"', '""', result)
    result = re.sub(r"'(?:[^'\\]|\\.)*'", "''", result)
    return result


__all__ = ["ValidationIssue", "ValidationResult", "validate_harness"]
