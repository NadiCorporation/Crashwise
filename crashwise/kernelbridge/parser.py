# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Parser for kernel OOPS logs and syzkaller reproducers.

Extracts structured data from raw kernel panic text so the triage agent
can classify the bug without re-parsing free-form text every time.
"""

from __future__ import annotations

import re

from crashwise.core.logging import get_logger
from crashwise.kernelbridge.models import (
    KernelBugType,
    KernelCrash,
    OopsReport,
    StackFrame,
    SyscallSequence,
)

log = get_logger(__name__)

# ── Regex patterns ───────────────────────────────────────────────────────────
# Strip dmesg-style timestamps like "[   12.345678] " from line starts.
_TS_PREFIX_RE = re.compile(r"^\s*\[\s*\d+\.\d+\]\s+", re.M)

_OOPS_HEADER_RE = re.compile(r"Oops:\s+(\d+)\s+\[\#(\d+)\]\s+(\w+)")

# CR2 holds the faulting address on x86; on other arches look for "at addr"
_CR2_RE = re.compile(r"CR2:\s+(0x[0-9a-fA-F]+|[0-9a-fA-F]+)")
_FAULT_ADDR_RE = re.compile(
    r"(?:BUG:|Unable to handle|Oops).*?\bat\s+(0x[0-9a-fA-F]+|0000000000000000|<null>)",
    re.S,
)

# RIP line: "RIP: 0010: vfs_read+0x42/0x1a0" — we want the function, not 0010
_RIP_FUNC_RE = re.compile(r"RIP:\s+\S+:\s+(\S+)")

# Crashing instruction: the "Code:" block after RIP
_CODE_BLOCK_RE = re.compile(r"Code:\s+(.*?)(?:\n\s*RSP:|\n\s*[A-Z]{2,3}:|\n\n|$)", re.S)

# Registers: "RAX: 0000000000000000" — values may lack 0x prefix.
# We match globally so multiple registers on one line are captured.
_REGISTER_RE = re.compile(
    r"(?:^|\s)(R?[A-Z]{2,3}|r\d+|fp|sp|lr|pc|ip):\s+(0x[0-9a-fA-F]+|[0-9a-fA-F]+|\?+)",
    re.M,
)

# Stack trace inside Call Trace block
_CALL_TRACE_RE = re.compile(r"Call Trace:.*?(?:</TASK>|---\[ end trace \])", re.S)

# Individual frame inside Call Trace: "  ksys_read+0x5f/0xf0"
# Allows optional timestamp prefix and optional hex address.
_FRAME_RE = re.compile(
    r"^\s*(?:\[.*?\]\s+)?"  # optional timestamp prefix
    r"(?:\[?\s*(0x[0-9a-fA-F]+)\s*\]?\s+)?"  # optional hex addr
    r"([\w_\.]+)\s*"  # function name
    r"(?:\+\s*(0x[0-9a-fA-F]+)\s*/\s*(0x[0-9a-fA-F]+))?",  # optional +off/size
    re.M,
)

_TAINT_RE = re.compile(r"Tainted:\s+(\S+)")
_COMM_RE = re.compile(r"Comm:\s+(\S+)")
_PID_RE = re.compile(r"PID:\s+(\d+)", re.I)

# syzkaller reproducer patterns
_SYSCALL_LINE_RE = re.compile(r"^\s*(\w+)\((.*)\)\s*;?\s*$", re.M)
_C_PROG_RE = re.compile(r"void\s+main\s*\(\s*\)\s*\{([^}]+)\}", re.S)


def _strip_timestamps(text: str) -> str:
    """Remove dmesg-style ``[ 123.456789] `` prefixes so regexes work on clean lines."""
    return _TS_PREFIX_RE.sub("", text)


def parse_oops(raw: str) -> OopsReport:
    """Parse a raw kernel OOPS / panic log into an :class:`OopsReport`."""
    report = OopsReport(raw_text=raw)
    clean = _strip_timestamps(raw)

    # Faulting address: prefer CR2, fall back to "at addr" patterns
    cr2_m = _CR2_RE.search(clean)
    if cr2_m:
        report.faulting_address = cr2_m.group(1)
    else:
        fa_m = _FAULT_ADDR_RE.search(clean)
        if fa_m:
            report.faulting_address = fa_m.group(1)

    # Crashing instruction from the Code: block
    code_m = _CODE_BLOCK_RE.search(clean)
    if code_m:
        insn = code_m.group(1).strip().replace("\n", " ")
        # Strip RIP markers like "<48>" which indicate the faulting byte.
        insn = re.sub(r"<([0-9a-fA-F]+)>", r"\1", insn)
        report.crashing_instruction = insn[:200]

    # Registers
    for m in _REGISTER_RE.finditer(clean):
        report.register_state[m.group(1)] = m.group(2)

    # Stack trace: extract only the frames between Call Trace markers
    call_trace_m = _CALL_TRACE_RE.search(clean)
    trace_text = call_trace_m.group(0) if call_trace_m else clean
    report.stack_trace = _parse_stack_trace(trace_text)

    # Metadata
    taint_m = _TAINT_RE.search(clean)
    if taint_m:
        report.taint = taint_m.group(1)
    comm_m = _COMM_RE.search(clean)
    if comm_m:
        report.comm = comm_m.group(1)
    pid_m = _PID_RE.search(clean)
    if pid_m:
        report.pid = int(pid_m.group(1))

    # Heuristic bug classification
    report.bug_type = _classify_from_text(raw)

    log.info(
        "kernelbridge.parse_oops.complete",
        bug_type=report.bug_type.value,
        fault_addr=report.faulting_address,
        frames=len(report.stack_trace),
    )
    return report


def parse_syzkaller_repro(text: str) -> SyscallSequence:
    """Parse a syzkaller C reproducer or text reproducer."""
    seq = SyscallSequence()

    # Try C-style reproducer first: void main() { syscall(...); ... }
    c_match = _C_PROG_RE.search(text)
    if c_match:
        body = c_match.group(1)
        for m in _SYSCALL_LINE_RE.finditer(body):
            seq.syscalls.append(m.group(1))
            seq.args.append(_split_args(m.group(2)))
        return seq

    # Fallback: plain text reproducer (one syscall per line)
    for m in _SYSCALL_LINE_RE.finditer(text):
        seq.syscalls.append(m.group(1))
        seq.args.append(_split_args(m.group(2)))

    log.info(
        "kernelbridge.parse_syzkaller_repro.complete",
        syscalls=len(seq.syscalls),
    )
    return seq


def parse_kernel_crash(
    *,
    crash_id: str,
    oops_text: str,
    reproducer_text: str | None = None,
    kernel_version: str = "",
) -> KernelCrash:
    """High-level convenience: parse OOPS + optional reproducer into a :class:`KernelCrash`."""
    crash = KernelCrash(
        crash_id=crash_id,
        oops=parse_oops(oops_text),
        kernel_version=kernel_version,
    )
    if reproducer_text:
        crash.reproducer = parse_syzkaller_repro(reproducer_text)
    return crash


# ── Internals ────────────────────────────────────────────────────────────────
def _parse_stack_trace(raw: str) -> list[StackFrame]:
    """Extract kernel backtrace frames from an OOPS log."""
    frames: list[StackFrame] = []
    seen: set[str] = set()

    for m in _FRAME_RE.finditer(raw):
        func = m.group(2).strip() if m.group(2) else "??"
        if not func or func in ("<TASK>", "</TASK>", "---[", "end", "trace"):
            continue
        if func in seen:
            continue
        seen.add(func)
        frames.append(
            StackFrame(
                function=func,
                offset=m.group(3) or "",
            )
        )

    return frames


def _split_args(arg_str: str) -> list[str]:
    """Split a syscall argument string by commas, respecting nesting."""
    args: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in arg_str:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        args.append("".join(current).strip())
    return args


def _classify_from_text(raw: str) -> KernelBugType:
    """Heuristic bug classification from OOPS text."""
    text = raw.lower()

    if "null pointer dereference" in text:
        return KernelBugType.NULL_POINTER_DEREF
    if "use-after-free" in text or "slab-use-after-free" in text:
        return KernelBugType.USE_AFTER_FREE
    if "double-free" in text:
        return KernelBugType.DOUBLE_FREE
    if "stack-protector" in text or "stack smashing" in text:
        return KernelBugType.STACK_OVERFLOW
    if "buffer overflow" in text or "out-of-bounds" in text:
        return KernelBugType.BUFFER_OVERFLOW
    if "integer overflow" in text or "signedness" in text:
        return KernelBugType.INTEGER_OVERFLOW
    if "deadlock" in text or "lockdep" in text:
        return KernelBugType.DEADLOCK
    if "infoleak" in text or "uninit" in text:
        return KernelBugType.INFO_LEAK
    if "hung task" in text or "softlockup" in text or "rcu stall" in text:
        return KernelBugType.HANG
    if "kasan" in text and "race" in text:
        return KernelBugType.RACE_CONDITION
    if "kasan" in text and "use-after-free" not in text:
        # Generic KASAN hit without a more specific classification
        return KernelBugType.BUFFER_OVERFLOW
    # Null deref from CR2=0x0 without explicit "null pointer" text
    if "cr2: 0000000000000000" in text:
        return KernelBugType.NULL_POINTER_DEREF

    return KernelBugType.UNKNOWN


__all__ = ["parse_kernel_crash", "parse_oops", "parse_syzkaller_repro"]
