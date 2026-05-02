# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Tests for the KernelBridge parser and models."""

from __future__ import annotations

from crashwise.kernelbridge.models import KernelBugType, KernelCrash, OopsReport, StackFrame
from crashwise.kernelbridge.parser import (
    _classify_from_text,
    _split_args,
    parse_kernel_crash,
    parse_oops,
    parse_syzkaller_repro,
)

# ── Mock kernel crash log ────────────────────────────────────────────────────
_MOCK_OOPS = """\
[   12.345678] Oops: 0000 [#1] SMP
[   12.345679] CPU: 0 PID: 1234 Comm: syz-executor Tainted: G        W         5.15.0 #1
[   12.345680] RIP: 0010: vfs_read+0x42/0x1a0
[   12.345681] Code: 48 89 45 d8 48 8b 45 d8 48 89 45 d0 48 8b 45 d0 <48> 8b 00 48 89 45 c8
[   12.345682] RSP: 0018:ffff888006e43e58  EFLAGS: 00010246
[   12.345683] RAX: 0000000000000000 RBX: ffff888006e43e80 RCX: 0000000000000000
[   12.345684] RDX: 0000000000000001 RSI: ffff888006e43e80 RDI: 0000000000000000
[   12.345685] RBP: ffff888006e43e80 R08: 0000000000000000 R09: 0000000000000000
[   12.345686] CR2: 0000000000000000
[   12.345687] Call Trace:
[   12.345688]  <TASK>
[   12.345689]  ksys_read+0x5f/0xf0
[   12.345690]  do_syscall_64+0x3b/0x90
[   12.345691]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[   12.345692]  </TASK>
[   12.345693] Modules linked in: btrfs
[   12.345694] ---[ end trace 0000000000000000 ]---
"""

_MOCK_SYZ_REPRO = """\
void main() {
    open("/dev/btrfs-control", 0);
    ioctl(3, 0x50009418, 0);
    mmap(0, 0x1000, 3, 0x22, -1, 0);
}
"""

_MOCK_UAF_OOPS = """\
[   45.123456] ==================================================================
[   45.123457] BUG: KASAN: use-after-free in btrfs_inode+0x123/0x456
[   45.123458] Read of size 8 at addr ffff88800a1b2c30 by task syz-executor/5678
[   45.123459] CPU: 1 PID: 5678 Comm: syz-executor Tainted: G        W
[   45.123460] Call Trace:
[   45.123461]  <TASK>
[   45.123462]  btrfs_inode+0x123/0x456
[   45.123463]  do_syscall_64+0x3b/0x90
[   45.123464]  </TASK>
[   45.123465] ==================================================================
"""


# ── OOPS parser tests ────────────────────────────────────────────────────────
def test_parse_oops_extracts_faulting_address() -> None:
    report = parse_oops(_MOCK_OOPS)
    assert report.faulting_address == "0000000000000000"


def test_parse_oops_extracts_crashing_instruction() -> None:
    report = parse_oops(_MOCK_OOPS)
    assert "48 8b 00" in report.crashing_instruction


def test_parse_oops_extracts_registers() -> None:
    report = parse_oops(_MOCK_OOPS)
    assert report.register_state.get("RAX") == "0000000000000000"
    assert report.register_state.get("RDI") == "0000000000000000"


def test_parse_oops_extracts_stack_trace() -> None:
    report = parse_oops(_MOCK_OOPS)
    funcs = [f.function for f in report.stack_trace]
    assert "ksys_read" in funcs
    assert "do_syscall_64" in funcs


def test_parse_oops_classifies_null_deref() -> None:
    report = parse_oops(_MOCK_OOPS)
    assert report.bug_type == KernelBugType.NULL_POINTER_DEREF


def test_parse_oops_classifies_uaf_from_kasan() -> None:
    report = parse_oops(_MOCK_UAF_OOPS)
    assert report.bug_type == KernelBugType.USE_AFTER_FREE


def test_parse_oops_extracts_metadata() -> None:
    report = parse_oops(_MOCK_OOPS)
    assert report.comm == "syz-executor"
    assert report.pid == 1234
    assert "G" in report.taint


# ── Syzkaller reproducer parser ──────────────────────────────────────────────
def test_parse_syzkaller_repro_c_style() -> None:
    seq = parse_syzkaller_repro(_MOCK_SYZ_REPRO)
    assert seq.syscalls == ["open", "ioctl", "mmap"]
    assert seq.args[0] == ['"/dev/btrfs-control"', "0"]
    assert seq.args[1] == ["3", "0x50009418", "0"]


def test_parse_syzkaller_repro_empty() -> None:
    seq = parse_syzkaller_repro("")
    assert seq.syscalls == []


# ── High-level kernel crash parser ───────────────────────────────────────────
def test_parse_kernel_crash_full_pipeline() -> None:
    crash = parse_kernel_crash(
        crash_id="repro-001",
        oops_text=_MOCK_OOPS,
        reproducer_text=_MOCK_SYZ_REPRO,
        kernel_version="6.8.0",
    )
    assert crash.crash_id == "repro-001"
    assert crash.kernel_version == "6.8.0"
    assert crash.oops.bug_type == KernelBugType.NULL_POINTER_DEREF
    assert crash.oops.faulting_address == "0000000000000000"
    assert crash.reproducer is not None
    assert crash.reproducer.syscalls == ["open", "ioctl", "mmap"]


# ── Helper tests ───────────────────────────────────────────────────────────
def test_split_args_respects_nesting() -> None:
    args = _split_args('open("/dev/foo", 0), ioctl(3, 0x10, ptr(0x20))')
    assert args == ['open("/dev/foo", 0)', "ioctl(3, 0x10, ptr(0x20))"]


def test_classify_from_text_unknown() -> None:
    assert _classify_from_text("some random kernel log") == KernelBugType.UNKNOWN


def test_classify_from_text_deadlock() -> None:
    assert _classify_from_text("lockdep detected a deadlock") == KernelBugType.DEADLOCK


# ── Model validation ─────────────────────────────────────────────────────────
def test_kernel_crash_model_roundtrip() -> None:
    crash = KernelCrash(
        crash_id="test-001",
        oops=OopsReport(
            raw_text="Oops: 0000",
            bug_type=KernelBugType.NULL_POINTER_DEREF,
            faulting_address="0x0",
            stack_trace=[StackFrame(function="foo", file="bar.c", line=42)],
        ),
        kernel_version="6.8.0",
    )
    js = crash.model_dump_json()
    restored = KernelCrash.model_validate_json(js)
    assert restored.oops.faulting_address == "0x0"
    assert restored.oops.stack_trace[0].line == 42
