# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""KernelBridge — collaborative Linux-kernel research and fuzzing.

Wraps syzkaller-style workflows behind Temporal so multiple agents (and
human operators) can drive long-running kernel campaigns with durable state.

Public API:
    :func:`parse_kernel_crash`  — high-level OOPS + reproducer parser.
    :func:`parse_oops`          — parse raw OOPS text.
    :func:`parse_syzkaller_repro` — parse syzkaller C reproducer.
    :class:`KernelCrash`       — top-level crash model.
    :class:`OopsReport`         — parsed OOPS model.
    :class:`SyscallSequence`   — reproducer model.
"""

from __future__ import annotations

from crashwise.kernelbridge.models import (
    KernelBugType,
    KernelCrash,
    OopsReport,
    StackFrame,
    SyscallSequence,
)
from crashwise.kernelbridge.parser import (
    parse_kernel_crash,
    parse_oops,
    parse_syzkaller_repro,
)

__all__ = [
    "KernelBugType",
    "KernelCrash",
    "OopsReport",
    "StackFrame",
    "SyscallSequence",
    "parse_kernel_crash",
    "parse_oops",
    "parse_syzkaller_repro",
]
