# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the Phase-3 triage pipeline.

LLM is stubbed; these exercise the heuristic fallback, deduplication,
and GDB backtrace parsing.
"""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage

from crashwise.agents.harness_synth.llm import set_chat_model_override
from crashwise.agents.triage.analyzer import triage_batch, triage_crash
from crashwise.agents.triage.dedup import CrashDeduper, compute_stack_hash, normalise_stack
from crashwise.agents.triage.models import BugType, CrashReport, StackFrame


class _StubLLM:
    """Returns a canned JSON triage response."""

    def __init__(self, response_json: str) -> None:
        self._response = response_json

    async def ainvoke(self, *args: object, **kwargs: object) -> AIMessage:
        return AIMessage(content=self._response)


@pytest.fixture(autouse=True)
def _clear_llm_override() -> None:
    """Force LLM path to fail so heuristic fallback is exercised."""

    class _FailingLLM:
        async def ainvoke(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("LLM disabled for heuristic tests")

    set_chat_model_override(_FailingLLM())
    yield
    set_chat_model_override(None)


# ── Mock data ────────────────────────────────────────────────────────────────
_GDB_OUTPUT = """\
#0  0x00007f8b2c3a4d11 in parse_packet () from /lib/libparser.so
#1  0x0000555a1b2c3e4a in main () at harness.cpp:45
#2  0x00007f8b2c1a4f25 in __libc_start_main () from /lib/libc.so.6
"""

_ASAN_HEAP_UAF = """\
ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
READ of size 1 in parse_packet() at parser.c:42
#0 0x555a in parse_packet parser.c:42
#1 0x666b in LLVMFuzzerTestOneInput harness.cpp:30
"""

_ASAN_HEAP_OOB = """\
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000020
WRITE of size 4 in decode_buffer() at decoder.c:15
#0 0x777c in decode_buffer decoder.c:15
"""


# ── Dedup tests ──────────────────────────────────────────────────────────────
def test_normalise_stack_strips_addresses() -> None:
    report = CrashReport(
        crash_id="test",
        stack_frames=[
            StackFrame(function="main", file="/home/user/src/main.c", line=42, pc="0x555a"),
            StackFrame(function="parse", file="/home/user/src/parser.c", line=10, pc="0x666b"),
        ],
    )
    norm = normalise_stack(report)
    assert "0x555a" not in norm
    assert "0x666b" not in norm
    assert "/home/user" not in norm
    assert "main@main.c:42" in norm or "main" in norm


def test_compute_stack_hash_stable() -> None:
    report = CrashReport(
        crash_id="a",
        stack_frames=[
            StackFrame(function="foo", file="x.c", line=1),
            StackFrame(function="bar", file="y.c", line=2),
        ],
    )
    h1 = compute_stack_hash(report)
    h2 = compute_stack_hash(report)
    assert h1 == h2
    assert len(h1) == 64  # SHA256 hex


def test_deduper_flags_duplicate() -> None:
    deduper = CrashDeduper()
    report1 = CrashReport(
        crash_id="first",
        stack_frames=[StackFrame(function="foo", file="x.c", line=1)],
    )
    report2 = CrashReport(
        crash_id="second",
        stack_frames=[StackFrame(function="foo", file="x.c", line=1)],
    )
    r1 = deduper.check(report1)
    assert r1.duplicate_of is None
    r2 = deduper.check(report2)
    assert r2.duplicate_of == "first"


# ── Heuristic fallback tests ─────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_heuristic_classifies_asan_heap_uaf() -> None:
    report = CrashReport(crash_id="uaf", asan_output=_ASAN_HEAP_UAF)
    result = await triage_crash(report)
    assert result.bug_type == BugType.HEAP_USE_AFTER_FREE
    assert result.severity == "critical"
    assert result.confidence >= 0.8


@pytest.mark.asyncio
async def test_heuristic_classifies_asan_heap_oob() -> None:
    report = CrashReport(crash_id="oob", asan_output=_ASAN_HEAP_OOB)
    result = await triage_crash(report)
    assert result.bug_type == BugType.HEAP_BUFFER_OVERFLOW
    assert result.severity == "critical"


@pytest.mark.asyncio
async def test_heuristic_null_deref_from_sigsegv() -> None:
    report = CrashReport(
        crash_id="null",
        raw_text="Program received signal SIGSEGV, Segmentation fault.\n",
        registers={"pc": "0x0"},
    )
    result = await triage_crash(report)
    assert result.bug_type == BugType.NULL_POINTER_DEREF
    assert result.severity == "high"


@pytest.mark.asyncio
async def test_heuristic_unknown_when_no_signals() -> None:
    report = CrashReport(crash_id="blank", raw_text="some random log")
    result = await triage_crash(report)
    assert result.bug_type == BugType.UNKNOWN
    assert result.confidence == 0.0


# ── LLM path tests ───────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_llm_classifies_when_available() -> None:
    stub_response = (
        '{"bug_type": "use-after-free", "severity": "critical", '
        '"root_cause": "Double free in parser", "confidence": 0.95, '
        '"recommendations": ["Audit parser.c"] }'
    )
    set_chat_model_override(_StubLLM(stub_response))

    report = CrashReport(crash_id="llm-test", raw_text="anything")
    result = await triage_crash(report)
    assert result.bug_type == BugType.USE_AFTER_FREE
    assert result.severity == "critical"
    assert result.confidence == 0.95
    assert result.recommendations == ["Audit parser.c"]


@pytest.mark.asyncio
async def test_llm_malformed_json_falls_back_to_heuristics() -> None:
    set_chat_model_override(_StubLLM("not json at all"))

    report = CrashReport(crash_id="bad-llm", asan_output=_ASAN_HEAP_UAF)
    result = await triage_crash(report)
    # Fallback should still catch the ASAN heap-use-after-free.
    assert result.bug_type == BugType.HEAP_USE_AFTER_FREE


@pytest.mark.asyncio
async def test_llm_exception_falls_back_to_heuristics() -> None:
    class _ExplodingLLM:
        async def ainvoke(self, *args: object, **kwargs: object) -> AIMessage:
            raise RuntimeError("network down")

    set_chat_model_override(_ExplodingLLM())  # type: ignore[arg-type]

    report = CrashReport(crash_id="explode", asan_output=_ASAN_HEAP_OOB)
    result = await triage_crash(report)
    assert result.bug_type == BugType.HEAP_BUFFER_OVERFLOW


# ── Batch triage ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_batch_dedupes_internally() -> None:
    reports = [
        CrashReport(
            crash_id="a",
            stack_frames=[StackFrame(function="foo", file="x.c", line=1)],
        ),
        CrashReport(
            crash_id="b",
            stack_frames=[StackFrame(function="foo", file="x.c", line=1)],
        ),
    ]
    results = await triage_batch(reports)
    assert results[0].duplicate_of is None
    assert results[1].duplicate_of == "a"


# ── GDB parser ───────────────────────────────────────────────────────────────
def test_parse_gdb_backtrace() -> None:
    from crashwise.orchestration.activities.triage_results import _parse_gdb_backtrace

    frames = _parse_gdb_backtrace(_GDB_OUTPUT)
    assert len(frames) == 3
    assert frames[0].function == "parse_packet"
    assert frames[1].function == "main ()"
    assert frames[1].file == "harness.cpp"
    assert frames[1].line == 45
    assert frames[2].function == "__libc_start_main"


# ── ASAN parser ──────────────────────────────────────────────────────────────
_ASAN_REAL_OUTPUT = """\
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000020
    #0 0x4e6c1d in inflate_fast /src/zlib/inflate.c:232:3
    #1 0x4e1a1b in inflate /src/zlib/inflate.c:987
    #2 0x555a2b in LLVMFuzzerTestOneInput+0x42 /src/harness.cpp:30
"""


def test_parse_asan_backtrace() -> None:
    from crashwise.orchestration.activities.triage_results import _parse_asan_backtrace

    frames = _parse_asan_backtrace(_ASAN_REAL_OUTPUT)
    assert len(frames) == 3
    assert frames[0].function == "inflate_fast"
    assert frames[0].file == "/src/zlib/inflate.c"
    assert frames[0].line == 232
    assert frames[1].function == "inflate"
    assert frames[1].line == 987
    assert frames[2].function == "LLVMFuzzerTestOneInput"


def test_asan_frames_produce_stable_hash() -> None:
    from crashwise.agents.triage.dedup import compute_stack_hash
    from crashwise.orchestration.activities.triage_results import _parse_asan_backtrace

    frames = _parse_asan_backtrace(_ASAN_REAL_OUTPUT)
    report = CrashReport(crash_id="asan", stack_frames=frames)
    h1 = compute_stack_hash(report)
    h2 = compute_stack_hash(report)
    assert h1 == h2
    assert len(h1) == 64
