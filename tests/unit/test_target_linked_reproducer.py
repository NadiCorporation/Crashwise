# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Milestone M4 / Requirement R4: Target-Linked Crash Reproducer & Reporting."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from crashwise.agents.reporting.generator import generate_finding_report, generate_report
from crashwise.agents.triage.analyzer import classify_crash_severity
from crashwise.agents.triage.exploit_gen import (
    _build_compilation_command,
    _template_for_primitive,
    generate_exploit,
    generate_target_linked_reproducer,
)
from crashwise.agents.triage.models import BugType, CrashReport, StackFrame
from crashwise.core.models import (
    CrashSeverity,
    FindingReport,
    PocVerifyInput,
    PocVerifyOutput,
)
from crashwise.orchestration.activities.verify_poc import (
    _compile,
    _execute,
    _verify_high_fidelity,
    verify_poc,
)


# ── Test 1: Generated reproducer includes target headers & links target library ──
@pytest.mark.asyncio
async def test_reproducer_includes_target_headers_and_links_library() -> None:
    """Generated reproducer contains #include of target headers and links library."""
    report = CrashReport(
        crash_id="repro-1",
        asan_output="ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000020",
        stack_frames=[StackFrame(function="inflate_fast", file="inflate.c", line=232)],
    )

    result = await generate_target_linked_reproducer(
        report,
        target_func="inflate_fast",
        crash_file_path="/tmp/crash_payload.bin",
        target_headers=["zlib.h", "<stdint.h>"],
        target_include_dirs=["/usr/include/zlib", "/opt/target/include"],
        target_libs=["/opt/target/lib/libz.a", "-lz"],
        link_flags=["-Wl,-rpath,/opt/target/lib"],
    )

    # 1. Check header inclusion in C code
    assert '#include "zlib.h"' in result.poc_code or '#include <zlib.h>' in result.poc_code
    assert "#include <stdint.h>" in result.poc_code
    assert "#include <stdio.h>" in result.poc_code
    assert "main(int argc, char **argv)" in result.poc_code

    # 2. Check compilation command includes target include dirs and libraries
    assert "-I/usr/include/zlib" in result.compilation_command
    assert "-I/opt/target/include" in result.compilation_command
    assert "/opt/target/lib/libz.a" in result.compilation_command
    assert "-lz" in result.compilation_command
    assert "-Wl,-rpath,/opt/target/lib" in result.compilation_command
    assert result.target_linked is True


# ── Test 2: Reproducer reads minimized crash file from argv[1] ──────────────────
@pytest.mark.asyncio
async def test_reproducer_reads_crash_file_from_argv1() -> None:
    """Reproducer reads crash input from argv[1] and passes buffer to target function."""
    report = CrashReport(
        crash_id="repro-2",
        asan_output="ERROR: AddressSanitizer: out-of-bounds-write in cJSON_Parse()",
    )

    result = await generate_exploit(
        report,
        target_func="cJSON_Parse",
        crash_file_path="/var/fuzz/crashes/min_crash.bin",
    )

    # Must check argv[1] with default fallback
    assert "if (argc > 1)" in result.poc_code
    assert "input_path = argv[1];" in result.poc_code
    assert "/var/fuzz/crashes/min_crash.bin" in result.poc_code
    assert "fopen(input_path, \"rb\")" in result.poc_code
    assert "fread(buffer, 1," in result.poc_code
    assert "cJSON_Parse(buffer, bytes_read);" in result.poc_code
    assert "free(buffer);" in result.poc_code


# ── Test 3: Target-linked compilation and execution with mock library ──────────
@pytest.mark.asyncio
async def test_target_linked_compilation_and_execution() -> None:
    """Target-linked reproducer compiles against a real/mock C target library and executes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        inc_dir = tmp_path / "include"
        inc_dir.mkdir()
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        # 1. Create a mock target header and source
        header_path = inc_dir / "target_lib.h"
        header_path.write_text("""
#ifndef TARGET_LIB_H
#define TARGET_LIB_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
int parse_vuln_packet(const uint8_t *data, size_t size);
#ifdef __cplusplus
}
#endif
#endif
""")

        target_src = tmp_path / "target_lib.c"
        target_src.write_text("""
#include "target_lib.h"
#include <stdlib.h>
#include <string.h>

int parse_vuln_packet(const uint8_t *data, size_t size) {
    if (!data || size < 4) return 0;
    if (data[0] == 'B' && data[1] == 'U' && data[2] == 'G') {
        char *buf = (char *)malloc(8);
        // Trigger heap buffer overflow on write
        memset(buf, 'X', size);
        free(buf);
        return 1;
    }
    return 0;
}
""")

        # 2. Create crash input file
        crash_file = tmp_path / "crash.bin"
        crash_file.write_bytes(b"BUG_OVERFLOW_PAYLOAD_1234567890")

        # 3. Generate reproducer C code
        report = CrashReport(
            crash_id="test-mock-target",
            asan_output="ERROR: AddressSanitizer: heap-buffer-overflow in parse_vuln_packet",
        )
        gen_output = await generate_target_linked_reproducer(
            report,
            target_func="parse_vuln_packet",
            crash_file_path=str(crash_file),
            target_headers=['"target_lib.h"'],
            target_include_dirs=[str(inc_dir)],
        )

        # 4. Verify compilation and execution with ASan
        poc_src = tmp_path / "poc.c"
        poc_src.write_text(gen_output.poc_code)
        poc_bin = tmp_path / "poc_bin"

        # Compile reproducer + target source with ASan
        custom_cmd = (
            f"clang -fsanitize=address -g -O0 -I{inc_dir} {poc_src} {target_src} -o {poc_bin}"
        )
        ok, _stdout, stderr = await _compile(poc_src, poc_bin, custom_command=custom_cmd)
        assert ok is True, f"Compilation failed: {stderr}"
        assert poc_bin.exists()

        # Execute with crash input
        exec_ok, _out, err, sig = await _execute(poc_bin, crash_file_path=str(crash_file))
        assert exec_ok is True
        assert "AddressSanitizer: heap-buffer-overflow" in err or sig != ""


# ── Test 4: ASan Signature Matching (Exact Error Class & Frame #0 Function) ─────
def test_asan_signature_matching_exact_class_and_frame_zero() -> None:
    """_verify_high_fidelity matches exact ASan error class and frame #0 crashing function."""
    asan_stderr = """
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000030 at pc 0x5555555551dc bp 0x7fffffffe000 sp 0x7fffffffe000
WRITE of size 32 at 0x602000000030 thread T0
    #0 0x5555555551db in parse_vuln_packet /tmp/target_lib.c:11
    #1 0x55555555530f in main /tmp/poc.c:54
    #2 0x7ffff7a05249 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29249)
=================================================================
"""

    # Exact match for class and frame #0 function
    asan_matched, func_matched, reproduced, fidelity = _verify_high_fidelity(
        asan_stderr,
        expected_asan_pattern="heap-buffer-overflow",
        expected_function="parse_vuln_packet",
        signal_received="SIGSEGV",
    )
    assert asan_matched is True
    assert func_matched is True
    assert reproduced is True
    assert fidelity == 1.0

    # Wrong function (e.g. crashing in helper function instead of target)
    asan_m2, func_m2, repro2, fid2 = _verify_high_fidelity(
        asan_stderr,
        expected_asan_pattern="heap-buffer-overflow",
        expected_function="unrelated_function",
        signal_received="SIGSEGV",
    )
    assert asan_m2 is True
    assert func_m2 is False
    assert repro2 is True
    assert fid2 < 1.0  # partial fidelity


# ── Test 5: Severity Classifier Assigns CRITICAL to Write Primitives & Controlled IP
def test_severity_classifier_critical_write_and_controlled_ip() -> None:
    """Classifier assigns CRITICAL (9.0-10.0) to write-what-where and controlled IP."""
    # Write primitive in ASan
    asan_write = """
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 8 at 0x602000000010 thread T0
    #0 0x555a in write_primitive parser.c:42
"""
    sev, score, prim = classify_crash_severity(
        bug_type=BugType.HEAP_BUFFER_OVERFLOW,
        asan_output=asan_write,
    )
    assert sev == CrashSeverity.CRITICAL
    assert 9.0 <= score <= 10.0
    assert "write" in prim

    # Controlled instruction pointer (PC 0x41414141)
    sev_ip, score_ip, prim_ip = classify_crash_severity(
        bug_type=BugType.UNKNOWN,
        registers={"pc": "0x41414141"},
        raw_text="Program received signal SIGSEGV, Segmentation fault (pc 0x41414141).",
    )
    assert sev_ip == CrashSeverity.CRITICAL
    assert score_ip == 10.0
    assert prim_ip == "controlled-ip"


# ── Test 6: Severity Classifier Assigns LOW to Null-Deref-Read ─────────────────
def test_severity_classifier_low_null_deref_read() -> None:
    """Classifier assigns LOW (1.0-3.9) to null pointer dereferences and divide-by-zero."""
    # Null pointer dereference
    sev_null, score_null, prim_null = classify_crash_severity(
        bug_type=BugType.NULL_POINTER_DEREF,
        registers={"pc": "0x0000000000000000"},
        raw_text="AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x0... READ)",
    )
    assert sev_null == CrashSeverity.LOW
    assert 1.0 <= score_null <= 3.9
    assert "null" in prim_null

    # Divide by zero
    sev_fpe, score_fpe, prim_fpe = classify_crash_severity(
        bug_type=BugType.DIVIDE_BY_ZERO,
        raw_text="Program received signal SIGFPE, Arithmetic exception (divide by zero).",
    )
    assert sev_fpe == CrashSeverity.LOW
    assert 1.0 <= score_fpe <= 3.9
    assert prim_fpe == "divide-by-zero"


# ── Test 7: Severity Classifier Assigns HIGH to UAF/Double-Free & MEDIUM to OOB Read
def test_severity_classifier_high_uaf_and_medium_oob_read() -> None:
    """Classifier assigns HIGH to UAF / Double-Free and MEDIUM to Out-of-bounds Read."""
    # Heap use-after-free
    sev_uaf, score_uaf, _ = classify_crash_severity(
        bug_type=BugType.HEAP_USE_AFTER_FREE,
        asan_output="ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010",
    )
    assert sev_uaf == CrashSeverity.HIGH
    assert 7.0 <= score_uaf <= 8.9

    # Double free
    sev_df, score_df, _ = classify_crash_severity(
        bug_type=BugType.DOUBLE_FREE,
        asan_output="ERROR: AddressSanitizer: double-free on address 0x602000000010",
    )
    assert sev_df == CrashSeverity.HIGH
    assert 7.0 <= score_df <= 8.9

    # Out-of-bounds read
    asan_read = """
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
READ of size 4 at 0x602000000010 thread T0
    #0 0x555a in read_element parser.c:18
"""
    sev_read, score_read, _ = classify_crash_severity(
        bug_type=BugType.OUT_OF_BOUNDS_READ,
        asan_output=asan_read,
    )
    assert sev_read == CrashSeverity.MEDIUM
    assert 4.0 <= score_read <= 6.9


# ── Test 8: Structured Finding Report Generation ─────────────────────────────
def test_structured_finding_report_generation() -> None:
    """generate_finding_report produces a complete FindingReport with SHA256 & metadata."""
    payload = b"CRASH_TEST_PAYLOAD_ABCDEF123456"
    expected_hash = hashlib.sha256(payload).hexdigest()

    crash_data = {
        "crash_id": "cve-finding-42",
        "bug_type": "heap-buffer-overflow",
        "affected_function": "decode_header",
        "source_location": "decoder.c:142",
        "asan_output": "ERROR: AddressSanitizer: heap-buffer-overflow\nWRITE of size 8 in decode_header at decoder.c:142",
        "root_cause": "Buffer length integer truncation before memcpy",
        "suggested_patch": "--- decoder.c\n+++ decoder.c\n- if (len > 0)\n+ if (len > 0 && len <= MAX_BUF)",
        "target_name": "libdecoder",
        "target_repo": "https://github.com/example/libdecoder",
        "target_linked": True,
        "crash_reproduced": True,
        "asan_class_matched": True,
        "function_matched": True,
        "poc_code": "#include <stdio.h>\nint main(int argc, char **argv) { return 0; }",
        "compilation_command": "clang -fsanitize=address poc.c -o poc -ldecoder",
        "reproduction_fidelity": 1.0,
    }

    report: FindingReport = generate_finding_report(
        crash_data,
        crash_file_bytes=payload,
    )

    assert report.crash_id == "cve-finding-42"
    assert report.bug_class == "heap-buffer-overflow"
    assert report.affected_function == "decode_header"
    assert report.source_location == "decoder.c:142"
    assert report.crash_input_hash == expected_hash
    assert report.severity_level == CrashSeverity.CRITICAL
    assert report.severity_score >= 9.0
    assert report.reproduction.target_linked is True
    assert report.reproduction.reproduced is True
    assert report.reproduction.asan_matched is True
    assert report.reproduction.function_matched is True
    assert report.reproduction.fidelity_score == 1.0


# ── Test 9: Crash Input Hash from File on Disk ───────────────────────────────
def test_finding_report_hash_from_file_path() -> None:
    """generate_finding_report computes correct SHA256 hex digest when given file path."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"SAMPLE_FUZZ_SEED_CONTENT_987654321")
        f.flush()
        file_path = f.name

    expected_sha = hashlib.sha256(b"SAMPLE_FUZZ_SEED_CONTENT_987654321").hexdigest()
    try:
        report = generate_finding_report(
            {"crash_id": "seed-test", "bug_type": "use-after-free"},
            crash_file_path=file_path,
        )
        assert report.crash_input_hash == expected_sha
    finally:
        Path(file_path).unlink(missing_ok=True)


# ── Test 10: Compilation Command Builder with Target Artifacts ─────────────────
def test_compilation_command_builder() -> None:
    """_build_compilation_command correctly formats include dirs, static archives, and link flags."""
    cmd = _build_compilation_command(
        target_include_dirs=["/path/include", "/path/target"],
        target_libs=["/path/lib/libtarget.a", "-L/custom/lib", "-lcustom"],
        link_flags=["-Wl,-Bstatic", "-Wl,-Bdynamic"],
        compiler="clang",
    )
    assert "clang" in cmd
    assert "-fsanitize=address,undefined" in cmd
    assert "-I/path/include" in cmd
    assert "-I/path/target" in cmd
    assert "/path/lib/libtarget.a" in cmd
    assert "-lcustom" in cmd
    assert "-lm" in cmd
    assert "-lpthread" in cmd


# ── Test 11: verify_poc Activity with Target Linking & Activity Context ────────
@pytest.mark.asyncio
async def test_verify_poc_activity_full_cycle() -> None:
    """verify_poc activity executes with mock activity info and reports fidelity."""
    mock_info = MagicMock()
    mock_info.workflow_id = "wf-verify-123"
    mock_info.attempt = 1

    poc_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    char *buf = malloc(16);
    memset(buf, 'A', 64); // ASan heap-buffer-overflow
    free(buf);
    return 0;
}
"""
    with patch("crashwise.orchestration.activities.verify_poc.activity.info", return_value=mock_info):
        output: PocVerifyOutput = await verify_poc(
            PocVerifyInput(
                crash_id="test-verify-poc",
                poc_code=poc_code,
                expected_asan_pattern="heap-buffer-overflow",
                expected_signal="SIGSEGV",
                target_include_dirs=["/usr/include"],
                target_link_libs=["-lz"],
                timeout_seconds=30,
            )
        )

    assert output.compiled is True
    assert output.crash_reproduced is True
    assert output.target_linked is True
    assert output.asan_class_matched is True
    assert output.reproduction_fidelity >= 0.8


# ── Test 12: FindingReport Model Strict Configuration ─────────────────────────
def test_finding_report_strict_model_config() -> None:
    """FindingReport rejects extra undeclared attributes per _StrictModel contract."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        FindingReport(  # type: ignore[call-arg]
            crash_id="strict-1",
            bug_class="double-free",
            invalid_extra_field="should_be_forbidden",
        )


# ── Test 13: C++ Forward Declaration Wrapper Generation ─────────────────────
def test_reproducer_forward_declaration_wrapper() -> None:
    """Reproducer wraps target function with extern C forward declaration when headers omitted."""
    report = CrashReport(crash_id="cxx-repro", stack_frames=[StackFrame(function="cpp_target_func", file="target.cpp", line=50)])
    code = _template_for_primitive("out-of-bounds-write", report, target_func="cpp_target_func")
    assert 'extern "C"' in code
    assert "cpp_target_func(" in code
    assert "main(int argc, char **argv)" in code


# ── Test 14: LLVMFuzzerTestOneInput Invocation Pattern ────────────────────────
def test_reproducer_llvmfuzzer_invocation() -> None:
    """Reproducer invokes LLVMFuzzerTestOneInput correctly with buffer and size."""
    report = CrashReport(crash_id="fuzzer-repro", stack_frames=[StackFrame(function="LLVMFuzzerTestOneInput", file="harness.cpp", line=25)])
    code = _template_for_primitive("use-after-free", report, target_func="LLVMFuzzerTestOneInput")
    assert "LLVMFuzzerTestOneInput(buffer, bytes_read);" in code


# ── Test 15: Severity Classifier for Uninitialized Read & Integer Overflow ───
def test_severity_classifier_uninitialized_and_integer_overflow() -> None:
    """Severity classifier assigns MEDIUM to uninitialized-read and integer-overflow."""
    sev_uninit, score_uninit, _ = classify_crash_severity(
        bug_type=BugType.UNINITIALIZED_READ,
        asan_output="ERROR: MemorySanitizer: use-of-uninitialized-value",
    )
    assert sev_uninit == CrashSeverity.MEDIUM
    assert 4.0 <= score_uninit <= 6.9

    sev_int, score_int, _ = classify_crash_severity(
        bug_type=BugType.INTEGER_OVERFLOW,
        raw_text="UndefinedBehaviorSanitizer: signed integer overflow",
    )
    assert sev_int == CrashSeverity.MEDIUM
    assert 4.0 <= score_int <= 6.9


# ── Test 16: Finding Report Automatic Location Extraction from ASan Trace ─────
def test_finding_report_location_extraction_from_trace() -> None:
    """generate_finding_report extracts affected_function and file:line from ASan backtrace."""
    crash_data = {
        "crash_id": "trace-extract-1",
        "bug_type": "heap-buffer-overflow",
        "asan_output": """
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 4 at 0x602000000010 thread T0
    #0 0x555a in parse_payload /workspace/parser.c:88
    #1 0x666b in main /workspace/main.c:20
""",
    }
    report = generate_finding_report(crash_data)
    assert report.affected_function == "parse_payload"
    assert "/workspace/parser.c:88" in report.source_location or "parser.c:88" in report.source_location
    assert report.severity_level == CrashSeverity.CRITICAL


# ── Test 17: Multi-Format Vulnerability Report Synthesis ─────────────────────
@pytest.mark.asyncio
async def test_generate_report_multi_format() -> None:
    """generate_report produces valid reports across generic, hackerone, bugcrowd, and kernel formats."""
    crash_data = {
        "target_name": "zlib",
        "target_repo": "https://github.com/madler/zlib",
        "bug_type": "heap-buffer-overflow",
        "severity": "critical",
        "severity_score": 9.5,
        "vulnerability_type": "CWE-122",
        "root_cause": "Buffer overflow in inflate_fast",
        "suggested_patch": "--- inflate.c\n+++ inflate.c\n+ bounds_check();",
        "verification_status": "reproduced",
        "stack_trace": "#0 0x123 in inflate_fast inflate.c:232",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
    }

    for fmt in ("generic", "hackerone", "bugcrowd", "kernel"):
        result = await generate_report(crash_data, fmt=fmt)
        assert result["platform"] == fmt
        assert "zlib" in result["title"] or "zlib" in result["body"]
        assert "heap-buffer-overflow" in result["title"].lower() or "heap buffer overflow" in result["title"].lower() or "heap" in result["body"].lower()

