# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Tests for harness evolution bug fixes."""

from __future__ import annotations

from pathlib import Path

import pytest

from crashwise.agents.harness_synth.evolution import (
    _extract_target_call,
    _generate_bypass_strategies,
    _read_blocker_context,
    _template_evolve,
)
from crashwise.core.models import (
    BlockerType,
    CoverageBlocker,
    EvolveHarnessInput,
)


# ── _extract_target_call improvements ────────────────────────────────────────
def test_extract_target_call_simple() -> None:
    code = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  parse_image(data, size);\n  return 0;\n}'
    result = _extract_target_call(code)
    assert "parse_image" in result
    assert result.strip().endswith(";")


def test_extract_target_call_with_cast() -> None:
    code = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  process((const char*)data, size);\n  return 0;\n}'
    result = _extract_target_call(code)
    assert "process" in result


def test_extract_target_call_multiline() -> None:
    code = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  decode_buffer(\n    data,\n    size\n  );\n  return 0;\n}'
    result = _extract_target_call(code)
    assert "decode_buffer" in result
    assert result.strip().endswith(";")


def test_extract_target_call_skips_malloc() -> None:
    code = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  void *buf = malloc(size);\n  target_func(data, size);\n  free(buf);\n  return 0;\n}'
    result = _extract_target_call(code)
    assert "target_func" in result
    assert "malloc" not in result
    assert "free" not in result


def test_extract_target_call_skips_control_flow() -> None:
    code = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  if (size > 0) {\n    parse(data, size);\n  }\n  return 0;\n}'
    result = _extract_target_call(code)
    assert "parse" in result


def test_extract_target_call_empty_harness() -> None:
    code = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  return 0;\n}'
    result = _extract_target_call(code)
    assert result == ""


def test_extract_target_call_only_stdlib() -> None:
    code = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  void *buf = malloc(size);\n  memcpy(buf, data, size);\n  free(buf);\n  return 0;\n}'
    result = _extract_target_call(code)
    assert result == ""


# ── _template_evolve no-op prevention ────────────────────────────────────────
@pytest.mark.asyncio
async def test_template_evolve_returns_original_when_no_target_call() -> None:
    """When _extract_target_call fails, return original harness instead of no-op."""
    blocker = CoverageBlocker(
        blocker_type=BlockerType.MAGIC_VALUE,
        line_number=10,
        function_name="parse",
        condition_text="if (magic != 0x89504E47)",
        expected_value="0x89504E47",
        confidence=0.9,
    )
    # Harness with no extractable target call (only stdlib + return)
    original_code = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  void *buf = malloc(size);\n  free(buf);\n  return 0;\n}'
    payload = EvolveHarnessInput(
        current_harness_code=original_code,
        blocker=blocker,
    )
    result = _template_evolve(payload)

    # Should return original harness, not a no-op template
    assert result.evolved_harness_code == original_code
    assert result.confidence == 0.0
    assert "Skipped" in result.bypass_strategy
    assert "TODO" not in result.evolved_harness_code


@pytest.mark.asyncio
async def test_template_evolve_generates_valid_harness_when_target_found() -> None:
    """When target call is found, generate a proper evolved harness."""
    blocker = CoverageBlocker(
        blocker_type=BlockerType.MAGIC_VALUE,
        line_number=10,
        function_name="parse",
        condition_text="if (magic != 0x89504E47)",
        expected_value="0x89504E47",
        confidence=0.9,
    )
    original_code = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  parse_image(data, size);\n  return 0;\n}'
    payload = EvolveHarnessInput(
        current_harness_code=original_code,
        blocker=blocker,
    )
    result = _template_evolve(payload)

    # Should generate an evolved harness with the target call
    assert result.evolved_harness_code != original_code
    assert "parse_image" in result.evolved_harness_code
    assert result.confidence == 0.5
    assert "magic" in result.bypass_strategy.lower()


# ── _read_blocker_context ────────────────────────────────────────────────────
def test_read_blocker_context_valid_file(tmp_path: Path) -> None:
    src = tmp_path / "parser.c"
    src.write_text("line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n")
    result = _read_blocker_context(str(src), 5)
    assert "line5" in result
    assert ">>>" in result  # Marker for the blocker line


def test_read_blocker_context_missing_file() -> None:
    result = _read_blocker_context("/nonexistent/file.c", 10)
    assert "not found" in result


def test_read_blocker_context_none_path() -> None:
    result = _read_blocker_context(None, 10)
    assert "not available" in result


def test_read_blocker_context_invalid_line(tmp_path: Path) -> None:
    src = tmp_path / "parser.c"
    src.write_text("line1\nline2\nline3\n")
    result = _read_blocker_context(str(src), 0)
    assert "out of range" in result


# ── _generate_bypass_strategies ──────────────────────────────────────────────
def test_generate_bypass_strategies_magic_value() -> None:
    result = _generate_bypass_strategies(BlockerType.MAGIC_VALUE)
    assert "magic bytes" in result.lower()
    assert "prefix" in result.lower()


def test_generate_bypass_strategies_length_check() -> None:
    result = _generate_bypass_strategies(BlockerType.LENGTH_CHECK)
    assert "length" in result.lower() or "minimum" in result.lower()


def test_generate_bypass_strategies_null_check() -> None:
    result = _generate_bypass_strategies(BlockerType.NULL_CHECK)
    assert "allocate" in result.lower() or "null" in result.lower()


def test_generate_bypass_strategies_unknown() -> None:
    result = _generate_bypass_strategies(BlockerType.UNKNOWN)
    assert "analyze" in result.lower() or "blocker" in result.lower()
