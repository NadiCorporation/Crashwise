# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Tests for the clang++ wrapper.

These exercise the real compiler when available; otherwise they're skipped.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from crashwise.agents.harness_synth.compiler import compile_harness

pytestmark = pytest.mark.skipif(
    shutil.which("clang++") is None,
    reason="clang++ not installed; install via scripts/setup.sh",
)


_GOOD_HARNESS = """\
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0 && data[0] == 'A') {
        return 1;
    }
    return 0;
}
"""

_BAD_HARNESS = """\
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return undeclared_symbol(data, size);
}
"""


@pytest.mark.asyncio
async def test_compile_harness_success(tmp_path: Path) -> None:
    src = tmp_path / "harness.cpp"
    src.write_text(_GOOD_HARNESS, encoding="utf-8")
    result = await compile_harness(harness_path=src, workdir=tmp_path)
    assert result.success is True
    assert result.returncode == 0
    assert result.binary_path is not None
    assert result.binary_path.exists()


@pytest.mark.asyncio
async def test_compile_harness_failure_captures_stderr(tmp_path: Path) -> None:
    src = tmp_path / "harness.cpp"
    src.write_text(_BAD_HARNESS, encoding="utf-8")
    result = await compile_harness(harness_path=src, workdir=tmp_path)
    assert result.success is False
    assert result.returncode != 0
    assert "undeclared_symbol" in result.stderr or "use of undeclared" in result.stderr
    assert result.binary_path is None
