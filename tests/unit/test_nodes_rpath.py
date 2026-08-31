# SPDX-License-Identifier: MIT
"""Unit tests for ELF shared library -Wl,-rpath single-token handling."""
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from crashwise.agents.harness_synth.build_resolver import BuildPaths
from crashwise.agents.harness_synth.nodes import validate_harness
from crashwise.agents.harness_synth.state import CompileResult, HarnessState


def test_build_resolver_so_rpath(tmp_path: Path) -> None:
    """Verify BuildPaths.to_compile_args emits -Wl,-rpath,<dir> as single atomic tokens."""
    paths = BuildPaths(
        include_dirs=[tmp_path / "include"],
        lib_files=[tmp_path / "lib" / "libtarget.so"],
        lib_dirs=[tmp_path / "lib"],
    )

    args = paths.to_compile_args()

    expected_rpath = f"-Wl,-rpath,{(tmp_path / 'lib').resolve()}"
    assert expected_rpath in args
    assert f"-L{tmp_path / 'lib'}" in args
    assert "-Wl,-rpath" not in args  # Must not be split across two list elements


@pytest.mark.asyncio
async def test_validate_harness_rpath_syntax(tmp_path: Path) -> None:
    """Verify validate_harness builds compile args with atomic -Wl,-rpath,<dir>."""
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    src_file = src_dir / "target.c"
    src_file.write_text("int target_func(const char* s) { return 0; }")

    lib_dir = tmp_path / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)
    so_file = lib_dir / "libtarget.so"
    so_file.write_bytes(b"ELF-fake-so")

    (tmp_path / "CMakeLists.txt").write_text("project(test)")

    harness_code = """
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return 0;
}
"""
    harness_file = tmp_path / "harness.c"
    harness_file.write_text(harness_code)

    state = HarnessState(
        source_path=src_file,
        source_code=src_file.read_text(),
        harness_path=harness_file,
        workdir=tmp_path / "harness_work",
        harness_code=harness_code,
        max_retries=1,
    )

    captured_compile_kwargs: dict[str, object] = {}

    async def mock_compile_harness(**kwargs: object) -> CompileResult:
        captured_compile_kwargs.update(kwargs)
        return CompileResult(
            success=True,
            returncode=0,
            stdout="",
            stderr="",
            binary_path=tmp_path / "harness_work" / "harness_bin",
        )

    with patch("crashwise.agents.harness_synth.nodes.compile_harness", side_effect=mock_compile_harness), patch("crashwise.agents.harness_synth.nodes.sanity_check", return_value=AsyncMock(passed=True, edges_hit=5, crashed_immediately=False)):
        res = await validate_harness(state)
        assert res.succeeded is True

    extra_link_args = captured_compile_kwargs.get("extra_args", [])
    expected_rpath = f"-Wl,-rpath,{lib_dir.resolve()}"
    assert expected_rpath in extra_link_args
    assert "-Wl,-rpath" not in extra_link_args  # Must NOT be separated
