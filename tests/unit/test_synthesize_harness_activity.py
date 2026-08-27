# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the synthesize_harness activity and local repo ingestion."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from crashwise.core.models import (
    FuzzingInput,
    SetupTargetInput,
    SynthesizeHarnessInput,
    SynthesizeHarnessOutput,
)
from crashwise.orchestration.activities.setup_target import _clone_repo
from crashwise.orchestration.activities.synthesize_harness import (
    _find_target_source_file,
    synthesize_harness_activity,
)


def test_fuzzing_input_accepts_various_url_formats() -> None:
    """Verify FuzzingInput accepts https, git@, file://, and local paths."""
    # HTTPS
    inp1 = FuzzingInput(target_repo="https://github.com/madler/zlib.git")
    assert inp1.target_repo == "https://github.com/madler/zlib.git"

    # SSH
    inp2 = FuzzingInput(target_repo="git@github.com:madler/zlib.git")
    assert inp2.target_repo == "git@github.com:madler/zlib.git"

    # file://
    inp3 = FuzzingInput(target_repo="file:///tmp/dummy-target")
    assert inp3.target_repo == "file:///tmp/dummy-target"

    # Local absolute path
    inp4 = FuzzingInput(target_repo="/tmp/dummy-target")
    assert inp4.target_repo == "/tmp/dummy-target"


def test_setup_target_input_accepts_various_url_formats() -> None:
    """Verify SetupTargetInput accepts various path formats."""
    inp = SetupTargetInput(target_repo="file:///tmp/my-target")
    assert inp.target_repo == "file:///tmp/my-target"


def test_find_target_source_file_locates_c_file() -> None:
    """Verify _find_target_source_file finds relevant C files while ignoring build/test dirs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # Create dummy structure
        (root / "build").mkdir()
        (root / "build" / "ignored.c").write_text("int x;")
        (root / "test").mkdir()
        (root / "test" / "test_main.c").write_text("int test;")
        (root / "src").mkdir()
        src_file = root / "src" / "parser.c"
        src_file.write_text("int parse(const char *s) { return 0; }")

        found = _find_target_source_file(root)
        assert found is not None
        assert found.resolve() == src_file.resolve()


@pytest.mark.asyncio
async def test_clone_repo_copies_local_directory() -> None:
    """Verify _clone_repo copies a local non-git directory seamlessly."""
    with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dest_dir:
        src = Path(src_dir)
        dest = Path(dest_dir) / "checkout"
        (src / "main.c").write_text("int main() { return 0; }")

        sha = await _clone_repo(
            repo_url=str(src),
            branch=None,
            workdir=dest,
        )
        assert sha == "local-snapshot"
        assert (dest / "main.c").exists()
        assert (dest / "main.c").read_text() == "int main() { return 0; }"


@pytest.mark.asyncio
async def test_synthesize_harness_activity_success() -> None:
    """Verify synthesize_harness_activity completes successfully when harness synth succeeds."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir)
        src = ws / "target.c"
        src.write_text("int target_func(const char *b) { return 0; }")

        mock_result = AsyncMock()
        mock_result.success = True
        mock_result.harness_path = ws / "harness" / "harness.cpp"
        mock_result.binary_path = ws / "harness" / "harness"
        mock_result.retry_count = 0
        mock_result.last_stderr = ""

        with patch(
            "crashwise.orchestration.activities.synthesize_harness.synthesize_harness",
            return_value=mock_result,
        ):
            output = await synthesize_harness_activity(
                SynthesizeHarnessInput(
                    workspace_path=ws,
                    source_file_path=src,
                    fuzzer_type="libfuzzer",
                )
            )
            assert output.success is True
            assert output.harness_path == ws / "harness" / "harness.cpp"
            assert output.binary_path == ws / "harness" / "harness"
            assert output.source_file_used == src
