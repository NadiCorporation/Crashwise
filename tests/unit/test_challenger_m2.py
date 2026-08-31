# SPDX-License-Identifier: MIT
"""Adversarial stress tests for Milestone M2 forensics."""
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError
from temporalio.exceptions import ApplicationError

from crashwise.api.main import CampaignCreateRequest
from crashwise.core.models import FuzzingInput, SetupTargetInput
from crashwise.orchestration.activities.setup_target import (
    _clone_repo,
    _extract_bazel_artifacts,
    _rank_and_select_libraries,
    setup_target,
)


def test_adversarial_pydantic_bounds():
    # Negative clone depth
    with pytest.raises(ValidationError):
        FuzzingInput(target_repo="https://github.com/foo/bar", target_clone_depth=-1)
    with pytest.raises(ValidationError):
        SetupTargetInput(target_repo="https://github.com/foo/bar", target_clone_depth=-5)
    with pytest.raises(ValidationError):
        CampaignCreateRequest(target_repo="https://github.com/foo/bar", target_name="bar", target_clone_depth=-1)

    # Subdir max length
    with pytest.raises(ValidationError):
        FuzzingInput(target_repo="https://github.com/foo/bar", target_subdir="a" * 513)


@pytest.mark.asyncio
async def test_adversarial_path_traversal_scenarios(tmp_path: Path):
    traversal_payloads = [
        "../",
        "../../",
        "../../etc/passwd",
        "/etc",
        "/tmp",
        "sub/../../..",
        "sub/../../../etc",
        "./../../secret",
    ]
    for bad_subdir in traversal_payloads:
        payload = SetupTargetInput(
            target_repo="https://github.com/foo/bar",
            target_subdir=bad_subdir,
        )
        with pytest.raises(ApplicationError) as exc:
            await setup_target(payload)
        assert exc.value.type == "InvalidSubdirectory", f"Failed to block traversal: {bad_subdir}"


def test_adversarial_library_ranking_complex(tmp_path: Path):
    # Setup complex directory with nested candidates
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir(parents=True)
    build_dir = tmp_path / "build" / "sub"
    build_dir.mkdir(parents=True)
    test_dir = tmp_path / "tests" / "bin"
    test_dir.mkdir(parents=True)
    bench_dir = tmp_path / "benchmarks"
    bench_dir.mkdir(parents=True)
    cmake_dir = tmp_path / "CMakeFiles" / "foo.dir"
    cmake_dir.mkdir(parents=True)

    (lib_dir / "libtarget.a").write_bytes(b"A" * 1000)
    (lib_dir / "libtarget.so.1.2").write_bytes(b"B" * 1000)
    (build_dir / "libtarget_core.so").write_bytes(b"C" * 2000)
    (build_dir / "libunrelated.a").write_bytes(b"D" * 500)
    (test_dir / "libtarget_test.a").write_bytes(b"E" * 9000)
    (bench_dir / "libtarget_bench.a").write_bytes(b"F" * 9000)
    (cmake_dir / "libtarget.a").write_bytes(b"G" * 9000)

    # 1. Target name "target"
    libs, rpaths = _rank_and_select_libraries(tmp_path, target_name="target")
    assert str(lib_dir / "libtarget.a") == libs[0]
    assert str(build_dir / "libtarget_core.so") in libs
    assert str(lib_dir / "libtarget.so.1.2") in libs
    assert str(test_dir / "libtarget_test.a") not in libs
    assert str(bench_dir / "libtarget_bench.a") not in libs
    assert str(cmake_dir / "libtarget.a") not in libs

    # Check RPATH set
    assert lib_dir.resolve() in rpaths
    assert build_dir.resolve() in rpaths

    # 2. Target name with .git prefix/suffix
    libs2, _ = _rank_and_select_libraries(tmp_path, target_name="libtarget.git")
    assert str(lib_dir / "libtarget.a") in libs2[:2]


def test_adversarial_bazel_artifact_extraction(tmp_path: Path):
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    bazel_bin = workdir / "bazel-bin"
    bazel_bin.mkdir()

    sub1 = bazel_bin / "pkg1"
    sub1.mkdir()
    (sub1 / "libfoo.a").write_bytes(b"FOO_A")
    (sub1 / "libfoo.so.1").write_bytes(b"FOO_SO_1")

    sub2 = bazel_bin / "pkg2"
    sub2.mkdir()
    (sub2 / "libbar.so").write_bytes(b"BAR_SO")

    _extract_bazel_artifacts(workdir)

    harvested = workdir / "lib"
    assert (harvested / "libfoo.a").read_bytes() == b"FOO_A"
    assert (harvested / "libfoo.so.1").read_bytes() == b"FOO_SO_1"
    assert (harvested / "libbar.so").read_bytes() == b"BAR_SO"


@pytest.mark.asyncio
async def test_adversarial_clone_fallback_on_shallow_rejection(tmp_path: Path):
    # Simulate shallow clone failing, followed by full clone success
    call_history = []

    async def fake_subprocess_exec(*args, **kwargs):
        call_history.append(list(args))
        mock_proc = AsyncMock()
        # If it was shallow clone, fail it
        if "--depth" in args:
            mock_proc.returncode = 128
            mock_proc.communicate.return_value = (b"", b"fatal: dumb http transport does not support shallow capabilities")
        else:
            mock_proc.returncode = 0
            mock_proc.communicate.return_value = (b"sha_full_commit\n", b"")
        return mock_proc

    with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess_exec):
        sha = await _clone_repo(
            repo_url="https://github.com/old/repo",
            branch=None,
            workdir=tmp_path / "checkout",
            clone_depth=1,
        )
        assert len(call_history) >= 2
        # First call should be shallow
        assert "--depth" in call_history[0]
        # Second call should be full
        assert "--depth" not in call_history[1]
        assert "sha_full_commit" in sha
