# SPDX-License-Identifier: MIT
"""Unit tests for Milestone M2 target setup, monorepo scoping, clone depth, and multi-library ranking."""
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from temporalio.exceptions import ApplicationError

from crashwise.core.models import SetupTargetInput
from crashwise.orchestration.activities.setup_target import (
    _clone_repo,
    _compile_harness,
    _get_build_timeout,
    _rank_and_select_libraries,
    setup_target,
)


@pytest.mark.asyncio
async def test_clone_repo_shallow_vs_full(tmp_path: Path) -> None:
    """Verify _clone_repo sets --depth correctly based on clone_depth."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"sha123456789\n", b"")
        mock_exec.return_value = mock_proc

        # Shallow clone (clone_depth = 1)
        await _clone_repo(
            repo_url="https://github.com/google/re2",
            branch=None,
            workdir=tmp_path / "repo1",
            clone_depth=1,
        )
        assert mock_exec.call_count >= 1
        first_call_args = mock_exec.call_args_list[0][0]
        assert "--depth" in first_call_args
        assert "1" in first_call_args

        mock_exec.reset_mock()

        # Custom shallow clone (clone_depth = 5)
        await _clone_repo(
            repo_url="https://github.com/google/re2",
            branch="main",
            workdir=tmp_path / "repo2",
            clone_depth=5,
        )
        call_args_5 = mock_exec.call_args_list[0][0]
        assert "--depth" in call_args_5
        assert "5" in call_args_5
        assert "--branch" in call_args_5
        assert "main" in call_args_5

        mock_exec.reset_mock()

        # Full clone (clone_depth = 0)
        await _clone_repo(
            repo_url="https://github.com/google/re2",
            branch=None,
            workdir=tmp_path / "repo3",
            clone_depth=0,
        )
        call_args_0 = mock_exec.call_args_list[0][0]
        assert "--depth" not in call_args_0


@pytest.mark.asyncio
async def test_setup_target_monorepo_subdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify setup_target executes build and harness search inside target_subdir."""
    from crashwise.core.config import get_settings

    monkeypatch.setenv("CRASHWISE_WORKDIR", str(tmp_path))
    get_settings.cache_clear()

    # Create dummy monorepo
    repo_dir = tmp_path / "anonymous" / "target"
    sub_dir = repo_dir / "components" / "parser"
    sub_dir.mkdir(parents=True, exist_ok=True)
    (sub_dir / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)\nproject(parser)")
    (sub_dir / "parser.c").write_text("int parse_buf(const char* s) { return 0; }")

    built_dirs: list[Path] = []

    async def fake_clone(repo_url: str, branch: str | None, workdir: Path, clone_depth: int = 1) -> str:
        # Repopulate dir after setup_target cleans workdir
        sub = workdir / "components" / "parser"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)\nproject(parser)")
        (sub / "parser.c").write_text("int parse_buf(const char* s) { return 0; }")
        return "abcdef1234567"

    async def fake_build(workdir: Path, sanitizers: str) -> None:
        built_dirs.append(workdir)

    import sys
    st_mod = sys.modules["crashwise.orchestration.activities.setup_target"]
    monkeypatch.setattr(st_mod, "_clone_repo", fake_clone)
    monkeypatch.setattr(st_mod, "_build_target", fake_build)

    payload = SetupTargetInput(
        target_repo="https://github.com/example/monorepo",
        target_name="parser",
        target_subdir="components/parser",
        synthesize_harness=False,
    )

    out = await setup_target(payload)
    assert out.workdir == (repo_dir / "components" / "parser").resolve()
    assert out.commit_sha == "abcdef1234567"
    assert len(built_dirs) == 1
    assert built_dirs[0] == (repo_dir / "components" / "parser").resolve()


@pytest.mark.asyncio
async def test_setup_target_path_traversal_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify setup_target blocks path traversal in target_subdir."""
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(tmp_path))

    payload = SetupTargetInput(
        target_repo="https://github.com/example/repo",
        target_subdir="../../etc",
    )

    with pytest.raises(ApplicationError) as exc_info:
        await setup_target(payload)
    assert exc_info.value.type == "InvalidSubdirectory"


@pytest.mark.asyncio
async def test_setup_target_nonexistent_subdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify setup_target raises DirectoryNotFound if target_subdir is missing."""
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(tmp_path))

    async def fake_clone(repo_url: str, branch: str | None, workdir: Path, clone_depth: int = 1) -> str:
        return "112233445566"

    import sys
    st_mod = sys.modules["crashwise.orchestration.activities.setup_target"]
    monkeypatch.setattr(st_mod, "_clone_repo", fake_clone)

    payload = SetupTargetInput(
        target_repo="https://github.com/example/repo",
        target_subdir="missing_subdir",
    )

    with pytest.raises(ApplicationError) as exc_info:
        await setup_target(payload)
    assert exc_info.value.type == "DirectoryNotFound"


def test_build_timeout_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify CRASHWISE_BUILD_TIMEOUT environment variable is respected."""
    monkeypatch.setenv("CRASHWISE_BUILD_TIMEOUT", "180")
    from crashwise.core.config import get_settings
    get_settings.cache_clear()

    assert _get_build_timeout() == 180.0


def test_multi_library_ranking_with_target_name(tmp_path: Path) -> None:
    """Verify _rank_and_select_libraries scores and ranks target-matching libraries first."""
    lib_dir = tmp_path / "build" / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)

    other_lib = lib_dir / "libauxiliary.a"
    other_lib.write_bytes(b"x" * 500)

    target_lib = lib_dir / "libre2.a"
    target_lib.write_bytes(b"x" * 2000)

    shared_lib = lib_dir / "libre2.so"
    shared_lib.write_bytes(b"x" * 2000)

    test_lib = lib_dir / "libre2_test.a"
    test_lib.write_bytes(b"x" * 5000)

    # When target_name is 're2'
    ranked_libs, rpath_dirs = _rank_and_select_libraries(tmp_path, target_name="re2")

    # libre2.a and libre2.so should be top-ranked, test_lib skipped
    assert str(test_lib) not in ranked_libs
    assert len(ranked_libs) == 3
    assert str(target_lib) in ranked_libs[:2]
    assert str(shared_lib) in ranked_libs[:2]
    assert lib_dir.resolve() in rpath_dirs


@pytest.mark.asyncio
async def test_compile_harness_with_so_rpath(tmp_path: Path) -> None:
    """Verify _compile_harness injects -Wl,-rpath,<dir> atomically when .so is present."""
    harness_src = tmp_path / "harness.c"
    harness_src.write_text("int LLVMFuzzerTestOneInput(const char* d, unsigned long s) { return 0; }")

    build_dir = tmp_path / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    shared_lib = build_dir / "libtarget.so"
    shared_lib.write_bytes(b"ELF-fake-so")

    captured_cmds: list[list[str]] = []

    async def fake_subprocess_exec(*args: str, **kwargs: object) -> AsyncMock:
        captured_cmds.append(list(args))
        # Create output binary so it looks successful
        (tmp_path / "harness_binary").write_bytes(b"ELF-binary")
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"", b"")
        return mock_proc

    with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess_exec):
        res = await _compile_harness(
            harness_source=harness_src,
            workdir=tmp_path,
            sanitizers="address",
            target_name="target",
        )
        assert res is not None
        assert len(captured_cmds) == 1
        cmd = captured_cmds[0]
        # Verify atomic -Wl,-rpath flag
        expected_rpath = f"-Wl,-rpath,{build_dir.resolve()}"
        assert expected_rpath in cmd
        assert "-Wl,-rpath" not in cmd  # Must NOT be split into two args
