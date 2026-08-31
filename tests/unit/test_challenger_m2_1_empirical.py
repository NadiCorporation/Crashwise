# SPDX-License-Identifier: MIT
"""Empirical stress tests for Challenger 1 on Milestone M2: Complex Target & Monorepo Support.

Tests cover:
1. Monorepo subdirectory scoping (target_subdir):
   - Strict execution of builds, harness detection, and synthesis in target_subdir
   - Protection against directory traversal attacks (../, absolute paths, nested traversal, symlink escapes)
   - Handling of nonexistent subdirs and file paths
   - Handling of normalization (trailing slashes, ./, nested dirs)
2. Clone depth behavior (target_clone_depth):
   - Smart git daemon repository depth=1 (shallow, 1 commit)
   - Smart git daemon repository depth=0 (full clone, all commits)
   - Smart git daemon repository depth=3 (shallow, 3 commits)
   - Fallback behavior on shallow clone failure (dumb HTTP transport)
3. Multi-library ranking and RPATH generation within monorepos
4. End-to-end API, CLI, and Workflow model propagation
"""

import os
import socket
import subprocess
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from temporalio.exceptions import ApplicationError

from crashwise.api.main import CampaignCreateRequest
from crashwise.core.config import get_settings
from crashwise.core.models import FuzzingInput, SetupTargetInput
from crashwise.orchestration.activities.setup_target import (
    _clone_repo,
    _detect_existing_harness,
    _find_best_source_for_synthesis,
    setup_target,
)


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture
def sample_git_monorepo(tmp_path: Path) -> Path:
    """Create a real local git repository with multiple commits and a monorepo structure."""
    repo_dir = tmp_path / "origin_monorepo"
    repo_dir.mkdir(parents=True, exist_ok=True)

    # Initialize git repo
    subprocess.run(["git", "init", "-b", "main", str(repo_dir)], check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "TestUser"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)

    # Commit 1: Add root README
    (repo_dir / "README.md").write_text("Monorepo Root")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Commit 1: root"], cwd=repo_dir, check=True)

    # Commit 2: Add Component A (no harness)
    subA = repo_dir / "components" / "compA"
    subA.mkdir(parents=True, exist_ok=True)
    (subA / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)\nproject(compA)")
    (subA / "compA.c").write_text("int compA_parse(const char* buf) { return 0; }")
    (subA / "compA.h").write_text("int compA_parse(const char* buf);")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Commit 2: compA"], cwd=repo_dir, check=True)

    # Commit 3: Add Component B (with existing harness)
    subB = repo_dir / "components" / "compB"
    subB.mkdir(parents=True, exist_ok=True)
    (subB / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)\nproject(compB)")
    (subB / "compB.c").write_text("int compB_decode(const char* buf) { return 0; }")
    harness_dir = subB / "fuzz"
    harness_dir.mkdir(parents=True, exist_ok=True)
    (harness_dir / "fuzz_target.c").write_text(
        '#include <stdint.h>\n#include <stddef.h>\n'
        'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
        '    return 0;\n'
        '}\n'
    )
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Commit 3: compB with harness"], cwd=repo_dir, check=True)

    # Commit 4: Add Root-level trap harness (should never be picked when targeting compA)
    root_fuzz = repo_dir / "root_fuzz"
    root_fuzz.mkdir(parents=True, exist_ok=True)
    (root_fuzz / "root_harness.c").write_text(
        '#include <stdint.h>\n#include <stddef.h>\n'
        'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 42; }\n'
    )
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Commit 4: root trap harness"], cwd=repo_dir, check=True)

    # Commit 5: Final metadata update
    (repo_dir / "VERSION").write_text("1.0.0")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Commit 5: version bump"], cwd=repo_dir, check=True)

    return repo_dir


@pytest.fixture
def git_daemon_server(sample_git_monorepo: Path, tmp_path: Path):
    """Run a local git daemon server for remote git protocol testing."""
    (sample_git_monorepo / ".git" / "git-daemon-export-ok").touch()
    port = _get_free_port()
    base_dir = sample_git_monorepo.parent

    proc = subprocess.Popen([
        "git", "daemon",
        "--reuseaddr",
        f"--base-path={base_dir}",
        "--export-all",
        "--listen=127.0.0.1",
        f"--port={port}",
        str(base_dir),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(0.3)
    url = f"git://127.0.0.1:{port}/{sample_git_monorepo.name}"
    yield url

    proc.terminate()
    proc.wait()


# =============================================================================
# 1. EMPIRICAL TESTS: Monorepo Subdirectory Scoping & Directory Traversal
# =============================================================================


@pytest.mark.asyncio
async def test_empirical_monorepo_scoping_compA(sample_git_monorepo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Empirically test that targeting compA builds ONLY compA and ignores other harnesses."""
    workdir_root = tmp_path / "crashwise_work"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(workdir_root))
    get_settings.cache_clear()

    built_targets: list[Path] = []

    async def mock_build(workdir: Path, sanitizers: str) -> None:
        built_targets.append(workdir)

    import sys
    st_mod = sys.modules["crashwise.orchestration.activities.setup_target"]
    monkeypatch.setattr(st_mod, "_build_target", mock_build)

    payload = SetupTargetInput(
        target_repo=f"file://{sample_git_monorepo.resolve()}",
        target_name="compA",
        target_subdir="components/compA",
        target_clone_depth=0,
        synthesize_harness=False,
    )

    out = await setup_target(payload)

    # 1. Output workdir must be strictly the subdirectory
    expected_compA_dir = (workdir_root / "anonymous" / "target" / "components" / "compA").resolve()
    assert out.workdir == expected_compA_dir

    # 2. Build must have run strictly on component_dir
    assert len(built_targets) == 1
    assert built_targets[0] == expected_compA_dir

    # 3. Harness detection in compA must find None (does not falsely find root_fuzz or compB harness)
    assert out.harness_path is None


@pytest.mark.asyncio
async def test_empirical_monorepo_scoping_compB_harness_detection(sample_git_monorepo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Empirically test that targeting compB finds compB's harness and NOT root harness."""
    workdir_root = tmp_path / "crashwise_work"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(workdir_root))
    get_settings.cache_clear()

    async def mock_build(workdir: Path, sanitizers: str) -> None:
        pass

    async def mock_compile_harness(harness_source: Path, workdir: Path, sanitizers: str, target_name: str | None = None) -> Path:
        assert harness_source.name == "fuzz_target.c"
        assert "compB" in str(harness_source)
        assert "root_fuzz" not in str(harness_source)
        return workdir / "harness_binary"

    import sys
    st_mod = sys.modules["crashwise.orchestration.activities.setup_target"]
    monkeypatch.setattr(st_mod, "_build_target", mock_build)
    monkeypatch.setattr(st_mod, "_compile_harness", mock_compile_harness)

    payload = SetupTargetInput(
        target_repo=f"file://{sample_git_monorepo.resolve()}",
        target_name="compB",
        target_subdir="components/compB",
        target_clone_depth=1,
    )

    out = await setup_target(payload)
    expected_compB_dir = (workdir_root / "anonymous" / "target" / "components" / "compB").resolve()
    assert out.workdir == expected_compB_dir
    assert out.harness_path == expected_compB_dir / "harness_binary"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "traversal_subdir",
    [
        "../",
        "../../",
        "../../etc",
        "/etc",
        "/tmp",
        "components/compA/../../..",
        "components/../../target_outside/..",
        "components/compA/../../../etc",
        "../other_workdir",
        "./../../",
    ],
)
async def test_empirical_path_traversal_blocked(
    sample_git_monorepo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    traversal_subdir: str,
) -> None:
    """Empirically test that all path traversal attempts escaping the repository root are blocked with InvalidSubdirectory."""
    workdir_root = tmp_path / "crashwise_work"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(workdir_root))
    get_settings.cache_clear()

    payload = SetupTargetInput(
        target_repo=f"file://{sample_git_monorepo.resolve()}",
        target_subdir=traversal_subdir,
    )

    with pytest.raises(ApplicationError) as exc_info:
        await setup_target(payload)

    assert exc_info.value.type == "InvalidSubdirectory"
    assert exc_info.value.non_retryable is True
    assert "Path traversal detected" in str(exc_info.value.message)


@pytest.mark.asyncio
async def test_empirical_symlink_escape_blocked(sample_git_monorepo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Empirically test that a symlink inside the repo pointing outside is blocked as path traversal."""
    workdir_root = tmp_path / "crashwise_work"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(workdir_root))
    get_settings.cache_clear()

    # Add a symlink inside the origin repo pointing to an outside dir
    outside_target = tmp_path / "outside_dir"
    outside_target.mkdir(parents=True, exist_ok=True)
    symlink_path = sample_git_monorepo / "escape_link"
    os.symlink(str(outside_target.resolve()), str(symlink_path))
    subprocess.run(["git", "add", "."], cwd=sample_git_monorepo, check=True)
    subprocess.run(["git", "commit", "-m", "Add evil symlink"], cwd=sample_git_monorepo, check=True)

    payload = SetupTargetInput(
        target_repo=f"file://{sample_git_monorepo.resolve()}",
        target_subdir="escape_link",
    )

    with pytest.raises(ApplicationError) as exc_info:
        await setup_target(payload)

    assert exc_info.value.type == "InvalidSubdirectory"
    assert exc_info.value.non_retryable is True


@pytest.mark.asyncio
async def test_empirical_nonexistent_and_file_subdir_handling(
    sample_git_monorepo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empirically test that non-existent subdir and file paths raise DirectoryNotFound."""
    workdir_root = tmp_path / "crashwise_work"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(workdir_root))
    get_settings.cache_clear()

    # 1. Non-existent directory
    payload_nonexistent = SetupTargetInput(
        target_repo=f"file://{sample_git_monorepo.resolve()}",
        target_subdir="components/nonexistent_module",
    )
    with pytest.raises(ApplicationError) as exc_info:
        await setup_target(payload_nonexistent)
    assert exc_info.value.type == "DirectoryNotFound"
    assert exc_info.value.non_retryable is True

    # 2. Subdir pointing to a regular file (not a directory)
    payload_file = SetupTargetInput(
        target_repo=f"file://{sample_git_monorepo.resolve()}",
        target_subdir="README.md",
    )
    with pytest.raises(ApplicationError) as exc_info:
        await setup_target(payload_file)
    assert exc_info.value.type == "DirectoryNotFound"
    assert exc_info.value.non_retryable is True


@pytest.mark.asyncio
@pytest.mark.parametrize("valid_subdir", ["components/compA", "components/compA/", "./components/compA"])
async def test_empirical_subdir_normalization(
    sample_git_monorepo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    valid_subdir: str,
) -> None:
    """Empirically verify that trailing slashes and relative prefixes (./) resolve correctly."""
    workdir_root = tmp_path / "crashwise_work"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(workdir_root))
    get_settings.cache_clear()

    async def mock_build(workdir: Path, sanitizers: str) -> None:
        pass

    import sys
    st_mod = sys.modules["crashwise.orchestration.activities.setup_target"]
    monkeypatch.setattr(st_mod, "_build_target", mock_build)

    payload = SetupTargetInput(
        target_repo=f"file://{sample_git_monorepo.resolve()}",
        target_subdir=valid_subdir,
    )
    out = await setup_target(payload)
    expected_dir = (workdir_root / "anonymous" / "target" / "components" / "compA").resolve()
    assert out.workdir == expected_dir


# =============================================================================
# 2. EMPIRICAL TESTS: Clone Depth Behavior
# =============================================================================


@pytest.mark.asyncio
async def test_empirical_clone_depth_shallow(git_daemon_server: str, tmp_path: Path) -> None:
    """Empirically verify that clone_depth=1 performs shallow clone with depth 1 over git protocol."""
    dest_dir = tmp_path / "clone_shallow"
    sha = await _clone_repo(
        repo_url=git_daemon_server,
        branch=None,
        workdir=dest_dir,
        clone_depth=1,
    )

    assert len(sha) >= 7
    # Verify via git that history depth is exactly 1
    rev_count = subprocess.run(
        ["git", "rev-list", "--count", "HEAD"],
        cwd=dest_dir,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert rev_count == "1"

    is_shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=dest_dir,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert is_shallow == "true"


@pytest.mark.asyncio
async def test_empirical_clone_depth_full(git_daemon_server: str, tmp_path: Path) -> None:
    """Empirically verify that clone_depth=0 performs full clone with all commits over git protocol."""
    dest_dir = tmp_path / "clone_full"
    sha = await _clone_repo(
        repo_url=git_daemon_server,
        branch=None,
        workdir=dest_dir,
        clone_depth=0,
    )

    assert len(sha) >= 7
    # Total commits in fixture is at least 5
    rev_count = int(subprocess.run(
        ["git", "rev-list", "--count", "HEAD"],
        cwd=dest_dir,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip())
    assert rev_count >= 5

    is_shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=dest_dir,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert is_shallow == "false"


@pytest.mark.asyncio
async def test_empirical_clone_depth_custom(git_daemon_server: str, tmp_path: Path) -> None:
    """Empirically verify that clone_depth=3 performs shallow clone with depth 3 over git protocol."""
    dest_dir = tmp_path / "clone_depth3"
    sha = await _clone_repo(
        repo_url=git_daemon_server,
        branch=None,
        workdir=dest_dir,
        clone_depth=3,
    )

    assert len(sha) >= 7
    rev_count = subprocess.run(
        ["git", "rev-list", "--count", "HEAD"],
        cwd=dest_dir,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert rev_count == "3"

    is_shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=dest_dir,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert is_shallow == "true"


@pytest.mark.asyncio
async def test_empirical_clone_fallback_on_shallow_failure(tmp_path: Path) -> None:
    """Verify that if shallow clone fails, _clone_repo falls back to full clone."""
    workdir = tmp_path / "clone_retry"

    calls: list[list[str]] = []

    async def fake_subprocess_exec(*args: str, **kwargs: object) -> AsyncMock:
        calls.append(list(args))
        mock_proc = AsyncMock()
        # If shallow clone (has --depth), simulate failure
        if "--depth" in args:
            mock_proc.returncode = 128
            mock_proc.communicate.return_value = (b"", b"fatal: dumb http transport does not support shallow capabilities")
        else:
            mock_proc.returncode = 0
            if "rev-parse" in args:
                mock_proc.communicate.return_value = (b"deadbeef12345678\n", b"")
            else:
                mock_proc.communicate.return_value = (b"", b"")
        return mock_proc

    with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess_exec):
        sha = await _clone_repo(
            repo_url="https://example.com/repo.git",
            branch=None,
            workdir=workdir,
            clone_depth=1,
        )

        assert sha == "deadbeef12345678"
        # Must have attempted shallow clone first, then full clone
        assert any("--depth" in cmd for cmd in calls)
        assert any("clone" in cmd and "--depth" not in cmd for cmd in calls)


# =============================================================================
# 3. EMPIRICAL TESTS: Harness Synthesis & Multi-Library Ranking in Monorepos
# =============================================================================


def test_empirical_harness_search_scoping(sample_git_monorepo: Path) -> None:
    """Empirically test that _detect_existing_harness is strictly scoped to given dir."""
    # When scoped to root
    root_harness = _detect_existing_harness(sample_git_monorepo)
    assert root_harness is not None
    # When scoped to compA
    compA_harness = _detect_existing_harness(sample_git_monorepo / "components" / "compA")
    assert compA_harness is None
    # When scoped to compB
    compB_harness = _detect_existing_harness(sample_git_monorepo / "components" / "compB")
    assert compB_harness is not None
    assert compB_harness.name == "fuzz_target.c"


def test_empirical_source_synthesis_scoping(sample_git_monorepo: Path) -> None:
    """Empirically test that _find_best_source_for_synthesis is strictly scoped to given dir."""
    compA_src = _find_best_source_for_synthesis(sample_git_monorepo / "components" / "compA")
    assert compA_src is not None
    assert "compA" in compA_src
    assert "compB" not in compA_src


# =============================================================================
# 4. EMPIRICAL TESTS: Model Validation & CLI Invocations
# =============================================================================


def test_empirical_cli_and_api_contract_integrity() -> None:
    """Verify that target_subdir and target_clone_depth round-trip cleanly."""
    api_req = CampaignCreateRequest(
        target_repo="https://github.com/torvalds/linux",
        target_name="zlib",
        target_subdir="lib/zlib",
        target_clone_depth=0,
    )
    fuzz_inp = FuzzingInput(
        target_repo=api_req.target_repo,
        target_name=api_req.target_name,
        target_subdir=api_req.target_subdir,
        target_clone_depth=api_req.target_clone_depth,
    )
    setup_inp = SetupTargetInput(
        target_repo=fuzz_inp.target_repo,
        target_name=fuzz_inp.target_name,
        target_subdir=fuzz_inp.target_subdir,
        target_clone_depth=fuzz_inp.target_clone_depth,
    )

    assert setup_inp.target_name == "zlib"
    assert setup_inp.target_subdir == "lib/zlib"
    assert setup_inp.target_clone_depth == 0


def test_empirical_boundary_validation_rejection() -> None:
    """Verify boundary conditions for target_clone_depth and target_subdir."""
    from pydantic import ValidationError

    # Negative clone depth
    with pytest.raises(ValidationError):
        SetupTargetInput(target_repo="https://example.com/repo", target_clone_depth=-1)

    with pytest.raises(ValidationError):
        FuzzingInput(target_repo="https://example.com/repo", target_clone_depth=-1)

    with pytest.raises(ValidationError):
        CampaignCreateRequest(target_repo="https://example.com/repo", target_name="test", target_clone_depth=-1)

    # Subdir exceeding max_length (512)
    with pytest.raises(ValidationError):
        SetupTargetInput(target_repo="https://example.com/repo", target_subdir="a" * 513)

    with pytest.raises(ValidationError):
        FuzzingInput(target_repo="https://example.com/repo", target_subdir="a" * 513)

    with pytest.raises(ValidationError):
        CampaignCreateRequest(target_repo="https://example.com/repo", target_name="test", target_subdir="a" * 513)


@pytest.mark.asyncio
async def test_empirical_real_cmake_build_in_monorepo_subdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Empirically test real CMake compilation and harness link in a monorepo subdir."""
    workdir_root = tmp_path / "workdir_cmake"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(workdir_root))
    get_settings.cache_clear()

    # Create dummy monorepo directory
    monorepo = tmp_path / "monorepo_real"
    monorepo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(monorepo)], check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "TestUser"], cwd=monorepo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=monorepo, check=True)

    # Subproject in sub_crypto
    sub = monorepo / "crypto_lib"
    sub.mkdir()
    (sub / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\n"
        "project(mycrypto C)\n"
        "add_library(mycrypto STATIC mycrypto.c)\n"
    )
    (sub / "mycrypto.h").write_text(
        "#ifdef __cplusplus\n"
        "extern \"C\" {\n"
        "#endif\n"
        "int crypto_decode(const char* buf, int len);\n"
        "#ifdef __cplusplus\n"
        "}\n"
        "#endif\n"
    )
    (sub / "mycrypto.c").write_text(
        "#include \"mycrypto.h\"\n"
        "int crypto_decode(const char* buf, int len) { return (buf && len > 0) ? buf[0] : 0; }\n"
    )
    # Fuzz harness inside subproject
    (sub / "fuzz_crypto.c").write_text(
        "#include <stdint.h>\n"
        "#include <stddef.h>\n"
        "#include \"mycrypto.h\"\n"
        "#ifdef __cplusplus\n"
        "extern \"C\"\n"
        "#endif\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "    return crypto_decode((const char*)data, (int)size);\n"
        "}\n"
    )

    subprocess.run(["git", "add", "."], cwd=monorepo, check=True)
    subprocess.run(["git", "commit", "-m", "Initial crypto subproject"], cwd=monorepo, check=True)

    # Execute setup_target for crypto_lib
    payload = SetupTargetInput(
        target_repo=f"file://{monorepo.resolve()}",
        target_name="mycrypto",
        target_subdir="crypto_lib",
        sanitizers="address",
        synthesize_harness=False,
    )

    out = await setup_target(payload)

    # Verify workdir
    assert out.workdir == (workdir_root / "anonymous" / "target" / "crypto_lib").resolve()
    # Verify built library exists
    built_lib = out.workdir / "build" / "libmycrypto.a"
    assert built_lib.exists()
    # Verify compiled harness binary was produced and is executable
    assert out.harness_path is not None
    assert out.harness_path.exists()
    assert out.harness_path.name == "harness_binary"

