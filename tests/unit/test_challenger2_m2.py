# SPDX-License-Identifier: MIT
"""Adversarial empirical challenge tests for Milestone M2:
1. Bazel and Meson build detection and command generation (flag injection and bazel-bin/ artifact extraction).
2. Multi-library CMake ranking and .so RPATH linker flag generation (atomic -Wl,-rpath,<dir> argument).
"""
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from crashwise.agents.harness_synth.build_resolver import BuildPaths
from crashwise.agents.harness_synth.nodes import validate_harness
from crashwise.agents.harness_synth.state import CompileResult, HarnessState
from crashwise.cli import app
from crashwise.core.discovery import discover_project
from crashwise.orchestration.activities.setup_target import (
    _build_target,
    _compile_harness,
    _extract_bazel_artifacts,
    _rank_and_select_libraries,
)

runner = CliRunner()


# ==============================================================================
# SECTION 1: Bazel & Meson Discovery, Command Gen, Flag Injection & Extraction
# ==============================================================================

@pytest.mark.parametrize("bazel_file", [
    "BUILD.bazel",
    "BUILD",
    "WORKSPACE.bazel",
    "WORKSPACE",
    "MODULE.bazel",
])
def test_empirical_bazel_variant_discovery(tmp_path: Path, bazel_file: str) -> None:
    """Empirically test that every Bazel workspace/build file variant is detected."""
    project_dir = tmp_path / f"proj_{bazel_file.replace('.', '_')}"
    project_dir.mkdir(parents=True)
    (project_dir / bazel_file).write_text("# Bazel root marker")
    (project_dir / "lib.c").write_text("int f() { return 42; }")

    profile = discover_project(project_dir)
    assert profile is not None
    assert profile.build_system == "bazel"
    assert "bazel build" in profile.build_command
    assert "//..." in profile.build_command


def test_empirical_bazel_subdirectory_monorepo(tmp_path: Path) -> None:
    """Empirically test discovery inside a subpackage of a Bazel monorepo."""
    root_dir = tmp_path / "monorepo"
    root_dir.mkdir()
    (root_dir / "WORKSPACE").write_text('workspace(name = "mono")')

    sub_dir = root_dir / "libs" / "compression"
    sub_dir.mkdir(parents=True)
    (sub_dir / "BUILD.bazel").write_text('cc_library(name = "compression", srcs = ["compress.c"])')
    (sub_dir / "compress.c").write_text("void compress() {}")

    # Scoped discovery in subdirectory
    sub_profile = discover_project(sub_dir)
    assert sub_profile is not None
    assert sub_profile.build_system == "bazel"


@pytest.mark.asyncio
@pytest.mark.parametrize("sanitizers,expected_san", [
    ("address,undefined", "address,undefined"),
    ("address", "address"),
    ("memory", "memory"),
    ("", "address,undefined"),  # Fallback default when empty
])
async def test_empirical_bazel_flag_injection_matrix(
    tmp_path: Path, sanitizers: str, expected_san: str
) -> None:
    """Empirically verify all required compiler/linker flags are injected for Bazel builds."""
    (tmp_path / "BUILD.bazel").write_text("# Bazel build")
    (tmp_path / "main.c").write_text("int main() { return 0; }")

    captured_cmds: list[str] = []
    captured_envs: list[dict[str, str]] = []

    async def fake_subprocess_shell(cmd: str, env: dict[str, str] | None = None, **kwargs: object) -> AsyncMock:
        captured_cmds.append(cmd)
        if env:
            captured_envs.append(env)
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"", b"")
        return mock_proc

    with patch("asyncio.create_subprocess_shell", side_effect=fake_subprocess_shell):
        await _build_target(tmp_path, sanitizers=sanitizers)

    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]

    # Verify CC / CXX actions
    assert "--action_env=CC=clang" in cmd
    assert "--action_env=CXX=clang++" in cmd

    # Verify sanitizers in both copt and linkopt
    assert f"--copt=-fsanitize={expected_san}" in cmd
    assert f"--linkopt=-fsanitize={expected_san}" in cmd

    # Verify fuzzer-no-link coverage
    assert "--copt=-fsanitize=fuzzer-no-link" in cmd

    # Verify llvm source-based coverage flags
    assert "--copt=-fprofile-instr-generate" in cmd
    assert "--copt=-fcoverage-mapping" in cmd
    assert "--linkopt=-fprofile-instr-generate" in cmd

    # Verify optimization and debug flags
    assert "--copt=-g" in cmd
    assert "--copt=-O1" in cmd
    assert "//..." in cmd


@pytest.mark.asyncio
async def test_empirical_bazel_artifact_extraction_deep_symlinks(tmp_path: Path) -> None:
    """Empirically test bazel-bin extraction with symlinks, nested dirs, versioned .so, and duplicates."""
    workdir = tmp_path / "workspace"
    workdir.mkdir()

    # External bazel-bin output cache
    external_cache = tmp_path / "bazel_execroot" / "k8-fastbuild" / "bin"
    external_cache.mkdir(parents=True)

    # Deep subdirectories in bazel-bin
    deep_static_dir = external_cache / "src" / "core"
    deep_static_dir.mkdir(parents=True)
    (deep_static_dir / "libcore.a").write_bytes(b"STATIC-CORE-BYTES")

    deep_shared_dir = external_cache / "src" / "crypto"
    deep_shared_dir.mkdir(parents=True)
    (deep_shared_dir / "libcrypto.so.3.0.1").write_bytes(b"SHARED-CRYPTO-VERSIONED")
    (deep_shared_dir / "libcrypto.so").write_bytes(b"SHARED-CRYPTO-LINK")

    # Symlink bazel-bin in workspace pointing to external cache
    (workdir / "bazel-bin").symlink_to(external_cache)

    # Also secondary bazel-bin-dbg
    secondary_bin = workdir / "bazel-bin-dbg"
    secondary_bin.mkdir()
    (secondary_bin / "libdebug.a").write_bytes(b"STATIC-DEBUG-BYTES")
    # Duplicate libcore.a in secondary - should be handled gracefully without overwriting/error
    (secondary_bin / "libcore.a").write_bytes(b"STATIC-CORE-DUPE")

    # Execute extraction
    _extract_bazel_artifacts(workdir)

    lib_dir = workdir / "lib"
    assert lib_dir.exists()
    assert (lib_dir / "libcore.a").exists()
    assert (lib_dir / "libcore.a").read_bytes() == b"STATIC-CORE-BYTES"
    assert (lib_dir / "libcrypto.so.3.0.1").exists()
    assert (lib_dir / "libcrypto.so.3.0.1").read_bytes() == b"SHARED-CRYPTO-VERSIONED"
    assert (lib_dir / "libcrypto.so").exists()
    assert (lib_dir / "libcrypto.so").read_bytes() == b"SHARED-CRYPTO-LINK"
    assert (lib_dir / "libdebug.a").exists()
    assert (lib_dir / "libdebug.a").read_bytes() == b"STATIC-DEBUG-BYTES"


@pytest.mark.asyncio
async def test_empirical_bazel_artifact_extraction_dangling_symlink(tmp_path: Path) -> None:
    """Verify bazel extraction handles broken / dangling symlinks safely without crash."""
    workdir = tmp_path / "workspace_broken"
    workdir.mkdir()

    non_existent = tmp_path / "does_not_exist"
    (workdir / "bazel-bin").symlink_to(non_existent)

    # Should run and not raise exception
    _extract_bazel_artifacts(workdir)
    assert (workdir / "lib").exists()


@pytest.mark.asyncio
async def test_empirical_meson_build_setup_and_reconfigure(tmp_path: Path) -> None:
    """Empirically test Meson initial setup vs --reconfigure when build directory exists."""
    (tmp_path / "meson.build").write_text("project('demo', 'c')")
    (tmp_path / "demo.c").write_text("int main() { return 0; }")

    captured_cmds: list[str] = []

    async def fake_subprocess_shell(cmd: str, **kwargs: object) -> AsyncMock:
        captured_cmds.append(cmd)
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"", b"")
        return mock_proc

    with patch("asyncio.create_subprocess_shell", side_effect=fake_subprocess_shell):
        # 1. Fresh build (build/ directory does NOT exist yet)
        await _build_target(tmp_path, sanitizers="address,undefined")

    assert len(captured_cmds) == 1
    assert captured_cmds[0] == "meson setup build --wrap-mode=nofallback && meson compile -C build"

    # 2. Existing build (build/ directory exists)
    (tmp_path / "build").mkdir(exist_ok=True)
    captured_cmds.clear()

    with patch("asyncio.create_subprocess_shell", side_effect=fake_subprocess_shell):
        await _build_target(tmp_path, sanitizers="address,undefined")

    assert len(captured_cmds) == 1
    assert captured_cmds[0] == "meson setup build --reconfigure --wrap-mode=nofallback && meson compile -C build"


# ==============================================================================
# SECTION 2: Multi-library Ranking & RPATH Atomic Linker Flags
# ==============================================================================

def test_empirical_multi_library_ranking_complex_repo(tmp_path: Path) -> None:
    """Empirically test ranking across realistic multi-component build directory with shared & static libs."""
    build_dir = tmp_path / "build"
    build_dir.mkdir()

    # Create various libraries:
    # 1. Main target library matching target_name="openssl"
    (build_dir / "libssl.so.3").write_bytes(b"x" * 2_000_000)
    (build_dir / "libcrypto.a").write_bytes(b"x" * 5_000_000)
    (build_dir / "libopenssl.a").write_bytes(b"x" * 3_000_000)

    # 2. Auxiliary library
    (build_dir / "libz.a").write_bytes(b"x" * 100_000)

    # 3. Test libraries (must be filtered out)
    test_dir = build_dir / "test"
    test_dir.mkdir()
    (test_dir / "libssl_test.a").write_bytes(b"x" * 10_000_000)

    # 4. Example library (must be filtered out)
    example_dir = build_dir / "examples"
    example_dir.mkdir()
    (example_dir / "libdemo.a").write_bytes(b"x" * 10_000_000)

    # 5. CMake internal files (must be filtered out)
    cmake_dir = build_dir / "CMakeFiles" / "3.28"
    cmake_dir.mkdir(parents=True)
    (cmake_dir / "libdummy.a").write_bytes(b"x" * 10_000_000)

    ranked_libs, rpath_dirs = _rank_and_select_libraries(tmp_path, target_name="openssl")

    # Assert test and example and cmake files are filtered out
    assert str(test_dir / "libssl_test.a") not in ranked_libs
    assert str(example_dir / "libdemo.a") not in ranked_libs
    assert str(cmake_dir / "libdummy.a") not in ranked_libs

    # Assert libopenssl.a gets top rank (+100 exact match)
    assert ranked_libs[0] == str(build_dir / "libopenssl.a")

    # Assert RPATH directories contains build_dir because of libssl.so.3
    assert build_dir.resolve() in rpath_dirs


def test_empirical_multi_library_ranking_stem_clean_variations(tmp_path: Path) -> None:
    """Test target_name clean variations (e.g. target_name='libz.git' vs 'z')."""
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    (lib_dir / "libz.a").write_bytes(b"x" * 1000)
    (lib_dir / "libother.a").write_bytes(b"x" * 1000)

    # Target name with .git and lib prefix
    ranked_1, _ = _rank_and_select_libraries(tmp_path, target_name="libz.git")
    assert ranked_1[0] == str(lib_dir / "libz.a")

    # Target name without lib prefix
    ranked_2, _ = _rank_and_select_libraries(tmp_path, target_name="z")
    assert ranked_2[0] == str(lib_dir / "libz.a")


@pytest.mark.asyncio
async def test_empirical_compile_harness_atomic_rpath_token(tmp_path: Path) -> None:
    """Empirically test that _compile_harness emits -Wl,-rpath,<dir> as a single string argument."""
    harness_src = tmp_path / "fuzz_harness.cpp"
    harness_src.write_text("""
#include <cstdint>
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return 0;
}
""")

    lib_dir1 = tmp_path / "build" / "lib"
    lib_dir1.mkdir(parents=True)
    (lib_dir1 / "libtarget.so").write_bytes(b"ELF_SO_1")

    lib_dir2 = tmp_path / "plugins"
    lib_dir2.mkdir(parents=True)
    (lib_dir2 / "libengine.so.1").write_bytes(b"ELF_SO_2")

    captured_exec_args: list[list[str]] = []

    async def fake_subprocess_exec(*args: str, **kwargs: object) -> AsyncMock:
        captured_exec_args.append(list(args))
        (tmp_path / "harness_binary").write_bytes(b"ELF_OUT")
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
    assert len(captured_exec_args) == 1
    cmd = captured_exec_args[0]

    # Check atomic RPATH tokens
    expected_rpath1 = f"-Wl,-rpath,{lib_dir1.resolve()}"
    expected_rpath2 = f"-Wl,-rpath,{lib_dir2.resolve()}"

    assert expected_rpath1 in cmd
    assert expected_rpath2 in cmd

    # Assert NO element in cmd is bare '-Wl,-rpath'
    assert "-Wl,-rpath" not in cmd
    for idx, arg in enumerate(cmd):
        if arg == "-Wl,-rpath":
            pytest.fail(f"Found separated -Wl,-rpath at argument index {idx}!")


@pytest.mark.asyncio
async def test_empirical_nodes_validate_harness_atomic_rpath_token(tmp_path: Path) -> None:
    """Empirically test that validate_harness in nodes.py emits atomic -Wl,-rpath,<dir>."""
    target_root = tmp_path / "project"
    target_root.mkdir()
    (target_root / "CMakeLists.txt").write_text("project(demo)")

    src_file = target_root / "src" / "demo.c"
    src_file.parent.mkdir()
    src_file.write_text("int demo_api(const char* b) { return 0; }")

    so_dir = target_root / "build" / "lib"
    so_dir.mkdir(parents=True)
    (so_dir / "libdemo.so").write_bytes(b"ELF_SO")

    harness_file = tmp_path / "harness.cpp"
    harness_code = """
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }
"""
    harness_file.write_text(harness_code)

    state = HarnessState(
        source_path=src_file,
        source_code=src_file.read_text(),
        harness_path=harness_file,
        workdir=tmp_path / "harness_dir",
        harness_code=harness_code,
        max_retries=1,
    )

    passed_extra_args: list[str] = []

    async def mock_compile_harness(**kwargs: object) -> CompileResult:
        passed_extra_args.extend(kwargs.get("extra_args", []))  # type: ignore[arg-type]
        return CompileResult(
            success=True,
            returncode=0,
            stdout="",
            stderr="",
            binary_path=tmp_path / "harness_dir" / "harness_bin",
        )

    with patch("crashwise.agents.harness_synth.nodes.compile_harness", side_effect=mock_compile_harness), \
         patch("crashwise.agents.harness_synth.nodes.sanity_check", return_value=AsyncMock(passed=True, edges_hit=10, crashed_immediately=False)):
        res = await validate_harness(state)
        assert res.succeeded is True

    expected_rpath = f"-Wl,-rpath,{so_dir.resolve()}"
    assert expected_rpath in passed_extra_args
    assert "-Wl,-rpath" not in passed_extra_args


def test_empirical_build_paths_to_compile_args(tmp_path: Path) -> None:
    """Empirically test BuildPaths.to_compile_args format for atomic .so RPATH and -L."""
    paths = BuildPaths(
        include_dirs=[tmp_path / "inc1"],
        lib_files=[tmp_path / "lib1" / "libcore.a"],
        lib_dirs=[tmp_path / "lib1", tmp_path / "plugins"],
    )

    compile_args = paths.to_compile_args()
    assert f"-I{tmp_path / 'inc1'}" in compile_args
    assert str(tmp_path / "lib1" / "libcore.a") in compile_args
    assert f"-L{tmp_path / 'lib1'}" in compile_args
    assert f"-Wl,-rpath,{(tmp_path / 'lib1').resolve()}" in compile_args
    assert f"-L{tmp_path / 'plugins'}" in compile_args
    assert f"-Wl,-rpath,{(tmp_path / 'plugins').resolve()}" in compile_args
    assert "-Wl,-rpath" not in compile_args


def test_cli_run_help_contains_m2_options():
    """Empirically test that CLI help contains all M2 flags."""
    res = runner.invoke(app, ["run", "--help"])
    assert res.exit_code == 0
    assert "--name" in res.output
    assert "--subdir" in res.output
    assert "--clone-depth" in res.output


# ==============================================================================
# SECTION 3: Real Compiler / Linker & ELF RPATH Verification
# ==============================================================================

def test_empirical_real_clang_compilation_and_elf_rpath(tmp_path: Path) -> None:
    """Live compiler test: compile a real C shared library and harness, verifying ELF RPATH and execution."""
    if not shutil.which("clang") or not shutil.which("readelf"):
        pytest.skip("clang or readelf not available in test environment")

    # 1. Compile a real shared library
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    lib_c = lib_dir / "target_lib.c"
    lib_c.write_text("""
#include <stdio.h>
int target_multiply(int a, int b) {
    return a * b;
}
""")
    so_path = lib_dir / "libtarget.so"
    res = subprocess.run(
        ["clang", "-shared", "-fPIC", "-o", str(so_path), str(lib_c)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Failed to build mock .so: {res.stderr}"
    assert so_path.exists()

    # 2. Compile harness using atomic -Wl,-rpath,<dir>
    harness_c = tmp_path / "harness.c"
    harness_c.write_text("""
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

extern int target_multiply(int a, int b);

int main() {
    int res = target_multiply(6, 7);
    printf("Result: %d\\n", res);
    return res == 42 ? 0 : 1;
}
""")
    bin_path = tmp_path / "test_bin"
    rpath_flag = f"-Wl,-rpath,{lib_dir.resolve()}"

    cmd = [
        "clang",
        "-o", str(bin_path),
        str(harness_c),
        f"-L{lib_dir}",
        "-ltarget",
        rpath_flag,
    ]
    res2 = subprocess.run(cmd, capture_output=True, text=True)
    assert res2.returncode == 0, f"Failed to link with atomic RPATH: {res2.stderr}"
    assert bin_path.exists()

    # 3. Verify readelf shows RPATH or RUNPATH containing lib_dir
    res3 = subprocess.run(["readelf", "-d", str(bin_path)], capture_output=True, text=True)
    assert res3.returncode == 0
    assert ("RPATH" in res3.stdout or "RUNPATH" in res3.stdout)
    assert str(lib_dir.resolve()) in res3.stdout

    # 4. Verify binary executes and dynamically loads libtarget.so without LD_LIBRARY_PATH
    env = os.environ.copy()
    env.pop("LD_LIBRARY_PATH", None)
    res4 = subprocess.run([str(bin_path)], capture_output=True, text=True, env=env)
    assert res4.returncode == 0
    assert "Result: 42" in res4.stdout


# ==============================================================================
# SECTION 4: Edge Cases & Multi-Component Monorepo Scenarios
# ==============================================================================

@pytest.mark.asyncio
async def test_empirical_monorepo_subdir_bazel_inside_cmake_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Empirically test monorepo with root CMakeLists.txt and subdir BUILD.bazel."""
    from crashwise.core.config import get_settings
    from crashwise.core.models import SetupTargetInput
    from crashwise.orchestration.activities.setup_target import setup_target

    monkeypatch.setenv("CRASHWISE_WORKDIR", str(tmp_path))
    get_settings.cache_clear()

    # Monorepo layout
    repo_dir = tmp_path / "anonymous" / "target"
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "CMakeLists.txt").write_text("project(root_cmake)")

    bazel_sub = repo_dir / "modules" / "bazel_sub"
    bazel_sub.mkdir(parents=True, exist_ok=True)
    (bazel_sub / "BUILD.bazel").write_text('cc_library(name = "sub", srcs = ["sub.c"])')
    (bazel_sub / "sub.c").write_text("int sub_func() { return 1; }")

    built_systems: list[str] = []

    async def fake_clone(repo_url: str, branch: str | None, workdir: Path, clone_depth: int = 1) -> str:
        # Repopulate
        sub = workdir / "modules" / "bazel_sub"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "BUILD.bazel").write_text('cc_library(name = "sub", srcs = ["sub.c"])')
        (sub / "sub.c").write_text("int sub_func() { return 1; }")
        return "sha998877"

    async def fake_subprocess_shell(cmd: str, **kwargs: object) -> AsyncMock:
        if "bazel build" in cmd:
            built_systems.append("bazel")
        elif "cmake" in cmd:
            built_systems.append("cmake")
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"", b"")
        return mock_proc

    import sys
    st_mod = sys.modules["crashwise.orchestration.activities.setup_target"]
    monkeypatch.setattr(st_mod, "_clone_repo", fake_clone)

    with patch("asyncio.create_subprocess_shell", side_effect=fake_subprocess_shell):
        payload = SetupTargetInput(
            target_repo="https://github.com/monorepo/test",
            target_name="sub",
            target_subdir="modules/bazel_sub",
            synthesize_harness=False,
        )
        res = await setup_target(payload)

    assert res.workdir == (repo_dir / "modules" / "bazel_sub").resolve()
    assert built_systems == ["bazel"]


def test_empirical_multi_library_ranking_size_tiebreaker(tmp_path: Path) -> None:
    """Verify that among libraries with equal name match score, the larger file is preferred."""
    lib_dir = tmp_path / "build" / "lib"
    lib_dir.mkdir(parents=True)

    # Both libraries have substring match for "core"
    small_lib = lib_dir / "libcore_small.a"
    small_lib.write_bytes(b"x" * 1024)  # 1 KB

    large_lib = lib_dir / "libcore_large.a"
    large_lib.write_bytes(b"x" * 1024 * 1024 * 5)  # 5 MB

    ranked, _ = _rank_and_select_libraries(tmp_path, target_name="core")
    assert ranked[0] == str(large_lib)
    assert ranked[1] == str(small_lib)
