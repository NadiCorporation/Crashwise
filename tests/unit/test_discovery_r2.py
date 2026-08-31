# SPDX-License-Identifier: MIT
"""Unit tests for Milestone M2 discovery engine (Bazel, Meson) and artifact extraction."""
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from crashwise.core.discovery import discover_project
from crashwise.orchestration.activities.setup_target import (
    _build_target,
)


def test_detect_bazel_workspace_variants(tmp_path: Path) -> None:
    """Verify discovery engine recognizes all standard Bazel file variants."""
    variants = [
        "BUILD.bazel",
        "BUILD",
        "WORKSPACE.bazel",
        "WORKSPACE",
        "MODULE.bazel",
    ]

    for variant in variants:
        test_dir = tmp_path / f"bazel_test_{variant}"
        test_dir.mkdir(parents=True, exist_ok=True)
        (test_dir / variant).write_text("# Bazel build file")
        (test_dir / "main.c").write_text("int main() { return 0; }")

        profile = discover_project(test_dir)
        assert profile is not None, f"Failed to discover {variant}"
        assert profile.build_system == "bazel", f"Expected bazel for {variant}, got {profile.build_system}"


def test_detect_meson_build(tmp_path: Path) -> None:
    """Verify discovery engine recognizes Meson projects with nofallback."""
    (tmp_path / "meson.build").write_text("project('tutorial', 'c')")
    (tmp_path / "main.c").write_text("int main() { return 0; }")

    profile = discover_project(tmp_path)
    assert profile is not None
    assert profile.build_system == "meson"
    assert "--wrap-mode=nofallback" in profile.build_command


@pytest.mark.asyncio
async def test_bazel_build_command_and_bin_extraction(tmp_path: Path) -> None:
    """Verify _build_target synthesizes instrumented bazel flags and harvests artifacts."""
    (tmp_path / "BUILD.bazel").write_text("# Bazel project")
    (tmp_path / "main.c").write_text("int main() { return 0; }")

    # Create mock bazel-bin directory with built static and shared libraries
    bazel_bin = tmp_path / "bazel-bin"
    bazel_bin.mkdir(parents=True, exist_ok=True)
    mock_lib_a = bazel_bin / "libfoo.a"
    mock_lib_a.write_bytes(b"ARCHIVE-FOO")
    mock_lib_so = bazel_bin / "libfoo.so"
    mock_lib_so.write_bytes(b"ELF-FOO-SO")

    captured_cmds: list[str] = []

    async def fake_create_subprocess_shell(cmd: str, **kwargs: object) -> AsyncMock:
        captured_cmds.append(cmd)
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"", b"")
        return mock_proc

    with patch("asyncio.create_subprocess_shell", side_effect=fake_create_subprocess_shell):
        await _build_target(tmp_path, sanitizers="address,undefined")

    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]
    assert "bazel build" in cmd
    assert "--action_env=CC=clang" in cmd
    assert "--action_env=CXX=clang++" in cmd
    assert "--copt=-fsanitize=address,undefined" in cmd
    assert "--linkopt=-fsanitize=address,undefined" in cmd
    assert "--copt=-fprofile-instr-generate" in cmd

    # Verify artifacts were harvested into tmp_path / "lib"
    lib_dir = tmp_path / "lib"
    assert (lib_dir / "libfoo.a").exists()
    assert (lib_dir / "libfoo.a").read_bytes() == b"ARCHIVE-FOO"
    assert (lib_dir / "libfoo.so").exists()
    assert (lib_dir / "libfoo.so").read_bytes() == b"ELF-FOO-SO"


@pytest.mark.asyncio
async def test_meson_build_command_reconfigure(tmp_path: Path) -> None:
    """Verify _build_target adds --reconfigure if meson build dir exists."""
    (tmp_path / "meson.build").write_text("project('tutorial', 'c')")
    build_dir = tmp_path / "build"
    build_dir.mkdir(parents=True, exist_ok=True)

    captured_cmds: list[str] = []

    async def fake_create_subprocess_shell(cmd: str, **kwargs: object) -> AsyncMock:
        captured_cmds.append(cmd)
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"", b"")
        return mock_proc

    with patch("asyncio.create_subprocess_shell", side_effect=fake_create_subprocess_shell):
        await _build_target(tmp_path, sanitizers="address")

    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]
    assert "meson setup build --reconfigure --wrap-mode=nofallback" in cmd
    assert "meson compile -C build" in cmd
