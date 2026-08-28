# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Sentinel R1 upgrades (Alpine Linux & Git checks)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from crashwise.core.sentinel import (
    _CHECK_PACKAGES_BY_DISTRO,
    _INSTALL_COMMANDS,
    CheckResult,
    CheckStatus,
    DistroDetector,
    DistroInfo,
    _install_hint,
    check_build_git,
    check_runtime_docker_compose,
    generate_setup_script,
    get_missing_packages,
    run_all_checks,
)


def test_distro_info_alpine_properties() -> None:
    """Verify is_alpine property and discrimination from other families."""
    info = DistroInfo(family="alpine", id_="alpine", pretty_name="Alpine Linux v3.19")
    assert info.is_alpine is True
    assert info.is_arch is False
    assert info.is_debian is False
    assert info.is_fedora is False
    assert info.family == "alpine"


def test_distro_detector_normalise_alpine() -> None:
    """Verify Alpine normalization from os-release fields."""
    assert DistroDetector._normalise("alpine", "") == "alpine"
    assert DistroDetector._normalise("alpine", "alpine") == "alpine"
    assert DistroDetector._normalise("postmarketos", "alpine") == "alpine"
    assert DistroDetector._normalise("ALPINE", "") == "alpine"


def test_install_hint_alpine() -> None:
    """Verify apk command generation for Alpine."""
    with patch("crashwise.core.sentinel._is_root", return_value=True):
        hint = _install_hint("alpine", ["git", "cmake"])
        assert hint == "apk add --no-cache git cmake"

    with patch("crashwise.core.sentinel._is_root", return_value=False), patch(
        "crashwise.core.sentinel._which", return_value="/usr/bin/sudo"
    ):
        hint = _install_hint("alpine", ["git", "cmake"])
        assert hint == "sudo apk add --no-cache git cmake"


def test_check_build_git_success() -> None:
    """Verify check_build_git passes when git is present."""
    with patch(
        "crashwise.core.sentinel._run",
        return_value=(0, "git version 2.43.0\n", ""),
    ):
        res = check_build_git()
        assert res.status == CheckStatus.OK
        assert res.name == "build.git"
        assert "git version 2.43.0" in res.message


def test_check_build_git_failure() -> None:
    """Verify check_build_git fails with remediation when git is missing."""
    with patch("crashwise.core.sentinel._run", return_value=(127, "", "not found")), patch(
        "crashwise.core.sentinel._detect_distro", return_value="alpine"
    ), patch("crashwise.core.sentinel._is_root", return_value=True):
        res = check_build_git()
        assert res.status == CheckStatus.FAIL
        assert res.name == "build.git"
        assert "apk add --no-cache git" in res.remediation


def test_package_map_includes_git_on_all_distros() -> None:
    """Verify build.git is present in all package manager dictionaries."""
    for distro in ("debian", "arch", "fedora", "alpine"):
        assert distro in _CHECK_PACKAGES_BY_DISTRO
        assert "build.git" in _CHECK_PACKAGES_BY_DISTRO[distro]
        assert _CHECK_PACKAGES_BY_DISTRO[distro]["build.git"] == ["git"]


def test_alpine_package_map_complete() -> None:
    """Verify alpine package map has all required tools."""
    alpine_pkgs = _CHECK_PACKAGES_BY_DISTRO["alpine"]
    assert "runtime.docker" in alpine_pkgs
    assert "runtime.docker-compose" in alpine_pkgs
    assert "build.git" in alpine_pkgs
    assert "build.cmake" in alpine_pkgs
    assert "build.clang" in alpine_pkgs
    assert "build.gcc" in alpine_pkgs
    assert "build.llvm" in alpine_pkgs
    assert "build.afl++" in alpine_pkgs
    assert "musl-dev" in alpine_pkgs["build.gcc"]


def test_install_commands_alpine() -> None:
    """Verify alpine install and update commands."""
    assert "alpine" in _INSTALL_COMMANDS
    update_tmpl, install_tmpl = _INSTALL_COMMANDS["alpine"]
    assert update_tmpl == "{sudo}apk update"
    assert install_tmpl == "{sudo}apk add --no-cache {pkgs}"


def test_generate_setup_script_alpine() -> None:
    """Verify generate_setup_script generates apk commands for Alpine."""
    with patch("crashwise.core.sentinel._is_root", return_value=True):
        script = generate_setup_script(["git", "cmake", "clang"], distro="alpine")
        assert "# CrashWise System Provisioner (alpine)" in script
        assert "apk update" in script
        assert "apk add --no-cache git cmake clang" in script
        assert "sudo" not in script


def test_get_missing_packages_alpine() -> None:
    """Verify get_missing_packages resolves correct package names on Alpine."""
    report = type("MockReport", (), {})()
    report.checks = [
        CheckResult(name="build.git", status=CheckStatus.FAIL, message="missing"),
        CheckResult(name="build.gcc", status=CheckStatus.FAIL, message="missing"),
    ]
    pkgs = get_missing_packages(report, distro="alpine")
    assert "git" in pkgs
    assert "gcc" in pkgs
    assert "g++" in pkgs
    assert "musl-dev" in pkgs


def test_check_runtime_docker_compose_legacy_alpine() -> None:
    """Verify legacy compose v1 migration recommendation on Alpine."""
    with patch(
        "crashwise.core.sentinel._run",
        side_effect=[
            (1, "", "docker: 'compose' is not a docker command"),
            (0, "docker-compose version 1.29.2, build 5becea4c", ""),
        ],
    ), patch("crashwise.core.sentinel._detect_distro", return_value="alpine"), patch(
        "crashwise.core.sentinel._is_root", return_value=True
    ):
        res = check_runtime_docker_compose()
        assert res.status == CheckStatus.FAIL
        assert "apk add --no-cache docker-cli-compose" in res.remediation


@pytest.mark.asyncio
async def test_run_all_checks_includes_git() -> None:
    """Verify run_all_checks executes check_build_git."""
    with patch("crashwise.core.sentinel._run", return_value=(0, "ok", "")), patch(
        "crashwise.core.sentinel.httpx.AsyncClient"
    ):
        report = await run_all_checks()
        check_names = {c.name for c in report.checks}
        assert "build.git" in check_names
