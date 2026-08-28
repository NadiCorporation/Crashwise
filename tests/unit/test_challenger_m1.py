# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Empirical Challenger Test Suite for Milestone M1 (Adaptive Installation).

Adversarial stress-testing of:
1. Dynamic distro detection in sentinel.py (Ubuntu, Debian, Alpine, Fedora, RHEL, CentOS,
   Arch, Manjaro, Rocky, AlmaLinux, Kali, Pop!_OS, Mint, EndeavourOS, Amazon Linux, unknown, corrupted).
2. Distro package maps, install hints, setup script generation, and git/compose checks.
3. crashwise configure --non-interactive valid/invalid flag permutations and .env integrity.
4. Pydantic Settings integration with generated .env files.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import mock_open, patch

import pytest
from typer.testing import CliRunner

from crashwise.cli import app
from crashwise.core.config import Settings
from crashwise.core.configure import (
    run_configure_non_interactive,
)
from crashwise.core.sentinel import (
    _CHECK_PACKAGES_BY_DISTRO,
    CheckStatus,
    DistroDetector,
    _install_hint,
    check_build_git,
    generate_setup_script,
)

runner = CliRunner()


# =============================================================================
# 1. Distro Detection Adversarial Matrix
# =============================================================================


@pytest.mark.parametrize(
    ("os_release_content", "expected_family", "expected_id", "expected_flags"),
    [
        # Ubuntu family
        (
            'NAME="Ubuntu"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\nVERSION_ID="22.04"\n',
            "debian",
            "ubuntu",
            {"is_debian": True, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        (
            'ID="ubuntu"\nID_LIKE="debian"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n',
            "debian",
            "ubuntu",
            {"is_debian": True, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        # Debian pure
        (
            'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\nID=debian\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
            "debian",
            "debian",
            {"is_debian": True, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        # Alpine Linux
        (
            'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.19.1\nPRETTY_NAME="Alpine Linux v3.19"\n',
            "alpine",
            "alpine",
            {"is_debian": False, "is_arch": False, "is_fedora": False, "is_alpine": True},
        ),
        # Alpine derivative (e.g. postmarketOS)
        (
            'ID=postmarketos\nID_LIKE=alpine\nPRETTY_NAME="postmarketOS edge"\n',
            "alpine",
            "postmarketos",
            {"is_debian": False, "is_arch": False, "is_fedora": False, "is_alpine": True},
        ),
        # Fedora
        (
            'NAME="Fedora Linux"\nVERSION="39 (Workstation Edition)"\nID=fedora\nVERSION_ID=39\nPRETTY_NAME="Fedora Linux 39 (Workstation Edition)"\n',
            "fedora",
            "fedora",
            {"is_debian": False, "is_arch": False, "is_fedora": True, "is_alpine": False},
        ),
        # RHEL
        (
            'NAME="Red Hat Enterprise Linux"\nVERSION="9.3 (Plow)"\nID="rhel"\nID_LIKE="fedora"\nVERSION_ID="9.3"\nPRETTY_NAME="Red Hat Enterprise Linux 9.3 (Plow)"\n',
            "fedora",
            "rhel",
            {"is_debian": False, "is_arch": False, "is_fedora": True, "is_alpine": False},
        ),
        # CentOS Stream
        (
            'NAME="CentOS Stream"\nVERSION="9"\nID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="9"\nPRETTY_NAME="CentOS Stream 9"\n',
            "fedora",
            "centos",
            {"is_debian": False, "is_arch": False, "is_fedora": True, "is_alpine": False},
        ),
        # Rocky Linux
        (
            'NAME="Rocky Linux"\nVERSION="9.2 (Blue Onyx)"\nID="rocky"\nID_LIKE="rhel centos fedora"\nPRETTY_NAME="Rocky Linux 9.2 (Blue Onyx)"\n',
            "fedora",
            "rocky",
            {"is_debian": False, "is_arch": False, "is_fedora": True, "is_alpine": False},
        ),
        # AlmaLinux
        (
            'NAME="AlmaLinux"\nVERSION="9.3 (Shamrock Pampas Cat)"\nID="almalinux"\nID_LIKE="rhel centos fedora"\nPRETTY_NAME="AlmaLinux 9.3 (Shamrock Pampas Cat)"\n',
            "fedora",
            "almalinux",
            {"is_debian": False, "is_arch": False, "is_fedora": True, "is_alpine": False},
        ),
        # Amazon Linux 2023
        (
            'NAME="Amazon Linux"\nVERSION="2023"\nID="amzn"\nID_LIKE="fedora"\nPRETTY_NAME="Amazon Linux 2023"\n',
            "fedora",
            "amzn",
            {"is_debian": False, "is_arch": False, "is_fedora": True, "is_alpine": False},
        ),
        # Arch Linux
        (
            'NAME="Arch Linux"\nPRETTY_NAME="Arch Linux"\nID=arch\nBUILD_ID=rolling\n',
            "arch",
            "arch",
            {"is_debian": False, "is_arch": True, "is_fedora": False, "is_alpine": False},
        ),
        # Manjaro Linux
        (
            'NAME="Manjaro Linux"\nID=manjaro\nID_LIKE=arch\nPRETTY_NAME="Manjaro Linux"\n',
            "arch",
            "manjaro",
            {"is_debian": False, "is_arch": True, "is_fedora": False, "is_alpine": False},
        ),
        # EndeavourOS
        (
            'NAME="EndeavourOS"\nID=endeavouros\nID_LIKE=arch\nPRETTY_NAME="EndeavourOS"\n',
            "arch",
            "endeavouros",
            {"is_debian": False, "is_arch": True, "is_fedora": False, "is_alpine": False},
        ),
        # Kali Linux
        (
            'NAME="Kali GNU/Linux"\nID=kali\nID_LIKE=debian\nPRETTY_NAME="Kali GNU/Linux Rolling"\n',
            "debian",
            "kali",
            {"is_debian": True, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        # Pop!_OS
        (
            'NAME="Pop!_OS"\nID=pop\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Pop!_OS 22.04 LTS"\n',
            "debian",
            "pop",
            {"is_debian": True, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        # Linux Mint
        (
            'NAME="Linux Mint"\nID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint 21.3"\n',
            "debian",
            "linuxmint",
            {"is_debian": True, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        # Raspbian
        (
            'NAME="Raspbian GNU/Linux"\nID=raspbian\nID_LIKE=debian\nPRETTY_NAME="Raspbian GNU/Linux 11 (bullseye)"\n',
            "debian",
            "raspbian",
            {"is_debian": True, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        # Unknown distributions
        (
            'NAME="Gentoo"\nID=gentoo\nPRETTY_NAME="Gentoo Linux"\n',
            "unknown",
            "gentoo",
            {"is_debian": False, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        (
            'NAME="NixOS"\nID=nixos\nPRETTY_NAME="NixOS 23.11 (Tapir)"\n',
            "unknown",
            "nixos",
            {"is_debian": False, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        (
            'NAME="Void Linux"\nID=void\nPRETTY_NAME="Void Linux"\n',
            "unknown",
            "void",
            {"is_debian": False, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        (
            'NAME="Slackware"\nID=slackware\nPRETTY_NAME="Slackware 15.0"\n',
            "unknown",
            "slackware",
            {"is_debian": False, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
        (
            'NAME="FreeBSD"\nID=freebsd\nPRETTY_NAME="FreeBSD 14.0-RELEASE"\n',
            "unknown",
            "freebsd",
            {"is_debian": False, "is_arch": False, "is_fedora": False, "is_alpine": False},
        ),
    ],
)
def test_empirical_distro_detection(
    os_release_content: str,
    expected_family: str,
    expected_id: str,
    expected_flags: dict[str, bool],
) -> None:
    """Empirically test DistroDetector across wide range of distros."""
    with patch("builtins.open", mock_open(read_data=os_release_content)):
        detector = DistroDetector()
        info = detector.detect()
        assert info.family == expected_family
        assert info.id_ == expected_id
        assert info.is_debian == expected_flags["is_debian"]
        assert info.is_arch == expected_flags["is_arch"]
        assert info.is_fedora == expected_flags["is_fedora"]
        assert info.is_alpine == expected_flags["is_alpine"]


def test_distro_detector_os_release_edge_cases() -> None:
    """Stress test /etc/os-release parser with weird formats, comments, missing keys."""
    # 1. Missing file
    with patch("builtins.open", side_effect=FileNotFoundError):
        detector = DistroDetector()
        info = detector.detect()
        assert info.family == "unknown"
        assert info.id_ == ""

    # 2. Empty file
    with patch("builtins.open", mock_open(read_data="")):
        detector = DistroDetector()
        info = detector.detect()
        assert info.family == "unknown"
        assert info.id_ == ""

    # 3. File with comments, blank lines, extra whitespace, single/double quotes, and multiple '='
    raw = """
    # This is a comment
    
       ID = "Ubuntu"   
    ID_LIKE = 'debian'
    HOME_URL="https://www.ubuntu.com/?utm=1&val=2"
    PRETTY_NAME = "Ubuntu 22.04"
    NO_EQUALS_LINE
    """
    with patch("builtins.open", mock_open(read_data=raw)):
        detector = DistroDetector()
        info = detector.detect()
        assert info.family == "debian"
        assert info.id_ == "ubuntu"
        assert info.pretty_name == "Ubuntu 22.04"

    # 4. Uppercase values in ID / ID_LIKE
    raw_caps = "ID=ALPINE\nID_LIKE=ALPINE\n"
    with patch("builtins.open", mock_open(read_data=raw_caps)):
        detector = DistroDetector()
        info = detector.detect()
        assert info.family == "alpine"
        assert info.is_alpine is True


def test_distro_detector_override() -> None:
    """Test manual override in constructor and global override."""
    det = DistroDetector(override="fedora")
    assert det.detect().family == "fedora"
    assert det.detect().is_fedora is True

    det_arch = DistroDetector(override="arch")
    assert det_arch.detect().family == "arch"
    assert det_arch.detect().is_arch is True

    det_alpine = DistroDetector(override="alpine")
    assert det_alpine.detect().family == "alpine"
    assert det_alpine.detect().is_alpine is True


# =============================================================================
# 2. Package Maps and Install Command Matrix
# =============================================================================


@pytest.mark.parametrize("distro", ["debian", "arch", "fedora", "alpine"])
def test_all_distros_have_complete_package_mapping(distro: str) -> None:
    """Verify package map keys for all 4 distro families."""
    required_checks = {
        "runtime.docker",
        "runtime.docker-compose",
        "build.git",
        "build.cmake",
        "build.clang",
        "build.gcc",
        "build.llvm",
        "build.afl++",
    }
    assert distro in _CHECK_PACKAGES_BY_DISTRO
    distro_map = _CHECK_PACKAGES_BY_DISTRO[distro]
    missing = required_checks - set(distro_map.keys())
    assert not missing, f"Distro {distro} missing packages for: {missing}"
    for check_name, pkgs in distro_map.items():
        assert isinstance(pkgs, list)
        assert len(pkgs) > 0, f"Empty package list for {distro} -> {check_name}"


@pytest.mark.parametrize(
    ("distro", "is_root", "has_sudo", "expected_cmd"),
    [
        ("alpine", True, False, "apk add --no-cache git cmake"),
        ("alpine", False, True, "sudo apk add --no-cache git cmake"),
        ("alpine", False, False, "apk add --no-cache git cmake"),
        ("arch", True, False, "pacman -S --needed git cmake"),
        ("arch", False, True, "sudo pacman -S --needed git cmake"),
        ("fedora", True, False, "dnf install -y git cmake"),
        ("fedora", False, True, "sudo dnf install -y git cmake"),
        ("debian", True, False, "apt-get install -y git cmake"),
        ("debian", False, True, "sudo apt-get install -y git cmake"),
        ("unknown", False, True, "sudo apt-get install -y git cmake"),
    ],
)
def test_install_hints_across_distros_and_privileges(
    distro: str,
    is_root: bool,
    has_sudo: bool,
    expected_cmd: str,
) -> None:
    """Verify _install_hint formatting across all distros and privilege levels."""
    with patch("crashwise.core.sentinel._is_root", return_value=is_root), patch(
        "crashwise.core.sentinel._which",
        return_value="/usr/bin/sudo" if has_sudo else None,
    ):
        hint = _install_hint(distro, ["git", "cmake"])
        assert hint == expected_cmd


def test_generate_setup_script_matrix() -> None:
    """Verify generate_setup_script produces valid shell scripts for all distros."""
    for distro in ("debian", "arch", "fedora", "alpine"):
        with patch("crashwise.core.sentinel._is_root", return_value=True):
            script = generate_setup_script(["git", "cmake"], distro=distro)
            assert "#!/usr/bin/env bash" in script
            assert f"# CrashWise System Provisioner ({distro})" in script
            assert "set -euo pipefail" in script
            if distro == "alpine":
                assert "apk update" in script
                assert "apk add --no-cache git cmake" in script
            elif distro == "arch":
                assert "pacman -Sy --noconfirm" in script
                assert "pacman -S --noconfirm --needed git cmake" in script
            elif distro == "fedora":
                assert "dnf -y check-update || true" in script
                assert "dnf install -y git cmake" in script
            elif distro == "debian":
                assert "apt-get update -qq" in script
                assert "apt-get install -y git cmake" in script


# =============================================================================
# 3. Git & Compose Checks
# =============================================================================


@pytest.mark.parametrize(
    ("distro", "expected_remediation_snippet"),
    [
        ("alpine", "apk add --no-cache git"),
        ("arch", "pacman -S --needed git"),
        ("fedora", "dnf install -y git"),
        ("debian", "apt-get install -y git"),
    ],
)
def test_check_build_git_remediation_per_distro(
    distro: str, expected_remediation_snippet: str
) -> None:
    """Verify git check failure surfaces exact distro-specific command."""
    with patch("crashwise.core.sentinel._run", return_value=(127, "", "git: not found")), patch(
        "crashwise.core.sentinel._detect_distro", return_value=distro
    ), patch("crashwise.core.sentinel._is_root", return_value=True):
        res = check_build_git()
        assert res.status == CheckStatus.FAIL
        assert expected_remediation_snippet in res.remediation


# =============================================================================
# 4. Configure Non-Interactive Stress Tests
# =============================================================================


def test_configure_non_interactive_full_permutations(tmp_path: Path) -> None:
    """Stress test run_configure_non_interactive with all valid flags and options."""
    env_file = tmp_path / "comprehensive.env"

    run_configure_non_interactive(
        env_path=env_file,
        api_port=8080,
        temporal_host="10.0.0.1:7233",
        temporal_namespace="production",
        temporal_task_queue="critical-queue",
        database_url="postgresql+asyncpg://admin:supersecret@10.0.0.2:5432/crashwise_db",
        redis_url="redis://:redispass@10.0.0.3:6379/5",
        worker_name="fuzz-node-alpha",
        workdir=Path("/data/crashwise/workspaces"),
        build_timeout=1800,
        llm_provider="anthropic",
        llm_model="claude-3-7-sonnet-20250219",
        llm_api_key="sk-ant-api03-secret-key-xyz",
        openai_api_base="https://custom.api/v1",
        ai_provider="venice",
        ai_model="llama-3.3-70b-specdec",
        ai_api_key="venice-api-key-999",
        ollama_url="http://10.0.0.4:11434",
    )

    assert env_file.exists()
    content = env_file.read_text(encoding="utf-8")

    # Verify all sections exist in order
    assert "# ── Agentic Workflows (LangChain) ──" in content
    assert "# ── Crash Triage ──" in content
    assert "# ── Infrastructure & Services ──" in content

    # Verify exact key values
    assert "CRASHWISE_API_PORT=8080" in content
    assert "TEMPORAL_HOST=10.0.0.1:7233" in content
    assert "TEMPORAL_NAMESPACE=production" in content
    assert "TEMPORAL_TASK_QUEUE=critical-queue" in content
    assert "DATABASE_URL=postgresql+asyncpg://admin:supersecret@10.0.0.2:5432/crashwise_db" in content
    assert "REDIS_URL=redis://:redispass@10.0.0.3:6379/5" in content
    assert "WORKER_NAME=fuzz-node-alpha" in content
    assert "CRASHWISE_WORKDIR=/data/crashwise/workspaces" in content
    assert "CRASHWISE_BUILD_TIMEOUT=1800" in content
    assert "CRASHWISE_LLM_MODEL=claude-3-7-sonnet-20250219" in content
    assert "ANTHROPIC_API_KEY=sk-ant-api03-secret-key-xyz" in content
    assert "OPENAI_API_BASE=https://custom.api/v1" in content
    assert "AI_PROVIDER=venice" in content
    assert "AI_MODEL=llama-3.3-70b-specdec" in content
    assert "AI_API_KEY=venice-api-key-999" in content
    assert "OLLAMA_URL=http://10.0.0.4:11434" in content

    # Verify that Settings parses this .env correctly
    settings = Settings(_env_file=env_file)
    assert settings.crashwise_api_port == 8080
    assert settings.temporal_host == "10.0.0.1:7233"
    assert settings.crashwise_workdir == Path("/data/crashwise/workspaces")
    assert settings.crashwise_build_timeout == 1800
    assert settings.temporal_namespace == "production"
    assert settings.temporal_task_queue == "critical-queue"
    assert settings.worker_name == "fuzz-node-alpha"


def test_configure_non_interactive_special_characters_and_edge_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify passwords with special symbols, URLs with query params, unusual paths."""
    env_file = tmp_path / "special.env"

    special_db = "postgresql+asyncpg://user:p@$$w0rd#123!@db-host:5432/cw_db?sslmode=disable"
    special_workdir = "/tmp/space in path/dir-123_456"

    run_configure_non_interactive(
        env_path=env_file,
        database_url=special_db,
        workdir=special_workdir,
        api_port=9001,
    )

    content = env_file.read_text(encoding="utf-8")
    assert f"DATABASE_URL={special_db}" in content
    assert f"CRASHWISE_WORKDIR={special_workdir}" in content

    monkeypatch.delenv("DATABASE_URL", raising=False)
    settings = Settings(_env_file=env_file)
    assert settings.database_url == special_db
    assert settings.crashwise_workdir == Path(special_workdir)


def test_configure_non_interactive_preserves_unmanaged_and_dirty_env(tmp_path: Path) -> None:
    """Verify merge preserves custom variables, comments, and handles dirty lines."""
    env_file = tmp_path / "dirty.env"
    initial_content = """# Header comment
MY_CUSTOM_SECRET=keep_this_safe
ANOTHER_VAR=12345
# A comment in the middle
TEMPORAL_HOST=old_temporal:7233

# Empty lines above and bad line below
INVALID_LINE_WITHOUT_EQUALS
EMPTY_VALUE=
=EMPTY_KEY
"""
    env_file.write_text(initial_content, encoding="utf-8")

    run_configure_non_interactive(
        env_path=env_file,
        temporal_host="new_temporal:7233",
        api_port=7777,
    )

    content = env_file.read_text(encoding="utf-8")
    assert "MY_CUSTOM_SECRET=keep_this_safe" in content
    assert "ANOTHER_VAR=12345" in content
    assert "TEMPORAL_HOST=new_temporal:7233" in content
    assert "CRASHWISE_API_PORT=7777" in content
    assert "old_temporal:7233" not in content


def test_cli_configure_non_interactive_comprehensive_flags(tmp_path: Path) -> None:
    """Verify CLI `crashwise configure --non-interactive` with full flags via CliRunner."""
    env_file = tmp_path / "cli_full.env"
    res = runner.invoke(
        app,
        [
            "configure",
            "--non-interactive",
            "--env-file",
            str(env_file),
            "--api-port",
            "9876",
            "--temporal-host",
            "orchestrator:7233",
            "--temporal-namespace",
            "custom-ns",
            "--temporal-task-queue",
            "custom-tq",
            "--database-url",
            "sqlite+aiosqlite:///./test.db",
            "--redis-url",
            "redis://127.0.0.1:6379/3",
            "--worker-name",
            "worker-m1-test",
            "--workdir",
            "/tmp/cw_m1_test",
            "--build-timeout",
            "450",
            "--llm-provider",
            "anthropic",
            "--llm-model",
            "claude-3-5-haiku-20241022",
            "--llm-api-key",
            "sk-ant-test-key",
            "--openai-api-base",
            "https://api.openai.com/v1",
            "--ai-provider",
            "ollama",
            "--ai-model",
            "codellama:7b",
            "--ai-api-key",
            "dummy-key",
            "--ollama-url",
            "http://localhost:11434",
        ],
    )
    assert res.exit_code == 0
    assert "Configuration saved to" in res.output
    assert env_file.exists()

    content = env_file.read_text(encoding="utf-8")
    assert "CRASHWISE_API_PORT=9876" in content
    assert "TEMPORAL_HOST=orchestrator:7233" in content
    assert "TEMPORAL_NAMESPACE=custom-ns" in content
    assert "TEMPORAL_TASK_QUEUE=custom-tq" in content
    assert "DATABASE_URL=sqlite+aiosqlite:///./test.db" in content
    assert "REDIS_URL=redis://127.0.0.1:6379/3" in content
    assert "WORKER_NAME=worker-m1-test" in content
    assert "CRASHWISE_WORKDIR=/tmp/cw_m1_test" in content
    assert "CRASHWISE_BUILD_TIMEOUT=450" in content
    assert "ANTHROPIC_API_KEY=sk-ant-test-key" in content
    assert "CRASHWISE_LLM_MODEL=claude-3-5-haiku-20241022" in content
    assert "AI_PROVIDER=ollama" in content
    assert "AI_MODEL=codellama:7b" in content
    assert "AI_API_KEY=dummy-key" in content
    assert "OLLAMA_URL=http://localhost:11434" in content


def test_cli_configure_invalid_flags() -> None:
    """Verify CLI error handling for invalid options (e.g. non-integer port)."""
    res = runner.invoke(
        app,
        [
            "configure",
            "--non-interactive",
            "--api-port",
            "not-a-number",
        ],
    )
    assert res.exit_code != 0
    assert "Invalid value for '--api-port'" in res.output or "not a valid integer" in res.output
