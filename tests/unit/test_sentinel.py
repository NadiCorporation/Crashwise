# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Phase 20 — System Sentinel & Unified Provisioner."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from crashwise.core.sentinel import (
    CheckResult,
    CheckStatus,
    SentinelReport,
    _get_cpu_cores,
    _get_free_disk_gb,
    _get_total_ram_gb,
    _parse_meminfo_kb,
    _run,
    _which,
    check_build_afl,
    check_build_clang,
    check_build_cmake,
    check_build_gcc,
    check_build_libfuzzer,
    check_build_llvm,
    check_hardware_cpu,
    check_hardware_disk,
    check_hardware_ram,
    check_runtime_docker,
    check_runtime_docker_compose,
    check_runtime_python,
    check_service_llm,
    check_service_redis,
    check_service_temporal,
    generate_setup_script,
    get_missing_packages,
    run_all_checks,
)


# ── Helpers ────────────────────────────────────────────────────────────────────


def test_run_command_found() -> None:
    rc, out, err = _run(["echo", "hello"])
    assert rc == 0
    assert out == "hello"


def test_run_command_not_found() -> None:
    rc, out, err = _run(["nonexistent_command_xyz"])
    assert rc == 127
    assert "not found" in err.lower() or err == ""


def test_run_command_timeout() -> None:
    rc, out, err = _run(["sleep", "10"], timeout=0.1)
    assert rc == -1
    assert "timed out" in err.lower()


def test_which_found() -> None:
    path = _which("python3")
    assert path is not None


def test_which_not_found() -> None:
    path = _which("nonexistent_binary_xyz")
    assert path is None


# ── Hardware Checks ──────────────────────────────────────────────────────────


def test_parse_meminfo_kb() -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix="_meminfo", delete=False) as fh:
        fh.write("MemTotal:       16384000 kB\n")
        fh.write("MemFree:         8192000 kB\n")
        fh.flush()
        with patch("crashwise.core.sentinel.open", create=True) as mock_open:
            mock_open.return_value.__enter__.return_value = fh
            # We can't easily patch open for a specific path; test via the real file
            pass
    # Test with real /proc/meminfo if available
    kb = _parse_meminfo_kb("MemTotal")
    if kb is not None:
        assert isinstance(kb, int)
        assert kb > 0


def test_get_total_ram_gb() -> None:
    gb = _get_total_ram_gb()
    if gb is not None:
        assert isinstance(gb, float)
        assert gb > 0


def test_get_cpu_cores() -> None:
    cores = _get_cpu_cores()
    assert cores is not None
    assert isinstance(cores, int)
    assert cores > 0


def test_get_free_disk_gb() -> None:
    gb = _get_free_disk_gb()
    assert gb is not None
    assert isinstance(gb, float)
    assert gb >= 0


def test_check_hardware_ram_ok() -> None:
    with patch("crashwise.core.sentinel._get_total_ram_gb", return_value=16.0):
        result = check_hardware_ram(min_gb=8.0)
        assert result.status == CheckStatus.OK
        assert "16.0" in result.message


def test_check_hardware_ram_warn() -> None:
    with patch("crashwise.core.sentinel._get_total_ram_gb", return_value=4.0):
        result = check_hardware_ram(min_gb=8.0)
        assert result.status == CheckStatus.WARN
        assert "4.0" in result.message
        assert result.remediation != ""


def test_check_hardware_ram_skip() -> None:
    with patch("crashwise.core.sentinel._get_total_ram_gb", return_value=None):
        result = check_hardware_ram()
        assert result.status == CheckStatus.SKIP


def test_check_hardware_cpu_ok() -> None:
    with patch("crashwise.core.sentinel._get_cpu_cores", return_value=8):
        result = check_hardware_cpu(min_cores=4)
        assert result.status == CheckStatus.OK
        assert "8" in result.message


def test_check_hardware_cpu_warn() -> None:
    with patch("crashwise.core.sentinel._get_cpu_cores", return_value=2):
        result = check_hardware_cpu(min_cores=4)
        assert result.status == CheckStatus.WARN


def test_check_hardware_cpu_skip() -> None:
    with patch("crashwise.core.sentinel._get_cpu_cores", return_value=None):
        result = check_hardware_cpu()
        assert result.status == CheckStatus.SKIP


def test_check_hardware_disk_ok() -> None:
    with patch("crashwise.core.sentinel._get_free_disk_gb", return_value=100.0):
        result = check_hardware_disk(min_free_gb=50.0)
        assert result.status == CheckStatus.OK


def test_check_hardware_disk_warn() -> None:
    with patch("crashwise.core.sentinel._get_free_disk_gb", return_value=10.0):
        result = check_hardware_disk(min_free_gb=50.0)
        assert result.status == CheckStatus.WARN


def test_check_hardware_disk_skip() -> None:
    with patch("crashwise.core.sentinel._get_free_disk_gb", return_value=None):
        result = check_hardware_disk()
        assert result.status == CheckStatus.SKIP


# ── Runtime Checks ─────────────────────────────────────────────────────────────


def test_check_runtime_docker_ok() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(0, "24.0.7", "")):
        result = check_runtime_docker()
        assert result.status == CheckStatus.OK
        assert "24.0.7" in result.message


def test_check_runtime_docker_cli_found_daemon_dead() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(1, "", "Cannot connect")), \
         patch("crashwise.core.sentinel._which", return_value="/usr/bin/docker"):
        result = check_runtime_docker()
        assert result.status == CheckStatus.FAIL
        assert "daemon" in result.message.lower()


def test_check_runtime_docker_not_installed() -> None:
    with patch("crashwise.core.sentinel._which", return_value=None), \
         patch("crashwise.core.sentinel._run", return_value=(127, "", "not found")):
        result = check_runtime_docker()
        assert result.status == CheckStatus.FAIL
        assert "not installed" in result.message.lower()


def test_check_runtime_docker_permission_denied_stale_shell() -> None:
    """The exact scenario Yahya hit on Ubuntu 24.04: usermod -aG ran, the
    user IS in /etc/group, but the current shell still has the
    pre-usermod credential set, so the socket is unreachable.

    The Sentinel must surface this as a *stale-session* problem with a
    remediation that says 'log out / newgrp docker' — NOT
    'systemctl start docker', which is the wrong fix.
    """
    perm_err = (
        "permission denied while trying to connect to the Docker daemon "
        "socket at unix:///var/run/docker.sock"
    )
    with patch("crashwise.core.sentinel._run", return_value=(1, "", perm_err)), \
         patch("crashwise.core.sentinel._which", return_value="/usr/bin/docker"), \
         patch("crashwise.core.sentinel._user_in_docker_group", return_value=True), \
         patch("crashwise.core.sentinel._user_can_reach_docker_socket", return_value=False):
        result = check_runtime_docker()
    assert result.status == CheckStatus.FAIL
    assert "shell session" in result.message.lower() or "session" in result.message.lower()
    # The remediation must talk about log out / newgrp, NOT systemctl start.
    assert "newgrp" in result.remediation or "log out" in result.remediation.lower()
    assert "systemctl start" not in result.remediation


def test_check_runtime_docker_permission_denied_not_in_group() -> None:
    """User actually isn't in the docker group on disk → usermod is the fix."""
    perm_err = (
        "permission denied while trying to connect to the Docker daemon socket"
    )
    with patch("crashwise.core.sentinel._run", return_value=(1, "", perm_err)), \
         patch("crashwise.core.sentinel._which", return_value="/usr/bin/docker"), \
         patch("crashwise.core.sentinel._user_in_docker_group", return_value=False), \
         patch("crashwise.core.sentinel._user_can_reach_docker_socket", return_value=False):
        result = check_runtime_docker()
    assert result.status == CheckStatus.FAIL
    assert "docker group" in result.message.lower()
    assert "usermod" in result.remediation


def test_check_runtime_docker_compose_ok_plugin() -> None:
    with patch("crashwise.core.sentinel._run", side_effect=[
        (0, "Docker Compose version v2.20.0", ""),  # first cmd succeeds
    ]):
        result = check_runtime_docker_compose()
        assert result.status == CheckStatus.OK


def test_check_runtime_docker_compose_legacy_v1_is_fail() -> None:
    """Legacy ``docker-compose`` v1.x is incompatible with modern Docker
    engines (KeyError: 'ContainerConfig' — docker/compose#9229).  The
    Sentinel must surface this as a FAIL, not a soft warning, because
    it WILL break ``docker compose up -d`` the moment the user rebuilds
    an image.
    """
    with patch("crashwise.core.sentinel._run", side_effect=[
        (1, "", ""),  # docker compose v2 plugin missing
        (0, "docker-compose version 1.29.2", ""),  # only legacy v1 present
    ]):
        result = check_runtime_docker_compose()
        assert result.status == CheckStatus.FAIL
        assert "v1" in result.message.lower() or "legacy" in result.message.lower()
        assert "ContainerConfig" in result.message or "containerconfig" in result.message.lower()


def test_check_runtime_docker_compose_ok_v2_plugin() -> None:
    """``docker compose version`` (v2 plugin) is the happy path."""
    with patch("crashwise.core.sentinel._run", side_effect=[
        (0, "Docker Compose version v2.27.0", ""),  # v2 plugin OK
    ]):
        result = check_runtime_docker_compose()
        assert result.status == CheckStatus.OK
        assert "v2" in result.message


def test_check_runtime_docker_compose_unfamiliar_version_is_ok() -> None:
    """When a non-v1 standalone is present (e.g. a self-built v2.x), be
    permissive and report OK rather than FAIL."""
    with patch("crashwise.core.sentinel._run", side_effect=[
        (1, "", ""),  # plugin missing
        (0, "Docker Compose version 2.20.3", ""),  # standalone v2-style
    ]):
        result = check_runtime_docker_compose()
        assert result.status == CheckStatus.OK


def test_check_runtime_docker_compose_fail() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(1, "", "not found")):
        result = check_runtime_docker_compose()
        assert result.status == CheckStatus.FAIL


def test_check_runtime_python_ok() -> None:
    with patch("crashwise.core.sentinel.platform.python_version_tuple", return_value=("3", "11", "0")):
        result = check_runtime_python()
        assert result.status == CheckStatus.OK


def test_check_runtime_python_fail() -> None:
    with patch("crashwise.core.sentinel.platform.python_version_tuple", return_value=("3", "9", "0")):
        result = check_runtime_python()
        assert result.status == CheckStatus.FAIL


# ── Build Tool Checks ──────────────────────────────────────────────────────────


def test_check_build_cmake_ok() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(0, "cmake version 3.28.0", "")):
        result = check_build_cmake()
        assert result.status == CheckStatus.OK


def test_check_build_cmake_fail() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(127, "", "not found")):
        result = check_build_cmake()
        assert result.status == CheckStatus.FAIL


def test_check_build_clang_ok() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(0, "clang version 16.0.0", "")):
        result = check_build_clang()
        assert result.status == CheckStatus.OK


def test_check_build_clang_fail() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(127, "", "not found")):
        result = check_build_clang()
        assert result.status == CheckStatus.FAIL


def test_check_build_gcc_ok() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(0, "gcc (Debian 12.0.0)", "")):
        result = check_build_gcc()
        assert result.status == CheckStatus.OK


def test_check_build_gcc_fail() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(127, "", "not found")):
        result = check_build_gcc()
        assert result.status == CheckStatus.FAIL


def test_check_build_llvm_ok() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(0, "16.0.0", "")):
        result = check_build_llvm()
        assert result.status == CheckStatus.OK


def test_check_build_llvm_ok_with_suffix() -> None:
    # Phase 21: probe order is -19, -18, -17, -16, -15. Test that -17 succeeds
    # after -19/-18 fail (and the bare llvm-config probe also fails first).
    with patch("crashwise.core.sentinel._run", side_effect=[
        (127, "", "not found"),  # llvm-config fails
        (127, "", "not found"),  # llvm-config-19 fails
        (127, "", "not found"),  # llvm-config-18 fails
        (0, "17.0.0", ""),       # llvm-config-17 succeeds
    ]):
        result = check_build_llvm()
        assert result.status == CheckStatus.OK
        assert "llvm-config-17" in result.message


def test_check_build_llvm_fail() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(127, "", "not found")):
        result = check_build_llvm()
        assert result.status == CheckStatus.FAIL


def test_check_build_afl_ok() -> None:
    """A working AFL++ install prints its banner to stdout/stderr via -h
    and exits non-zero (since -h is treated like an unknown option that
    triggers the usage screen). The detector ignores the exit code and
    parses the banner line."""
    banner = (
        "afl-fuzz++4.21c based on afl by Michal Zalewski and a large "
        "online community\n\nafl-fuzz [ options ] -- ...\n"
    )
    with patch("crashwise.core.sentinel._which", return_value="/usr/bin/afl-fuzz"), \
         patch("crashwise.core.sentinel._run", return_value=(1, banner, "")):
        result = check_build_afl()
        assert result.status == CheckStatus.OK
        assert "4.21c" in result.message


def test_check_build_afl_not_installed() -> None:
    """afl-fuzz is not on PATH → WARN with install hint (Docker worker
    is the documented fallback so we don't FAIL)."""
    with patch("crashwise.core.sentinel._which", return_value=None), \
         patch("crashwise.core.sentinel._run", return_value=(127, "", "not found")):
        result = check_build_afl()
        assert result.status == CheckStatus.WARN
        assert "Docker worker" in result.remediation


def test_check_build_afl_broken_binary() -> None:
    """afl-fuzz is on PATH but cannot run (e.g. broken dynamic link).
    The detector must NOT report this as OK — surface as WARN with a
    'reinstall or use Docker' hint."""
    dyn_err = (
        "afl-fuzz: error while loading shared libraries: "
        "libpython3.13.so.1.0: cannot open shared object file: "
        "No such file or directory\n"
    )
    with patch("crashwise.core.sentinel._which", return_value="/usr/bin/afl-fuzz"), \
         patch("crashwise.core.sentinel._run", return_value=(127, "", dyn_err)):
        result = check_build_afl()
        assert result.status == CheckStatus.WARN
        assert "failed to load" in result.message.lower()
        assert "Docker worker" in result.remediation


def test_check_build_libfuzzer_ok() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(1, "", "linker input file")):
        result = check_build_libfuzzer()
        assert result.status == CheckStatus.OK


def test_check_build_libfuzzer_warn() -> None:
    with patch("crashwise.core.sentinel._run", return_value=(1, "", "unrecognized argument")):
        result = check_build_libfuzzer()
        assert result.status == CheckStatus.WARN


# ── Service Checks (async) ───────────────────────────────────────────────────


@pytest.mark.anyio
async def test_check_service_temporal_ok() -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    async def _mock_get(*args, **kwargs):
        return mock_resp

    mock_client = AsyncMock()
    mock_client.get = _mock_get
    mock_client.__aenter__.return_value = mock_client  # crucial: __aenter__ must return self

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await check_service_temporal()
        assert result.status == CheckStatus.OK


@pytest.mark.anyio
async def test_check_service_temporal_warn() -> None:
    with patch("socket.socket") as mock_socket_cls:
        mock_sock = MagicMock()
        mock_sock.connect = MagicMock(side_effect=Exception("connection refused"))
        mock_socket_cls.return_value = mock_sock

        result = await check_service_temporal("localhost", 7233)
        assert result.status == CheckStatus.WARN


@pytest.mark.anyio
async def test_check_service_redis_ok() -> None:
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(return_value=None)
    mock_redis.close = AsyncMock(return_value=None)

    with patch("redis.asyncio.Redis", return_value=mock_redis):
        result = await check_service_redis()
        assert result.status == CheckStatus.OK


@pytest.mark.anyio
async def test_check_service_redis_warn() -> None:
    with patch("redis.asyncio.Redis", side_effect=Exception("connection refused")):
        result = await check_service_redis()
        assert result.status == CheckStatus.WARN


@pytest.mark.anyio
async def test_check_service_llm_ok() -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = MagicMock(return_value={"models": [{"name": "codellama"}]})

    async def _mock_get(*args, **kwargs):
        return mock_resp

    mock_client = AsyncMock()
    mock_client.get = _mock_get
    mock_client.__aenter__.return_value = mock_client

    mock_settings = MagicMock()
    mock_settings.openai_api_base = None
    mock_settings.crashwise_llm_model = "codellama"
    mock_settings.ai_provider = "ollama"
    mock_settings.ollama_url = "http://localhost:11434"
    mock_settings.ai_model = "codellama"
    mock_settings.ai_api_key = None
    mock_settings.openai_api_key = None

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("crashwise.core.config.get_settings", return_value=mock_settings):
        result = await check_service_llm()
        assert result.status == CheckStatus.OK
        assert "codellama" in result.message


@pytest.mark.anyio
async def test_check_service_llm_warn() -> None:
    async def _mock_get(*args, **kwargs):
        raise Exception("connection refused")

    mock_client = AsyncMock()
    mock_client.get = _mock_get
    mock_client.__aenter__.return_value = mock_client

    mock_settings = MagicMock()
    mock_settings.openai_api_base = None
    mock_settings.crashwise_llm_model = "codellama"
    mock_settings.ai_provider = "ollama"
    mock_settings.ollama_url = "http://localhost:11434"
    mock_settings.ai_model = "codellama"
    mock_settings.ai_api_key = None
    mock_settings.openai_api_key = None

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("crashwise.core.config.get_settings", return_value=mock_settings):
        result = await check_service_llm()
        assert result.status == CheckStatus.WARN


# ── Report Aggregation ───────────────────────────────────────────────────────


def test_sentinel_report_counts() -> None:
    report = SentinelReport(
        checks=[
            CheckResult("a", CheckStatus.OK, "ok"),
            CheckResult("b", CheckStatus.OK, "ok"),
            CheckResult("c", CheckStatus.WARN, "warn"),
            CheckResult("d", CheckStatus.FAIL, "fail"),
        ]
    )
    assert report.ok_count == 2
    assert report.warn_count == 1
    assert report.fail_count == 1
    assert not report.healthy


def test_sentinel_report_healthy() -> None:
    report = SentinelReport(
        checks=[
            CheckResult("a", CheckStatus.OK, "ok"),
            CheckResult("b", CheckStatus.OK, "ok"),
        ]
    )
    assert report.healthy


def test_sentinel_report_by_category() -> None:
    report = SentinelReport(
        checks=[
            CheckResult("hardware.ram", CheckStatus.OK, "ok"),
            CheckResult("hardware.cpu", CheckStatus.OK, "ok"),
            CheckResult("build.cmake", CheckStatus.FAIL, "fail"),
        ]
    )
    groups = report.by_category()
    assert len(groups["hardware"]) == 2
    assert len(groups["build"]) == 1


# ── Provisioner ──────────────────────────────────────────────────────────────


def test_get_missing_packages() -> None:
    report = SentinelReport(
        checks=[
            CheckResult("build.cmake", CheckStatus.FAIL, "not found"),
            CheckResult("build.clang", CheckStatus.FAIL, "not found"),
            CheckResult("hardware.ram", CheckStatus.OK, "ok"),
        ]
    )
    # Pin distro to keep test deterministic across hosts (Phase 21).
    pkgs = get_missing_packages(report, distro="debian")
    assert "cmake" in pkgs
    assert "clang" in pkgs


def test_get_missing_packages_empty() -> None:
    report = SentinelReport(
        checks=[CheckResult("hardware.ram", CheckStatus.OK, "ok")]
    )
    pkgs = get_missing_packages(report, distro="debian")
    assert pkgs == []


def test_generate_setup_script() -> None:
    script = generate_setup_script(["cmake", "clang"], distro="debian")
    assert "#!/usr/bin/env bash" in script
    assert "apt-get update" in script
    assert "cmake clang" in script


def test_generate_setup_script_empty() -> None:
    script = generate_setup_script([])
    assert "already installed" in script


# ── Phase 21: Arch Linux Sentinel ────────────────────────────────────────────


def test_detect_distro_arch(monkeypatch: pytest.MonkeyPatch) -> None:
    from crashwise.core import sentinel as sm

    monkeypatch.setattr(sm, "_DISTRO_OVERRIDE", "arch", raising=False)
    assert sm._detect_distro() == "arch"


def test_detect_distro_debian(monkeypatch: pytest.MonkeyPatch) -> None:
    from crashwise.core import sentinel as sm

    monkeypatch.setattr(sm, "_DISTRO_OVERRIDE", "debian", raising=False)
    assert sm._detect_distro() == "debian"


def test_detect_distro_unknown_when_no_os_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from crashwise.core import sentinel as sm

    monkeypatch.setattr(sm, "_DISTRO_OVERRIDE", None, raising=False)
    # Force FileNotFoundError by chdir'ing somewhere os-release doesn't exist
    # is not viable since absolute path is used; we instead patch open.
    real_open = open

    def fake_open(*args, **kwargs):  # type: ignore[no-untyped-def]
        if args and args[0] == "/etc/os-release":
            raise FileNotFoundError(args[0])
        return real_open(*args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)
    assert sm._detect_distro() == "unknown"


def test_get_missing_packages_arch() -> None:
    report = SentinelReport(
        checks=[
            CheckResult("build.cmake", CheckStatus.FAIL, "not found"),
            CheckResult("build.gcc", CheckStatus.FAIL, "not found"),
            CheckResult("build.llvm", CheckStatus.FAIL, "not found"),
        ]
    )
    pkgs = get_missing_packages(report, distro="arch")
    assert "cmake" in pkgs
    # Arch ships C++ as part of `gcc`; no separate g++ package.
    assert "g++" not in pkgs
    assert "gcc" in pkgs
    assert "llvm" in pkgs
    assert "lld" in pkgs


def test_generate_setup_script_arch() -> None:
    script = generate_setup_script(["cmake", "clang"], distro="arch")
    assert "#!/usr/bin/env bash" in script
    assert "pacman -S" in script
    assert "cmake clang" in script
    # Must NOT contain Debian commands.
    assert "apt-get" not in script


def test_generate_setup_script_fedora() -> None:
    script = generate_setup_script(["cmake"], distro="fedora")
    assert "dnf install" in script


def test_check_build_llvm_arch_generic_binary() -> None:
    """Arch ships a bare `llvm-config` (no version suffix)."""
    with patch("crashwise.core.sentinel._run", return_value=(0, "19.1.0", "")):
        result = check_build_llvm()
        assert result.status == CheckStatus.OK
        assert "19.1.0" in result.message


def test_check_build_llvm_arch_remediation_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from crashwise.core import sentinel as sm

    monkeypatch.setattr(sm, "_DISTRO_OVERRIDE", "arch", raising=False)
    with patch("crashwise.core.sentinel._run", return_value=(127, "", "not found")):
        result = check_build_llvm()
        assert result.status == CheckStatus.FAIL
        assert "pacman" in result.remediation


# ── Full Orchestrator ────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_run_all_checks() -> None:
    with patch("crashwise.core.sentinel._get_total_ram_gb", return_value=16.0), \
         patch("crashwise.core.sentinel._get_cpu_cores", return_value=8), \
         patch("crashwise.core.sentinel._get_free_disk_gb", return_value=100.0), \
         patch("crashwise.core.sentinel._run", return_value=(0, "ok", "")), \
         patch("crashwise.core.sentinel._which", return_value="/usr/bin/docker"), \
         patch("crashwise.core.sentinel.platform.python_version_tuple", return_value=("3", "11", "0")), \
         patch("crashwise.core.sentinel.check_service_temporal", return_value=CheckResult("service.temporal", CheckStatus.OK, "ok")), \
         patch("crashwise.core.sentinel.check_service_redis", return_value=CheckResult("service.redis", CheckStatus.OK, "ok")), \
         patch("crashwise.core.sentinel.check_service_llm", return_value=CheckResult("service.llm", CheckStatus.OK, "ok")):
        report = await run_all_checks()
        assert report.healthy
        assert len(report.checks) >= 12  # hardware(3) + runtime(3) + build(6) + services(3)
