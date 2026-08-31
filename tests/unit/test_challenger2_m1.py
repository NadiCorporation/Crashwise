# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Empirical Challenger 2 Test Suite for Milestone M1 (Adaptive Installation).

Covers:
1. CRASHWISE_WORKDIR and CRASHWISE_BUILD_TIMEOUT overrides across config.py,
   setup_target.py, and healing_activities.py.
2. docker-compose.yaml parameterization syntax, YAML validity, and multi-service
   consistency with various environment overrides (credentials, ports, storage).
3. Build timeout execution & cancellation behavior in setup_target._build_target.
4. CLI non-interactive configure generation for CRASHWISE_WORKDIR and CRASHWISE_BUILD_TIMEOUT.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from crashwise.core.config import Settings, get_settings
from crashwise.core.configure import run_configure_non_interactive
from crashwise.core.discovery import DiscoveredProfile
from crashwise.core.models import SetupTargetInput
from crashwise.orchestration.activities.healing_activities import (
    _allocate_workspace,
    _get_healing_workspace_root,
)
from crashwise.orchestration.activities.setup_target import (
    _build_target,
    _get_build_timeout,
    setup_target,
)

# ══════════════════════════════════════════════════════════════════════════════
# 1. CRASHWISE_WORKDIR & CRASHWISE_BUILD_TIMEOUT Empirical Tests
# ══════════════════════════════════════════════════════════════════════════════


def test_workdir_default_resolution() -> None:
    """Verify default workdir is /tmp/crashwise when no env var is set."""
    get_settings.cache_clear()
    settings = Settings(_env_file=None)
    assert settings.crashwise_workdir == Path("/tmp/crashwise")
    assert settings.crashwise_build_timeout == 900


@pytest.mark.parametrize(
    "custom_path,expected_path",
    [
        ("/var/lib/crashwise", Path("/var/lib/crashwise")),
        ("/home/user/custom workdir/path", Path("/home/user/custom workdir/path")),
        ("./relative_workdir", Path("relative_workdir")),
        ("/tmp/crashwise_trailing/", Path("/tmp/crashwise_trailing")),
    ],
)
def test_workdir_various_path_types_override(
    monkeypatch: pytest.MonkeyPatch,
    custom_path: str,
    expected_path: Path,
) -> None:
    """Verify CRASHWISE_WORKDIR handles absolute, space-containing, relative, and trailing slash paths."""
    monkeypatch.setenv("CRASHWISE_WORKDIR", custom_path)
    get_settings.cache_clear()
    try:
        settings = Settings(_env_file=None)
        assert settings.crashwise_workdir.resolve() == expected_path.resolve()
    finally:
        get_settings.cache_clear()


@pytest.mark.parametrize(
    "timeout_str,expected_int",
    [
        ("30", 30),
        ("600", 600),
        ("1800", 1800),
        ("86400", 86400),
    ],
)
def test_build_timeout_env_overrides(
    monkeypatch: pytest.MonkeyPatch,
    timeout_str: str,
    expected_int: int,
) -> None:
    """Verify CRASHWISE_BUILD_TIMEOUT overrides settings and setup_target helper."""
    monkeypatch.setenv("CRASHWISE_BUILD_TIMEOUT", timeout_str)
    get_settings.cache_clear()
    try:
        settings = Settings(_env_file=None)
        assert settings.crashwise_build_timeout == expected_int
        assert _get_build_timeout() == float(expected_int)
    finally:
        get_settings.cache_clear()


def test_build_timeout_fallback_on_invalid_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify _get_build_timeout falls back to 900.0 on invalid or non-numeric settings."""
    with patch("crashwise.orchestration.activities.setup_target.get_settings") as mock_settings:
        mock_settings.return_value.crashwise_build_timeout = "not-a-number"
        assert _get_build_timeout() == 900.0


def test_healing_activities_workspace_hierarchy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify healing activities root and workspace allocation follow CRASHWISE_WORKDIR."""
    custom_root = tmp_path / "custom_healing_base"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(custom_root))
    get_settings.cache_clear()
    try:
        root = _get_healing_workspace_root()
        assert root == custom_root / "healing"

        build_ws = _allocate_workspace("campaign-test-1", mode="build")
        assert build_ws == custom_root / "healing" / "build" / "campaign-test-1"
        assert build_ws.is_dir()

        repair_ws = _allocate_workspace("crash-xyz:789", mode="repair")
        assert repair_ws == custom_root / "healing" / "repair" / "crash-xyz_789"
        assert repair_ws.is_dir()
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_setup_target_end_to_end_workdir_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify setup_target creates correct directory structure under CRASHWISE_WORKDIR and respects timeout."""
    custom_root = tmp_path / "custom_cw_root"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(custom_root))
    monkeypatch.setenv("CRASHWISE_BUILD_TIMEOUT", "45")
    get_settings.cache_clear()

    input_payload = SetupTargetInput(
        target_repo="https://github.com/example/repo.git",
        target_branch="main",
        sanitizers="address,undefined",
        synthesize_harness=False,
    )

    mock_info = MagicMock()
    mock_info.workflow_id = "wf-empirical-99"
    mock_info.attempt = 1

    build_called_with_timeout = []

    async def mock_clone(
        repo_url: str,
        branch: str | None,
        workdir: Path,
        clone_depth: int = 1,
        *args: object,
        **kwargs: object,
    ) -> str:
        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)\n")
        return "sha-1234567890abcdef"

    async def mock_build(workdir: Path, sanitizers: str) -> None:
        timeout = _get_build_timeout()
        build_called_with_timeout.append(timeout)

    with patch("temporalio.activity.info", return_value=mock_info), patch(
        "crashwise.orchestration.activities.setup_target._clone_repo",
        side_effect=mock_clone,
    ), patch(
        "crashwise.orchestration.activities.setup_target._build_target",
        side_effect=mock_build,
    ), patch(
        "crashwise.orchestration.activities.setup_target._detect_existing_harness",
        return_value=None,
    ):
        result = await setup_target(input_payload)

        expected_workdir = custom_root / "wf-empirical-99" / "target"
        assert result.workdir == expected_workdir
        assert result.workdir.is_dir()
        assert result.commit_sha == "sha-1234567890abcdef"
        assert len(build_called_with_timeout) == 1
        assert build_called_with_timeout[0] == 45.0


@pytest.mark.asyncio
async def test_build_target_actual_subprocess_timeout_enforcement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify _build_target cleanly terminates when a build command exceeds CRASHWISE_BUILD_TIMEOUT."""
    monkeypatch.setenv("CRASHWISE_BUILD_TIMEOUT", "1")
    get_settings.cache_clear()

    # Create dummy project
    workdir = tmp_path / "slow_project"
    workdir.mkdir()
    (workdir / "Makefile").write_text("all:\n\tsleep 10\n")

    mock_profile = DiscoveredProfile(
        name="slow_project",
        language="c",
        build_system="make",
        build_command="sleep 10",
        output_dir="build",
    )

    with patch("crashwise.core.discovery.discover_project", return_value=mock_profile):
        # Should gracefully timeout in ~1 second rather than 10 seconds, without raising an unhandled exception
        start_time = asyncio.get_event_loop().time()
        await _build_target(workdir=workdir, sanitizers="address")
        elapsed = asyncio.get_event_loop().time() - start_time
        assert elapsed < 5.0, f"Expected timeout after ~1s, took {elapsed:.2f}s"


def test_non_interactive_configure_writes_workdir_and_timeout(tmp_path: Path) -> None:
    """Verify run_configure_non_interactive persists CRASHWISE_WORKDIR and CRASHWISE_BUILD_TIMEOUT."""
    env_file = tmp_path / "custom.env"
    run_configure_non_interactive(
        env_path=env_file,
        workdir=Path("/var/custom_fuzz_work"),
        build_timeout=1500,
        api_port=8080,
    )
    content = env_file.read_text()
    assert "CRASHWISE_WORKDIR=/var/custom_fuzz_work" in content
    assert "CRASHWISE_BUILD_TIMEOUT=1500" in content
    assert "CRASHWISE_API_PORT=8080" in content


# ══════════════════════════════════════════════════════════════════════════════
# 2. docker-compose.yaml Parameterization & Syntax Empirical Tests
# ══════════════════════════════════════════════════════════════════════════════


def test_docker_compose_file_exists_and_parses_as_yaml() -> None:
    """Verify docker-compose.yaml is well-formed YAML without interpolation errors."""
    compose_path = Path("docker-compose.yaml")
    assert compose_path.is_file(), "docker-compose.yaml must exist at project root"

    content = compose_path.read_text(encoding="utf-8")
    # Verify ${VAR:-default} pattern is used throughout
    interpolations = re.findall(r"\$\{([A-Za-z0-9_]+):-([^}]*)\}", content)
    assert len(interpolations) >= 15, f"Expected >= 15 parameterized vars, found {len(interpolations)}"

    # Parse raw text (treating ${...} as literal strings)
    parsed = yaml.safe_load(content)
    assert "services" in parsed
    assert "temporal-server" in parsed["services"]
    assert "postgres" in parsed["services"]
    assert "redis" in parsed["services"]
    assert "minio" in parsed["services"]
    assert "api" in parsed["services"]
    assert "dashboard" in parsed["services"]
    assert "worker" in parsed["services"]


def test_docker_compose_config_cli_with_default_env() -> None:
    """Verify `docker compose config` evaluates successfully with defaults."""
    clean_env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
    res = subprocess.run(
        ["docker", "compose", "config"],
        capture_output=True,
        text=True,
        env=clean_env,
    )
    assert res.returncode == 0, f"`docker compose config` failed:\n{res.stderr}"
    config = yaml.safe_load(res.stdout)

    services = config["services"]
    # Check default postgres credentials
    assert services["postgres"]["environment"]["POSTGRES_PASSWORD"] == "temporal"
    assert services["postgres"]["environment"]["POSTGRES_USER"] == "temporal"
    assert services["postgres"]["environment"]["POSTGRES_DB"] == "temporal"

    # Check temporal server default postgres credentials
    assert services["temporal-server"]["environment"]["POSTGRES_PWD"] == "temporal"
    assert services["temporal-server"]["environment"]["POSTGRES_USER"] == "temporal"

    # Check api and worker DATABASE_URL defaults
    assert (
        services["api"]["environment"]["DATABASE_URL"]
        == "postgresql+asyncpg://temporal:temporal@postgres:5432/temporal"
    )
    assert (
        services["worker"]["environment"]["DATABASE_URL"]
        == "postgresql+asyncpg://temporal:temporal@postgres:5432/temporal"
    )

    # Check workdir and build timeout defaults
    assert services["api"]["environment"]["CRASHWISE_WORKDIR"] == "/tmp/crashwise"
    assert services["api"]["environment"]["CRASHWISE_BUILD_TIMEOUT"] == "900"
    assert services["worker"]["environment"]["CRASHWISE_WORKDIR"] == "/tmp/crashwise"
    assert services["worker"]["environment"]["CRASHWISE_BUILD_TIMEOUT"] == "900"


def test_docker_compose_config_cli_with_custom_env_overrides() -> None:
    """Verify `docker compose config` evaluates with custom environment variables."""
    clean_env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
    custom_env = {
        **clean_env,
        "POSTGRES_PASSWORD": "super_secret_pw_99",
        "POSTGRES_USER": "custom_admin",
        "POSTGRES_DB": "crashwise_prod",
        "POSTGRES_PORT": "5439",
        "TEMPORAL_PORT": "7239",
        "TEMPORAL_UI_PORT": "8239",
        "TEMPORAL_CORS_ORIGINS": "https://app.crashwise.corp",
        "REDIS_PORT": "6389",
        "MINIO_PORT": "9019",
        "MINIO_CONSOLE_PORT": "9029",
        "MINIO_ROOT_USER": "minio_admin",
        "MINIO_ROOT_PASSWORD": "minio_secret_password",
        "CRASHWISE_API_PORT": "8009",
        "DASHBOARD_PORT": "3009",
        "CRASHWISE_WORKDIR": "/srv/fuzz/crashwise_work",
        "CRASHWISE_BUILD_TIMEOUT": "1200",
    }

    res = subprocess.run(
        ["docker", "compose", "config"],
        capture_output=True,
        text=True,
        env=custom_env,
    )
    assert res.returncode == 0, f"`docker compose config` with custom env failed:\n{res.stderr}"
    config = yaml.safe_load(res.stdout)
    services = config["services"]

    # Verify postgres service
    assert services["postgres"]["environment"]["POSTGRES_PASSWORD"] == "super_secret_pw_99"
    assert services["postgres"]["environment"]["POSTGRES_USER"] == "custom_admin"
    assert services["postgres"]["environment"]["POSTGRES_DB"] == "crashwise_prod"

    # Verify temporal-server receives overridden credentials
    assert services["temporal-server"]["environment"]["POSTGRES_PWD"] == "super_secret_pw_99"
    assert services["temporal-server"]["environment"]["POSTGRES_USER"] == "custom_admin"

    # Verify temporal-ui cors origins
    assert services["temporal-ui"]["environment"]["TEMPORAL_CORS_ORIGINS"] == "https://app.crashwise.corp"

    # Verify api & worker DATABASE_URL propagates the overridden credentials
    expected_db_url = "postgresql+asyncpg://custom_admin:super_secret_pw_99@postgres:5432/crashwise_prod"
    assert services["api"]["environment"]["DATABASE_URL"] == expected_db_url
    assert services["worker"]["environment"]["DATABASE_URL"] == expected_db_url

    # Verify workdir and build timeout
    assert services["api"]["environment"]["CRASHWISE_WORKDIR"] == "/srv/fuzz/crashwise_work"
    assert services["api"]["environment"]["CRASHWISE_BUILD_TIMEOUT"] == "1200"
    assert services["worker"]["environment"]["CRASHWISE_WORKDIR"] == "/srv/fuzz/crashwise_work"
    assert services["worker"]["environment"]["CRASHWISE_BUILD_TIMEOUT"] == "1200"

    # Verify minio credentials
    assert services["minio"]["environment"]["MINIO_ROOT_USER"] == "minio_admin"
    assert services["minio"]["environment"]["MINIO_ROOT_PASSWORD"] == "minio_secret_password"

    # Verify published ports
    ports_by_service = {
        name: [p.get("published") for p in s.get("ports", [])]
        for name, s in services.items()
    }
    assert "5439" in ports_by_service["postgres"]
    assert "7239" in ports_by_service["temporal-server"]
    assert "8239" in ports_by_service["temporal-ui"]
    assert "6389" in ports_by_service["redis"]
    assert "9019" in ports_by_service["minio"]
    assert "9029" in ports_by_service["minio"]
    assert "8009" in ports_by_service["api"]
    assert "3009" in ports_by_service["dashboard"]


def test_docker_compose_direct_database_url_override() -> None:
    """Verify that an explicit DATABASE_URL overrides the composite postgres URL."""
    clean_env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
    custom_env = {
        **clean_env,
        "DATABASE_URL": "postgresql+asyncpg://external_user:ext_pass@external_host:5432/external_db",
    }
    res = subprocess.run(
        ["docker", "compose", "config"],
        capture_output=True,
        text=True,
        env=custom_env,
    )
    assert res.returncode == 0, f"`docker compose config` failed:\n{res.stderr}"
    config = yaml.safe_load(res.stdout)
    services = config["services"]

    assert (
        services["api"]["environment"]["DATABASE_URL"]
        == "postgresql+asyncpg://external_user:ext_pass@external_host:5432/external_db"
    )
    assert (
        services["worker"]["environment"]["DATABASE_URL"]
        == "postgresql+asyncpg://external_user:ext_pass@external_host:5432/external_db"
    )
