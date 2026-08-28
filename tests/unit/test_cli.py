# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the CrashWise CLI (crashwise/cli.py)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from crashwise.cli import app

runner = CliRunner()


# ── Meta commands ────────────────────────────────────────────────────────────


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "crashwise" in result.output


def test_info() -> None:
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "CrashWise" in result.output
    assert "temporal" in result.output
    assert "db_url" in result.output


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    # Typer with no_args_is_help=True shows help.
    assert result.exit_code in (0, 2)
    assert "Usage:" in result.output


# ── init command ─────────────────────────────────────────────────────────────


def test_init_creates_tables() -> None:
    with patch("crashwise.cli.init_db", new_callable=AsyncMock) as mock_init, \
         patch("crashwise.cli.close_db", new_callable=AsyncMock) as mock_close:
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "created successfully" in result.output
        mock_init.assert_awaited_once_with(drop=False)
        mock_close.assert_awaited_once()


def test_init_force_recreate() -> None:
    with patch("crashwise.cli.init_db", new_callable=AsyncMock) as mock_init, \
         patch("crashwise.cli.close_db", new_callable=AsyncMock) as _mock_close, \
         patch("crashwise.core.discovery.discover_project", return_value=None), \
         patch("crashwise.core.discovery.DiscoveredProfile"):
        result = runner.invoke(app, ["init", "--db-force"])
        assert result.exit_code == 0
        assert "recreated successfully" in result.output
        mock_init.assert_awaited_once_with(drop=True)


# ── run command ──────────────────────────────────────────────────────────────


def test_run_submits_workflow() -> None:
    """The ``run`` command submits a MainFuzzingWorkflow.

    Pre-flight is skipped via ``--skip-preflight`` so this test does not
    depend on Docker / clang / gcc being installed on the CI host. The
    API submission is stubbed to fail so the command falls through to the
    direct Temporal path.
    """
    mock_handle = MagicMock()
    mock_handle.id = "crashwise-test-123"

    with patch("httpx.AsyncClient", side_effect=Exception("no api")), \
         patch("crashwise.cli.connect", new_callable=AsyncMock) as mock_connect, \
         patch("crashwise.cli.start_main_workflow", new_callable=AsyncMock, return_value=mock_handle) as mock_start:
        result = runner.invoke(app, [
            "run",
            "https://github.com/example/target",
            "--fuzzer", "libfuzzer",
            "--timeout", "120",
            "--branch", "main",
            "--sanitizers", "address",
            "--skip-preflight",
            "--detach",
        ])
        assert result.exit_code == 0
        assert "Submitting MainFuzzingWorkflow" in result.output
        assert "Workflow submitted (direct)" in result.output
        mock_start.assert_awaited_once()
        mock_connect.assert_awaited_once()


def test_run_temporal_connection_error() -> None:
    from crashwise.orchestration.client import TemporalConnectionError

    with patch("httpx.AsyncClient", side_effect=Exception("no api")), \
         patch("crashwise.cli.connect", new_callable=AsyncMock, side_effect=TemporalConnectionError("down")):
        result = runner.invoke(app, [
            "run",
            "https://github.com/example/target",
            "--skip-preflight",
        ])
        assert result.exit_code == 1
        assert "Temporal connection failed" in result.output


def test_run_preflight_blocks_when_docker_missing() -> None:
    """T4: the ``run`` command must refuse to submit when a critical
    dependency (Docker / Clang / GCC) is missing, rather than crashing
    inside Temporal five minutes later.
    """
    from crashwise.core.sentinel import (
        CheckResult,
        CheckStatus,
        SentinelReport,
    )

    fake_report = SentinelReport(
        host="testhost",
        platform="Linux",
        checks=[
            CheckResult(
                "runtime.docker",
                CheckStatus.FAIL,
                "Docker is not installed.",
                remediation="Install: sudo pacman -S docker",
            ),
            CheckResult("build.clang", CheckStatus.OK, "Clang found."),
            CheckResult("build.gcc", CheckStatus.OK, "GCC found."),
        ],
    )

    with patch(
        "crashwise.core.sentinel.run_all_checks",
        new_callable=AsyncMock,
        return_value=fake_report,
    ), patch(
        "crashwise.cli.start_main_workflow", new_callable=AsyncMock
    ) as mock_start:
        result = runner.invoke(app, ["run", "https://github.com/example/target"])
        assert result.exit_code == 1
        assert "Pre-flight failed" in result.output
        assert "runtime.docker" in result.output
        # Critical: the workflow must NOT have been submitted.
        mock_start.assert_not_called()


# ── worker command ───────────────────────────────────────────────────────────


def test_worker_starts() -> None:
    with patch("crashwise.cli.run_worker", new_callable=AsyncMock) as mock_run:
        result = runner.invoke(app, ["worker"])
        assert result.exit_code == 0
        mock_run.assert_awaited_once_with(host=None, namespace=None, task_queue=None)


def test_worker_with_options() -> None:
    with patch("crashwise.cli.run_worker", new_callable=AsyncMock) as mock_run:
        result = runner.invoke(app, [
            "worker",
            "--host", "temporal:7233",
            "--namespace", "prod",
            "--task-queue", "custom-queue",
        ])
        assert result.exit_code == 0
        mock_run.assert_awaited_once_with(host="temporal:7233", namespace="prod", task_queue="custom-queue")


def test_worker_temporal_connection_error() -> None:
    from crashwise.orchestration.client import TemporalConnectionError

    with patch("crashwise.cli.run_worker", new_callable=AsyncMock, side_effect=TemporalConnectionError("down")):
        result = runner.invoke(app, ["worker"])
        assert result.exit_code == 1
        assert "Temporal connection failed" in result.output


# ── api command ──────────────────────────────────────────────────────────────


def test_api_launches_uvicorn() -> None:
    with patch("crashwise.cli.uvicorn.run") as mock_run:
        result = runner.invoke(app, ["api"])
        assert result.exit_code == 0
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["host"] == "0.0.0.0"
        assert call_kwargs["port"] == 8000
        assert call_kwargs["workers"] == 1


def test_api_with_custom_port_and_reload() -> None:
    with patch("crashwise.cli.uvicorn.run") as mock_run:
        result = runner.invoke(app, ["api", "--port", "8080", "--reload"])
        assert result.exit_code == 0
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["port"] == 8080
        assert call_kwargs["reload"] is True
        assert call_kwargs["workers"] == 1  # reload forces single worker


# ── dashboard command ────────────────────────────────────────────────────────


def test_dashboard_launches_unified_server() -> None:
    with patch("crashwise.cli.uvicorn.run") as mock_uvicorn:
        result = runner.invoke(app, ["dashboard", "--no-open"])
        assert result.exit_code == 0
        mock_uvicorn.assert_called_once()
        call_kwargs = mock_uvicorn.call_args.kwargs
        assert call_kwargs["host"] == "0.0.0.0"
        assert call_kwargs["port"] == 8000


def test_dashboard_ui_alias() -> None:
    with patch("crashwise.cli.uvicorn.run") as mock_uvicorn:
        result = runner.invoke(app, ["ui", "--port", "9000", "--no-open"])
        assert result.exit_code == 0
        mock_uvicorn.assert_called_once()
        call_kwargs = mock_uvicorn.call_args.kwargs
        assert call_kwargs["port"] == 9000


def test_dashboard_dev_mode() -> None:
    with patch("crashwise.cli.subprocess.run") as mock_run:
        result = runner.invoke(app, ["dashboard", "--dev", "--port", "3000"])
        assert result.exit_code == 0
        mock_run.assert_called_once()
        cmd_list = mock_run.call_args.args[0]
        assert "npm" in cmd_list[0]
        assert "dev" in cmd_list

