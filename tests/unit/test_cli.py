# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the CrashWise CLI (crashwise/cli.py)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
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
        mock_init.assert_awaited_once_with(drop_all=False)
        mock_close.assert_awaited_once()


def test_init_force_recreate() -> None:
    with patch("crashwise.cli.init_db", new_callable=AsyncMock) as mock_init, \
         patch("crashwise.cli.close_db", new_callable=AsyncMock) as mock_close:
        result = runner.invoke(app, ["init", "--force"])
        assert result.exit_code == 0
        assert "recreated successfully" in result.output
        mock_init.assert_awaited_once_with(drop_all=True)


# ── run command ──────────────────────────────────────────────────────────────


def test_run_submits_workflow() -> None:
    mock_result = MagicMock()
    mock_result.model_dump_json.return_value = '{"status": "ok"}'

    with patch("crashwise.cli.execute_main_workflow", new_callable=AsyncMock, return_value=mock_result) as mock_exec:
        result = runner.invoke(app, [
            "run",
            "https://github.com/example/target",
            "--fuzzer", "libfuzzer",
            "--timeout", "120",
            "--branch", "main",
            "--sanitizers", "address",
        ])
        assert result.exit_code == 0
        assert "Submitting MainFuzzingWorkflow" in result.output
        assert "Workflow result" in result.output
        mock_exec.assert_awaited_once()


def test_run_temporal_connection_error() -> None:
    from crashwise.orchestration.client import TemporalConnectionError

    with patch("crashwise.cli.execute_main_workflow", new_callable=AsyncMock, side_effect=TemporalConnectionError("down")):
        result = runner.invoke(app, ["run", "https://github.com/example/target"])
        assert result.exit_code == 1
        assert "Temporal connection failed" in result.output


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


def test_dashboard_launches_streamlit() -> None:
    with patch("crashwise.cli.subprocess.run") as mock_run:
        result = runner.invoke(app, ["dashboard"])
        assert result.exit_code == 0
        mock_run.assert_called_once()
        cmd_list = mock_run.call_args.args[0]
        assert any("streamlit" in str(x) for x in cmd_list)
        assert any("app.py" in str(x) for x in cmd_list)


def test_dashboard_with_api_url() -> None:
    with patch("crashwise.cli.subprocess.run") as mock_run:
        result = runner.invoke(app, ["dashboard", "--api-url", "http://api:8000"])
        assert result.exit_code == 0
        mock_run.assert_called_once()
        env = mock_run.call_args.kwargs["env"]
        assert env["CRASHWISE_API_URL"] == "http://api:8000"


def test_dashboard_not_found() -> None:
    with patch("pathlib.Path.exists", return_value=False):
        result = runner.invoke(app, ["dashboard"])
        assert result.exit_code == 1
        assert "Dashboard not found" in result.output
