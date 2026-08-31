# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Phase 0 smoke tests — verify the package imports and the CLI is wired."""

from __future__ import annotations

from typer.testing import CliRunner

import crashwise
from crashwise.cli import app


def test_package_version() -> None:
    assert crashwise.__version__ == "0.2.0.dev0"


def test_cli_version_command() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "crashwise 0.2.0.dev0" in result.stdout


def test_cli_info_command() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "CrashWise" in result.stdout
    assert "temporal" in result.stdout.lower()


def test_cli_help_lists_phase1_commands() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    # Phase 1 added `worker` and `run` subcommands.
    assert "worker" in result.stdout
    assert "run" in result.stdout
