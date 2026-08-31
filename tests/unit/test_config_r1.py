# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Config & Path Parameterization R1 upgrades."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from crashwise.core.config import Settings, get_settings
from crashwise.orchestration.activities.healing_activities import (
    _allocate_workspace,
    _get_healing_workspace_root,
)
from crashwise.orchestration.activities.setup_target import _get_build_timeout


def test_settings_workdir_and_timeout_defaults() -> None:
    """Verify default values for workdir and build timeout."""
    settings = Settings(_env_file=None)
    assert settings.crashwise_workdir == Path("/tmp/crashwise")
    assert settings.crashwise_build_timeout == 900


def test_settings_workdir_and_timeout_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify CRASHWISE_WORKDIR and CRASHWISE_BUILD_TIMEOUT environment overrides."""
    monkeypatch.setenv("CRASHWISE_WORKDIR", "/custom/workdir/path")
    monkeypatch.setenv("CRASHWISE_BUILD_TIMEOUT", "1800")

    settings = Settings(_env_file=None)
    assert settings.crashwise_workdir == Path("/custom/workdir/path")
    assert settings.crashwise_build_timeout == 1800


def test_setup_target_get_build_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify _get_build_timeout reads from settings."""
    monkeypatch.setenv("CRASHWISE_BUILD_TIMEOUT", "450")
    get_settings.cache_clear()
    try:
        assert _get_build_timeout() == 450.0
    finally:
        get_settings.cache_clear()


def test_healing_workspace_root_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify healing workspace root respects crashwise_workdir."""
    custom_dir = tmp_path / "custom_healing_root"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(custom_dir))
    get_settings.cache_clear()
    try:
        root = _get_healing_workspace_root()
        assert root == custom_dir / "healing"

        allocated = _allocate_workspace("campaign-123", mode="repair")
        assert allocated == custom_dir / "healing" / "repair" / "campaign-123"
        assert allocated.exists()
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_setup_target_activity_uses_configured_workdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify setup_target activity initializes workdir under crashwise_workdir."""
    from crashwise.core.models import SetupTargetInput
    from crashwise.orchestration.activities.setup_target import setup_target

    custom_root = tmp_path / "custom_root"
    monkeypatch.setenv("CRASHWISE_WORKDIR", str(custom_root))
    get_settings.cache_clear()

    input_payload = SetupTargetInput(
        target_repo="https://github.com/example/libtest.git",
        target_branch="main",
        sanitizers="address",
        synthesize_harness=False,
    )

    mock_info = MagicMock()
    mock_info.workflow_id = "test-wf-42"
    mock_info.attempt = 1

    with patch("temporalio.activity.info", return_value=mock_info), patch(
        "crashwise.orchestration.activities.setup_target._clone_repo",
        return_value="abcdef123456",
    ), patch(
        "crashwise.orchestration.activities.setup_target._build_target"
    ), patch(
        "crashwise.orchestration.activities.setup_target._detect_existing_harness",
        return_value=None,
    ):
        result = await setup_target(input_payload)
        expected_target_dir = custom_root / "test-wf-42" / "target"
        assert result.workdir == expected_target_dir
        assert expected_target_dir.exists()
