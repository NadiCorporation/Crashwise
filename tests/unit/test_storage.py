# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the distributed storage layer (Phase 9).

Uses mocks (not moto) so the suite stays fast and requires no
infrastructure.  The real R2 integration is validated via integration
tests that run against a live bucket.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from crashwise.core.storage import (
    download_file,
    list_objects,
    sync_directory,
    upload_bytes,
    upload_file,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _disable_r2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure R2 is disabled so we exercise the passthrough path."""
    monkeypatch.setenv("R2_ENABLED", "false")
    # Clear the settings cache so monkeypatch takes effect.
    from crashwise.core.config import get_settings

    get_settings.cache_clear()


# ── Passthrough tests (R2 disabled) ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_upload_file_passthrough(tmp_path: Path) -> None:
    """When R2 is disabled, upload_file returns the key immediately."""
    local = tmp_path / "test.txt"
    local.write_text("hello")
    result = await upload_file(local, "campaigns/test/test.txt")
    assert result == "campaigns/test/test.txt"


@pytest.mark.asyncio
async def test_download_file_passthrough(tmp_path: Path) -> None:
    """When R2 is disabled, download_file returns the local path."""
    dest = tmp_path / "downloaded.txt"
    result = await download_file("campaigns/test/test.txt", dest)
    assert result == dest


@pytest.mark.asyncio
async def test_list_objects_passthrough() -> None:
    """When R2 is disabled, list_objects returns an empty list."""
    result = await list_objects("campaigns/test/")
    assert result == []


@pytest.mark.asyncio
async def test_sync_directory_down_passthrough(tmp_path: Path) -> None:
    """When R2 is disabled, sync_directory returns an empty list."""
    result = await sync_directory(tmp_path, "campaigns/test/corpus", direction="down")
    assert result == []


@pytest.mark.asyncio
async def test_sync_directory_up_passthrough(tmp_path: Path) -> None:
    """When R2 is disabled, sync_directory returns an empty list."""
    result = await sync_directory(tmp_path, "campaigns/test/corpus", direction="up")
    assert result == []


@pytest.mark.asyncio
async def test_upload_bytes_passthrough() -> None:
    """When R2 is disabled, upload_bytes returns the key immediately."""
    result = await upload_bytes(b"raw data", "campaigns/test/seed.bin")
    assert result == "campaigns/test/seed.bin"


# ── Mocked R2 tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_upload_file_with_r2_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When R2 is enabled, upload_file calls boto3 put_object."""
    from crashwise.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("R2_ENABLED", "true")
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "test-key")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("R2_ACCOUNT_ID", "test-account")

    mock_client = AsyncMock()
    mock_session = MagicMock()
    mock_session.client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_session.client.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("crashwise.core.storage.aioboto3.Session", return_value=mock_session):
        local = tmp_path / "test.txt"
        local.write_text("hello")
        result = await upload_file(local, "campaigns/test/test.txt")

    assert result == "campaigns/test/test.txt"
    mock_client.put_object.assert_called_once()
    call_kwargs = mock_client.put_object.call_args.kwargs
    assert call_kwargs["Bucket"] == "crashwise"
    assert call_kwargs["Key"] == "campaigns/test/test.txt"


@pytest.mark.asyncio
async def test_download_file_with_r2_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When R2 is enabled, download_file calls boto3 get_object."""
    from crashwise.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("R2_ENABLED", "true")
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "test-key")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("R2_ACCOUNT_ID", "test-account")

    mock_body = AsyncMock()
    mock_body.read.return_value = b"downloaded content"
    mock_stream = AsyncMock()
    mock_stream.__aenter__ = AsyncMock(return_value=mock_body)
    mock_stream.__aexit__ = AsyncMock(return_value=False)

    mock_client = AsyncMock()
    mock_client.get_object.return_value = {"Body": mock_stream}
    mock_session = MagicMock()
    mock_session.client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_session.client.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("crashwise.core.storage.aioboto3.Session", return_value=mock_session):
        dest = tmp_path / "downloaded.txt"
        result = await download_file("campaigns/test/test.txt", dest)

    assert result == dest
    assert dest.read_bytes() == b"downloaded content"
    mock_client.get_object.assert_called_once()


@pytest.mark.asyncio
async def test_list_objects_with_r2_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """When R2 is enabled, list_objects paginates correctly."""
    from crashwise.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("R2_ENABLED", "true")
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "test-key")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("R2_ACCOUNT_ID", "test-account")

    async def _mock_paginate(*args, **kwargs):
        yield {"Contents": [{"Key": "a"}, {"Key": "b"}]}

    mock_paginator = MagicMock()
    mock_paginator.paginate = _mock_paginate

    mock_client = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator
    mock_session = MagicMock()
    mock_session.client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_session.client.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("crashwise.core.storage.aioboto3.Session", return_value=mock_session):
        result = await list_objects("campaigns/test/")

    assert result == ["a", "b"]


@pytest.mark.asyncio
async def test_sync_directory_up_with_r2_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When R2 is enabled, sync_directory uploads local files."""
    from crashwise.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("R2_ENABLED", "true")
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "test-key")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("R2_ACCOUNT_ID", "test-account")

    (tmp_path / "seed1.seed").write_bytes(b"seed1")
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "seed2.seed").write_bytes(b"seed2")

    mock_client = AsyncMock()
    mock_session = MagicMock()
    mock_session.client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_session.client.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("crashwise.core.storage.aioboto3.Session", return_value=mock_session):
        result = await sync_directory(tmp_path, "campaigns/test/corpus", direction="up")

    assert len(result) == 2
    assert mock_client.put_object.call_count == 2


@pytest.mark.asyncio
async def test_sync_directory_down_with_r2_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When R2 is enabled, sync_directory downloads from R2."""
    from crashwise.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("R2_ENABLED", "true")
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "test-key")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("R2_ACCOUNT_ID", "test-account")

    mock_body = AsyncMock()
    mock_body.read.return_value = b"seed data"
    mock_stream = AsyncMock()
    mock_stream.__aenter__ = AsyncMock(return_value=mock_body)
    mock_stream.__aexit__ = AsyncMock(return_value=False)

    async def _mock_get_object(*args, **kwargs):
        return {"Body": mock_stream}

    mock_client = MagicMock()
    mock_client.get_object = _mock_get_object

    async def _mock_paginate(*args, **kwargs):
        yield {"Contents": [{"Key": "campaigns/test/corpus/seed1.seed"}]}

    mock_paginator = MagicMock()
    mock_paginator.paginate = _mock_paginate
    mock_client.get_paginator.return_value = mock_paginator

    mock_session = MagicMock()
    mock_session.client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_session.client.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("crashwise.core.storage.aioboto3.Session", return_value=mock_session):
        result = await sync_directory(tmp_path, "campaigns/test/corpus", direction="down")

    assert len(result) == 1
    assert result[0].read_bytes() == b"seed data"
