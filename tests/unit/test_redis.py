# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the Redis distributed state layer (Phase 9).

Uses mocks so the suite stays fast and requires no Redis server.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from crashwise.core.redis import (
    claim_stack_hash,
    clear_dedup_cache,
    get_campaign_state,
    get_crash_counter,
    get_exec_counter,
    heartbeat,
    incr_crash_counter,
    incr_exec_counter,
    is_stack_hash_known,
    list_active_workers,
    release_stack_hash,
    set_campaign_state,
)

# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset Redis state and settings cache before every test."""
    from crashwise.core import redis as redis_mod

    redis_mod._pool = None  # type: ignore[attr-defined]
    monkeypatch.setenv("REDIS_ENABLED", "false")
    from crashwise.core.config import get_settings

    get_settings.cache_clear()


# ── No-op tests (Redis disabled) ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_incr_exec_counter_noop() -> None:
    """When Redis is disabled, counters return 0."""
    result = await incr_exec_counter("campaign-1", count=100)
    assert result == 0


@pytest.mark.asyncio
async def test_get_exec_counter_noop() -> None:
    result = await get_exec_counter("campaign-1")
    assert result == 0


@pytest.mark.asyncio
async def test_incr_crash_counter_noop() -> None:
    result = await incr_crash_counter("campaign-1", count=5)
    assert result == 0


@pytest.mark.asyncio
async def test_get_crash_counter_noop() -> None:
    result = await get_crash_counter("campaign-1")
    assert result == 0


@pytest.mark.asyncio
async def test_is_stack_hash_known_noop() -> None:
    """When Redis is disabled, dedup always returns False."""
    result = await is_stack_hash_known("campaign-1", "deadbeef")
    assert result is False


@pytest.mark.asyncio
async def test_clear_dedup_cache_noop() -> None:
    """When Redis is disabled, clear is a no-op."""
    await clear_dedup_cache("campaign-1")  # Should not raise.


@pytest.mark.asyncio
async def test_heartbeat_noop() -> None:
    """When Redis is disabled, heartbeat is a no-op."""
    await heartbeat("worker-1")  # Should not raise.


@pytest.mark.asyncio
async def test_list_active_workers_noop() -> None:
    result = await list_active_workers()
    assert result == []


@pytest.mark.asyncio
async def test_set_campaign_state_noop() -> None:
    """When Redis is disabled, state storage is a no-op."""
    await set_campaign_state("campaign-1", {"stage": "running"})


@pytest.mark.asyncio
async def test_get_campaign_state_noop() -> None:
    result = await get_campaign_state("campaign-1")
    assert result is None


# ── Mocked Redis tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incr_exec_counter_with_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    """When Redis is enabled, incrby is called."""
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.incrby = AsyncMock(return_value=150)
    mock_pool.expire = AsyncMock(return_value=True)

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        result = await incr_exec_counter("campaign-1", count=100)

    assert result == 150
    mock_pool.incrby.assert_called_once_with("crashwise:counter:exec:campaign-1", 100)
    mock_pool.expire.assert_called_once()


@pytest.mark.asyncio
async def test_get_exec_counter_with_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.get = AsyncMock(return_value="42")

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        result = await get_exec_counter("campaign-1")

    assert result == 42
    mock_pool.get.assert_called_once_with("crashwise:counter:exec:campaign-1")


@pytest.mark.asyncio
async def test_is_stack_hash_known_new_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    """A new stack hash is unknown and the check is read-only (no SADD)."""
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.sismember = AsyncMock(return_value=False)

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        result = await is_stack_hash_known("campaign-1", "deadbeef")

    assert result is False
    mock_pool.sismember.assert_called_once_with("crashwise:dedup:campaign-1", "deadbeef")
    mock_pool.sadd.assert_not_called()


@pytest.mark.asyncio
async def test_is_stack_hash_known_duplicate(monkeypatch: pytest.MonkeyPatch) -> None:
    """A known stack hash returns True (duplicate)."""
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.sismember = AsyncMock(return_value=True)

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        result = await is_stack_hash_known("campaign-1", "deadbeef")

    assert result is True
    mock_pool.sadd.assert_not_called()


@pytest.mark.asyncio
async def test_claim_stack_hash_new(monkeypatch: pytest.MonkeyPatch) -> None:
    """A claim on an unseen hash returns True and adds it to the set."""
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.sadd = AsyncMock(return_value=1)
    mock_pool.expire = AsyncMock(return_value=True)

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        result = await claim_stack_hash("campaign-1", "deadbeef")

    assert result is True
    mock_pool.sadd.assert_called_once_with("crashwise:dedup:campaign-1", "deadbeef")
    mock_pool.expire.assert_called_once()


@pytest.mark.asyncio
async def test_claim_stack_hash_duplicate(monkeypatch: pytest.MonkeyPatch) -> None:
    """A claim on an already-seen hash returns False and does not reset TTL."""
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.sadd = AsyncMock(return_value=0)

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        result = await claim_stack_hash("campaign-1", "deadbeef")

    assert result is False
    mock_pool.expire.assert_not_called()


@pytest.mark.asyncio
async def test_claim_stack_hash_noop_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """When Redis is disabled, claims succeed (DB unique constraint guards)."""
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "false")

    result = await claim_stack_hash("campaign-1", "deadbeef")
    assert result is True


@pytest.mark.asyncio
async def test_release_stack_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    """Releasing a claim removes the member from the dedup set."""
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.srem = AsyncMock(return_value=1)

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        await release_stack_hash("campaign-1", "deadbeef")

    mock_pool.srem.assert_called_once_with("crashwise:dedup:campaign-1", "deadbeef")


@pytest.mark.asyncio
async def test_heartbeat_with_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.setex = AsyncMock(return_value=True)

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        await heartbeat("worker-1", ttl=60)

    mock_pool.setex.assert_called_once()
    call_args = mock_pool.setex.call_args
    assert call_args.args[0] == "crashwise:worker:worker-1"
    assert call_args.args[1] == 60


@pytest.mark.asyncio
async def test_list_active_workers_with_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.keys = AsyncMock(
        return_value=[
            b"crashwise:worker:worker-1",
            b"crashwise:worker:worker-2",
        ]
    )

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        result = await list_active_workers()

    assert result == ["worker-1", "worker-2"]


@pytest.mark.asyncio
async def test_campaign_state_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.setex = AsyncMock(return_value=True)
    mock_pool.get = AsyncMock(return_value='{"stage": "running", "iteration": 3}')

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        await set_campaign_state("campaign-1", {"stage": "running", "iteration": 3})
        result = await get_campaign_state("campaign-1")

    assert result == {"stage": "running", "iteration": 3}


@pytest.mark.asyncio
async def test_clear_dedup_cache_with_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    from crashwise.core import redis as redis_mod
    from crashwise.core.config import get_settings

    redis_mod._pool = None
    get_settings.cache_clear()
    monkeypatch.setenv("REDIS_ENABLED", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    mock_pool = AsyncMock()
    mock_pool.ping = AsyncMock(return_value=True)
    mock_pool.delete = AsyncMock(return_value=1)

    with patch("crashwise.core.redis.redis.from_url", return_value=mock_pool):
        await clear_dedup_cache("campaign-1")

    mock_pool.delete.assert_called_once_with("crashwise:dedup:campaign-1")
