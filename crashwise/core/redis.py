# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Distributed state via Redis — global counters and deduplication cache.

Provides a thin async wrapper around ``redis-py`` for:

* **Global execution counter** — real-time fuzzer exec/sec across all workers.
* **Deduplication cache** — fast ``stack_hash`` lookup before DB writes.
* **Worker heartbeat** — ephemeral keys showing which workers are alive.

When ``redis_enabled`` is ``False`` (default), all operations are
no-ops that return sensible defaults — keeping local dev fast.
"""

from __future__ import annotations

import time
from typing import Any

import redis.asyncio as redis

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# ── Connection pool (lazy) ───────────────────────────────────────────────────
_pool: redis.Redis | None = None


def _get_pool() -> redis.Redis:
    """Return a cached Redis connection pool."""
    global _pool
    if _pool is None:
        settings = get_settings()
        _pool = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            health_check_interval=30,
        )
    return _pool


# ── Public API ───────────────────────────────────────────────────────────────


async def _check_enabled() -> bool:
    """Return whether Redis is configured and reachable."""
    settings = get_settings()
    if not settings.redis_enabled:
        return False
    try:
        pool = _get_pool()
        await pool.ping()
        return True
    except Exception:
        log.warning("redis.unreachable", url=settings.redis_url)
        return False


# ── Global counters ──────────────────────────────────────────────────────────


async def incr_exec_counter(
    campaign_id: str,
    count: int = 1,
    *,
    ttl: int = 3600,
) -> int:
    """Increment the global execution counter for a campaign.

    Returns
    -------
    The new counter value.
    """
    if not await _check_enabled():
        return 0

    pool = _get_pool()
    key = f"crashwise:counter:exec:{campaign_id}"
    new_val = await pool.incrby(key, count)
    await pool.expire(key, ttl)
    return int(new_val)


async def get_exec_counter(campaign_id: str) -> int:
    """Get the current global execution counter for a campaign."""
    if not await _check_enabled():
        return 0

    pool = _get_pool()
    key = f"crashwise:counter:exec:{campaign_id}"
    val = await pool.get(key)
    return int(val) if val else 0


async def incr_crash_counter(
    campaign_id: str,
    count: int = 1,
    *,
    ttl: int = 3600,
) -> int:
    """Increment the global crash counter for a campaign."""
    if not await _check_enabled():
        return 0

    pool = _get_pool()
    key = f"crashwise:counter:crash:{campaign_id}"
    new_val = await pool.incrby(key, count)
    await pool.expire(key, ttl)
    return int(new_val)


async def get_crash_counter(campaign_id: str) -> int:
    """Get the current global crash counter for a campaign."""
    if not await _check_enabled():
        return 0

    pool = _get_pool()
    key = f"crashwise:counter:crash:{campaign_id}"
    val = await pool.get(key)
    return int(val) if val else 0


# ── Deduplication cache ──────────────────────────────────────────────────────


async def is_stack_hash_known(
    campaign_id: str,
    stack_hash: str,
    *,
    ttl: int = 86_400,
) -> bool:
    """Check if a stack hash has been seen before for this campaign.

    Uses a Redis Set for O(1) membership testing.

    Parameters
    ----------
    campaign_id:
        Campaign identifier.
    stack_hash:
        SHA256 stack trace hash.
    ttl:
        Expiration for the dedup set (seconds).

    Returns
    -------
    ``True`` if the hash was already in the set (duplicate).
    """
    if not stack_hash or not await _check_enabled():
        return False

    pool = _get_pool()
    key = f"crashwise:dedup:{campaign_id}"
    was_member = await pool.sismember(key, stack_hash)
    if was_member:
        return True

    # Add it now so future calls see it.
    await pool.sadd(key, stack_hash)
    await pool.expire(key, ttl)
    return False


async def clear_dedup_cache(campaign_id: str) -> None:
    """Clear the deduplication cache for a campaign."""
    if not await _check_enabled():
        return

    pool = _get_pool()
    key = f"crashwise:dedup:{campaign_id}"
    await pool.delete(key)


# ── Worker heartbeat ─────────────────────────────────────────────────────────


async def heartbeat(
    worker_name: str | None = None,
    *,
    ttl: int = 60,
) -> None:
    """Register this worker as alive.

    Writes an ephemeral key that auto-expires.  Other services can
    scan ``crashwise:worker:*`` to discover active workers.
    """
    if not await _check_enabled():
        return

    settings = get_settings()
    name = worker_name or settings.worker_name
    pool = _get_pool()
    key = f"crashwise:worker:{name}"
    await pool.setex(key, ttl, str(time.time()))


async def list_active_workers(
    *,
    pattern: str = "crashwise:worker:*",
) -> list[str]:
    """Return the names of currently alive workers."""
    if not await _check_enabled():
        return []

    pool = _get_pool()
    keys = await pool.keys(pattern)
    return [k.decode().split(":")[-1] if isinstance(k, bytes) else k.split(":")[-1] for k in keys]


# ── Campaign state ───────────────────────────────────────────────────────────


async def set_campaign_state(
    campaign_id: str,
    state: dict[str, Any],
    *,
    ttl: int = 3600,
) -> None:
    """Store ephemeral campaign state in Redis (JSON serialised)."""
    if not await _check_enabled():
        return

    import json

    pool = _get_pool()
    key = f"crashwise:state:{campaign_id}"
    await pool.setex(key, ttl, json.dumps(state))


async def get_campaign_state(campaign_id: str) -> dict[str, Any] | None:
    """Retrieve ephemeral campaign state from Redis."""
    if not await _check_enabled():
        return None

    import json

    pool = _get_pool()
    key = f"crashwise:state:{campaign_id}"
    raw = await pool.get(key)
    if raw is None:
        return None
    return json.loads(raw)  # type: ignore[no-any-return]


__all__ = [
    "incr_exec_counter",
    "get_exec_counter",
    "incr_crash_counter",
    "get_crash_counter",
    "is_stack_hash_known",
    "clear_dedup_cache",
    "heartbeat",
    "list_active_workers",
    "set_campaign_state",
    "get_campaign_state",
]
