# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Distributed state via Redis — global counters and deduplication cache.

Provides a thin async wrapper around ``redis-py`` for:

* **Global execution counter** — real-time fuzzer exec/sec across all workers.
* **Deduplication cache** — fast ``stack_hash`` lookup before DB writes.
* **Worker heartbeat** — ephemeral keys showing which workers are alive.
* **MAB state persistence** — bandit posteriors survive worker restarts.

When ``redis_enabled`` is ``False`` (default), all operations are
no-ops that return sensible defaults — keeping local dev fast.

Resilience:
* Connection pool with automatic reconnection on transient failures.
* Exponential backoff before marking Redis as unavailable.
* MAB state uses persistent keys (no TTL) — campaigns of any duration.
* Warnings (not debug) on persistence failures so operators notice.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import redis.asyncio as redis

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# ── Connection pool (lazy, with reconnection) ────────────────────────────────
_pool: redis.Redis | None = None
_last_failure_time: float = 0.0
_consecutive_failures: int = 0
_BACKOFF_BASE_SECONDS: float = 2.0
_MAX_BACKOFF_SECONDS: float = 60.0


def _get_pool() -> redis.Redis:
    """Return a cached Redis connection pool.

    The pool is configured with:
    - socket_connect_timeout: 5s (fail fast on unreachable)
    - socket_keepalive: True (detect dead connections)
    - health_check_interval: 30s (periodic liveness check)
    - retry_on_timeout: True (auto-retry on transient timeouts)
    """
    global _pool
    if _pool is None:
        settings = get_settings()
        _pool = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            health_check_interval=30,
            retry_on_timeout=True,
        )
    return _pool


async def _reset_pool() -> None:
    """Close and reset the connection pool for reconnection."""
    global _pool
    if _pool is not None:
        try:
            await _pool.close()
        except Exception:
            pass
        _pool = None


# ── Public API ───────────────────────────────────────────────────────────────


async def _check_enabled() -> bool:
    """Return whether Redis is configured and reachable.

    Uses exponential backoff to avoid hammering a downed Redis server.
    On reconnection success, resets the backoff counter.
    """
    global _last_failure_time, _consecutive_failures

    settings = get_settings()
    if not settings.redis_enabled:
        return False

    # Exponential backoff: don't retry if we recently failed.
    if _consecutive_failures > 0:
        backoff = min(
            _BACKOFF_BASE_SECONDS * (2 ** (_consecutive_failures - 1)),
            _MAX_BACKOFF_SECONDS,
        )
        if time.time() - _last_failure_time < backoff:
            return False

    try:
        pool = _get_pool()
        await pool.ping()
        # Success — reset backoff.
        if _consecutive_failures > 0:
            log.info(
                "redis.reconnected",
                after_failures=_consecutive_failures,
            )
            _consecutive_failures = 0
        return True
    except Exception as exc:
        _consecutive_failures += 1
        _last_failure_time = time.time()
        if _consecutive_failures <= 3 or _consecutive_failures % 10 == 0:
            log.warning(
                "redis.unreachable",
                url=settings.redis_url,
                failures=_consecutive_failures,
                error=str(exc)[:100],
            )
        # Try to reset the pool so next attempt gets a fresh connection.
        if _consecutive_failures >= 3:
            await _reset_pool()
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
) -> None:
    """Persist campaign state to Redis (no TTL) and database (source of truth).

    The database is the primary store; Redis is a fast-read cache.
    Long-running or paused campaigns retain state indefinitely.
    """
    import json

    state_json = json.dumps(state)

    # Always write to DB first (source of truth).
    await _save_campaign_state_to_db(campaign_id, state_json)

    if not await _check_enabled():
        return

    pool = _get_pool()
    key = f"crashwise:state:{campaign_id}"
    try:
        await pool.set(key, state_json)
    except Exception as exc:
        log.warning(
            "redis.campaign_state_save_failed",
            campaign_id=campaign_id,
            error=str(exc)[:100],
        )


async def get_campaign_state(campaign_id: str) -> dict[str, Any] | None:
    """Retrieve campaign state. Tries Redis first, falls back to database."""
    import json

    if await _check_enabled():
        pool = _get_pool()
        key = f"crashwise:state:{campaign_id}"
        try:
            raw = await pool.get(key)
            if raw is not None:
                return json.loads(raw)  # type: ignore[no-any-return]
        except Exception as exc:
            log.warning(
                "redis.campaign_state_load_failed",
                campaign_id=campaign_id,
                error=str(exc)[:100],
            )

    # Fallback: database is the source of truth.
    return await _load_campaign_state_from_db(campaign_id)


# ── MAB state persistence (Phase 21) ─────────────────────────────────────────


async def save_mab_state(
    campaign_id: str,
    mab_state_json: str,
) -> None:
    """Persist serialised MabState JSON for a campaign.

    Uses a persistent key (no TTL) so campaigns of any duration retain
    their accumulated bandit statistics. Keys are cleaned up explicitly
    when a campaign completes.

    Falls back to the database when Redis is unavailable.
    """
    if not await _check_enabled():
        # Fallback: persist to database so state survives even without Redis.
        await _save_mab_state_to_db(campaign_id, mab_state_json)
        return

    pool = _get_pool()
    key = f"crashwise:mab:{campaign_id}"
    try:
        # No TTL — campaigns can run for days/weeks.
        await pool.set(key, mab_state_json)
    except Exception as exc:
        log.warning(
            "redis.mab_save_failed",
            campaign_id=campaign_id,
            error=str(exc)[:100],
        )
        # Fallback to DB on Redis write failure.
        await _save_mab_state_to_db(campaign_id, mab_state_json)


async def load_mab_state(campaign_id: str) -> str | None:
    """Return the persisted MabState JSON or ``None`` if absent.

    Tries Redis first, falls back to database if Redis is unavailable.
    """
    if not await _check_enabled():
        # Fallback: try database.
        return await _load_mab_state_from_db(campaign_id)

    pool = _get_pool()
    key = f"crashwise:mab:{campaign_id}"
    try:
        raw = await pool.get(key)
    except Exception as exc:
        log.warning(
            "redis.mab_load_failed",
            campaign_id=campaign_id,
            error=str(exc)[:100],
        )
        return await _load_mab_state_from_db(campaign_id)

    if raw is None:
        # Redis miss — try DB (state might have been saved during a Redis outage).
        return await _load_mab_state_from_db(campaign_id)

    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


async def clear_mab_state(campaign_id: str) -> None:
    """Remove persisted MAB state for a completed campaign.

    Called at campaign completion to clean up Redis keys.
    """
    if not await _check_enabled():
        return
    pool = _get_pool()
    key = f"crashwise:mab:{campaign_id}"
    try:
        await pool.delete(key)
    except Exception:
        pass


# ── MAB database fallback ────────────────────────────────────────────────────


async def _save_campaign_state_to_db(campaign_id: str, state_json: str) -> None:
    """Persist campaign state to the database (primary source of truth)."""
    try:
        from crashwise.core.database import get_session
        from sqlalchemy import text

        async with get_session() as session:
            await session.execute(
                text(
                    "INSERT INTO campaign_kv (campaign_id, key, value) "
                    "VALUES (:cid, :key, :val) "
                    "ON CONFLICT (campaign_id, key) DO UPDATE SET value = :val"
                ),
                {"cid": campaign_id, "key": "campaign_state", "val": state_json},
            )
            await session.commit()
    except Exception as exc:
        log.warning(
            "redis.campaign_state_db_save_failed",
            campaign_id=campaign_id,
            error=str(exc)[:100],
        )


async def _load_campaign_state_from_db(campaign_id: str) -> dict[str, Any] | None:
    """Load campaign state from the database (primary source of truth)."""
    try:
        import json

        from crashwise.core.database import get_session
        from sqlalchemy import text

        async with get_session() as session:
            result = await session.execute(
                text(
                    "SELECT value FROM campaign_kv "
                    "WHERE campaign_id = :cid AND key = :key"
                ),
                {"cid": campaign_id, "key": "campaign_state"},
            )
            row = result.fetchone()
            if row:
                return json.loads(row[0])  # type: ignore[no-any-return]
    except Exception as exc:
        log.debug("redis.campaign_state_db_load_skipped", error=str(exc)[:100])
    return None


async def _save_mab_state_to_db(campaign_id: str, mab_state_json: str) -> None:
    """Persist MAB state to the database as a fallback when Redis is down."""
    try:
        from crashwise.core.database import get_session
        from sqlalchemy import text

        async with get_session() as session:
            # Use a simple key-value approach via raw SQL to avoid new models.
            await session.execute(
                text(
                    "INSERT INTO campaign_kv (campaign_id, key, value) "
                    "VALUES (:cid, :key, :val) "
                    "ON CONFLICT (campaign_id, key) DO UPDATE SET value = :val"
                ),
                {"cid": campaign_id, "key": "mab_state", "val": mab_state_json},
            )
            await session.commit()
        log.debug("redis.mab_saved_to_db", campaign_id=campaign_id)
    except Exception as exc:
        # If DB also fails, log at warning level — operator needs to know.
        log.warning(
            "redis.mab_db_fallback_failed",
            campaign_id=campaign_id,
            error=str(exc)[:100],
        )


async def _load_mab_state_from_db(campaign_id: str) -> str | None:
    """Load MAB state from the database fallback."""
    try:
        from crashwise.core.database import get_session
        from sqlalchemy import text

        async with get_session() as session:
            result = await session.execute(
                text(
                    "SELECT value FROM campaign_kv "
                    "WHERE campaign_id = :cid AND key = :key"
                ),
                {"cid": campaign_id, "key": "mab_state"},
            )
            row = result.fetchone()
            if row:
                return row[0]
    except Exception as exc:
        # Table might not exist yet (first run, migration pending).
        log.debug("redis.mab_db_load_skipped", error=str(exc)[:100])
    return None


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
    "save_mab_state",
    "load_mab_state",
    "clear_mab_state",
]
