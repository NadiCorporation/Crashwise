# SPDX-License-Identifier: MIT
"""Worker-side crash persistence hook.

Operation Hydra Phase 5: When the triage activity identifies a unique crash,
this hook commits it to the CrashTestCase table for the web control plane.
"""
from __future__ import annotations

from crashwise.core.logging import get_logger

log = get_logger(__name__)


async def persist_crash_to_web(
    *,
    campaign_id: str,
    crash_type: str,
    crash_state: str,
    severity: str = "unknown",
    sanitizer_log: str = "",
    gdb_backtrace: str = "",
    reproducer_path: str = "",
) -> bool:
    """Persist a deduplicated crash to the web control plane DB.

    Returns True if inserted, False if duplicate (already exists).
    Uses the unique constraint on (campaign_id, crash_type, crash_state)
    for deduplication — INSERT ON CONFLICT DO NOTHING.
    """
    from uuid import UUID

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from crashwise.core.config import get_settings
    from crashwise.web.models import CrashTestCase, FuzzingCampaign

    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    try:
        async with session_factory() as session:
            # Check for duplicate.
            existing = await session.execute(
                select(CrashTestCase).where(
                    CrashTestCase.campaign_id == UUID(campaign_id),
                    CrashTestCase.crash_type == crash_type,
                    CrashTestCase.crash_state == crash_state,
                )
            )
            if existing.scalar_one_or_none():
                return False

            crash = CrashTestCase(
                campaign_id=UUID(campaign_id),
                crash_type=crash_type,
                crash_state=crash_state,
                severity=severity,
                sanitizer_log=sanitizer_log[:10000],
                gdb_backtrace=gdb_backtrace[:5000],
                reproducer_path=reproducer_path,
                status="new",
            )
            session.add(crash)
            await session.commit()

            # Update campaign crash count.
            campaign = await session.get(FuzzingCampaign, UUID(campaign_id))
            if campaign:
                campaign.crash_count = (campaign.crash_count or 0) + 1
                await session.commit()

            log.info(
                "web.crash_persisted",
                campaign_id=campaign_id,
                crash_type=crash_type,
                crash_state=crash_state,
                severity=severity,
            )
            return True
    except Exception as exc:
        log.warning("web.crash_persist_failed", error=str(exc)[:200])
        return False
    finally:
        await engine.dispose()
