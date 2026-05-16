# SPDX-License-Identifier: MIT
"""Activity to update campaign status in the database."""
from __future__ import annotations

from temporalio import activity

from crashwise.core.database import get_session
from crashwise.core.logging import get_logger

log = get_logger(__name__)


@activity.defn
async def update_campaign_status(payload: dict) -> None:
    """Update campaign status and optional run_count in the DB."""
    from uuid import UUID
    from sqlalchemy import update
    from crashwise.core.database import Campaign

    campaign_id = payload["campaign_id"]
    status = payload["status"]

    async with get_session() as session:
        stmt = update(Campaign).where(Campaign.id == UUID(campaign_id)).values(status=status)
        await session.execute(stmt)
        await session.commit()

    log.info("update_campaign_status", campaign_id=campaign_id, status=status)
