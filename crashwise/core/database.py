# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Async SQLAlchemy persistence layer for CrashWise.

Supports SQLite (``aiosqlite``) for local development and PostgreSQL
(``asyncpg``) for production.  All operations are async via
:class:`AsyncSession`.

Usage::

    from crashwise.core.database import init_db, get_session

    await init_db()
    async with get_session() as session:
        ...
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import AsyncGenerator
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Re-export asynccontextmanager for get_session
from contextlib import asynccontextmanager

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# ── Engine & session factory (lazy initialised) ──────────────────────────────
_engine = None
_session_factory = None


class Base(DeclarativeBase):
    """Project-wide SQLAlchemy declarative base."""

    pass


# ── Table definitions ────────────────────────────────────────────────────────

class Campaign(Base):
    """Top-level fuzzing campaign."""

    __tablename__ = "campaigns"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    target_repo: Mapped[str] = mapped_column(String(512))
    target_name: Mapped[str] = mapped_column(String(128))
    fuzzer_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(tz=UTC))
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(tz=UTC),
        onupdate=lambda: datetime.now(tz=UTC),
    )

    # Relationships
    runs: Mapped[list["FuzzingRun"]] = relationship(
        back_populates="campaign",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    seeds: Mapped[list["Seed"]] = relationship(
        back_populates="campaign",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class FuzzingRun(Base):
    """A single fuzzing iteration / execution."""

    __tablename__ = "fuzzing_runs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    campaign_id: Mapped[UUID] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE")
    )
    iteration: Mapped[int] = mapped_column(default=0)
    started_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(tz=UTC))
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    executions: Mapped[int] = mapped_column(default=0)
    duration_seconds: Mapped[float] = mapped_column(default=0.0)
    coverage_edges: Mapped[int] = mapped_column(default=0)
    status: Mapped[str] = mapped_column(String(32), default="running")

    # Relationships
    campaign: Mapped[Campaign] = relationship(back_populates="runs")
    crashes: Mapped[list["Crash"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class Crash(Base):
    """A unique crash discovered during a fuzzing run."""

    __tablename__ = "crashes"
    __table_args__ = (UniqueConstraint("run_id", "stack_hash", name="uq_run_stack"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("fuzzing_runs.id", ondelete="CASCADE"),
        nullable=True,
    )
    seed_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("seeds.id", ondelete="SET NULL"),
        nullable=True,
    )
    crash_type: Mapped[str] = mapped_column(String(64), default="unknown")
    severity: Mapped[str] = mapped_column(String(32), default="unknown")
    severity_score: Mapped[int] = mapped_column(default=0)  # 0-10 exploitability
    vulnerability_type: Mapped[str] = mapped_column(String(64), default="unknown")
    suggested_patch: Mapped[str] = mapped_column(String(16384), default="")
    verification_status: Mapped[str] = mapped_column(String(32), default="pending")
    # pending | fixed | failed_verification | build_failed | error
    verification_stdout: Mapped[str] = mapped_column(String(8192), default="")
    verification_stderr: Mapped[str] = mapped_column(String(8192), default="")
    stack_trace: Mapped[str] = mapped_column(String(8192), default="")
    stack_hash: Mapped[str] = mapped_column(String(128), default="")
    signal: Mapped[str] = mapped_column(String(32), default="")
    logs_path: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(tz=UTC))
    verified_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # Phase 15: PoC generation & reachability
    poc_code: Mapped[str] = mapped_column(String(65536), default="")
    poc_compiled: Mapped[bool] = mapped_column(default=False)
    poc_verified: Mapped[bool] = mapped_column(default=False)
    reachability: Mapped[str] = mapped_column(String(32), default="unknown")
    reachability_score: Mapped[float] = mapped_column(default=0.0)
    primitive: Mapped[str] = mapped_column(String(128), default="unknown")

    # Relationships
    run: Mapped[FuzzingRun | None] = relationship(back_populates="crashes")
    seed: Mapped["Seed | None"] = relationship(back_populates="crashes")


class Seed(Base):
    """A harvested seed used to bootstrap the fuzzer corpus."""

    __tablename__ = "seeds"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    campaign_id: Mapped[UUID] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE")
    )
    seed_id: Mapped[str] = mapped_column(String(256))
    source: Mapped[str] = mapped_column(String(32))
    target_name: Mapped[str] = mapped_column(String(128))
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    description: Mapped[str] = mapped_column(String(1024), default="")
    language: Mapped[str] = mapped_column(String(32), default="")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    downloaded_path: Mapped[str] = mapped_column(String(512), default="")
    seed_path: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(tz=UTC))

    # Relationships
    campaign: Mapped[Campaign] = relationship(back_populates="seeds")
    crashes: Mapped[list[Crash]] = relationship(
        back_populates="seed",
        lazy="selectin",
    )


class CampaignKV(Base):
    """Generic key-value store for campaign-scoped ephemeral state.

    Used as a database fallback when Redis is unavailable (e.g., MAB state
    persistence). Supports ON CONFLICT upsert via the unique constraint
    on (campaign_id, key).
    """

    __tablename__ = "campaign_kv"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(String(36), index=True)
    key: Mapped[str] = mapped_column(String(64))
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(tz=UTC),
        onupdate=lambda: datetime.now(tz=UTC),
    )

    __table_args__ = (
        UniqueConstraint("campaign_id", "key", name="uq_campaign_kv_cid_key"),
    )


# ── Lifecycle helpers ────────────────────────────────────────────────────────

async def init_db(*, drop: bool = False) -> None:
    """Create all tables.  Call once at application startup.

    Parameters
    ----------
    drop:
        If ``True``, drop existing tables first (useful for tests).
    """
    global _engine, _session_factory

    settings = get_settings()
    _engine = create_async_engine(
        settings.database_url,
        echo=False,
        future=True,
    )
    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    async with _engine.begin() as conn:
        if drop:
            log.warning("database.dropping_tables")
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    log.info("database.initialised", url=settings.database_url)


async def close_db() -> None:
    """Dispose of the engine.  Call at shutdown."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        log.info("database.closed")


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async session (context-manager style).

    Usage::

        async with get_session() as session:
            session.add(campaign)
            await session.commit()
    """
    if _session_factory is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")

    async with _session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Query helpers ────────────────────────────────────────────────────────────

async def get_campaigns(
    session: AsyncSession,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[Campaign]:
    """List campaigns ordered by most recent."""
    result = await session.execute(
        select(Campaign)
        .order_by(Campaign.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())


async def get_campaign_by_id(
    session: AsyncSession,
    campaign_id: UUID,
) -> Campaign | None:
    """Fetch a single campaign with all related data."""
    result = await session.execute(
        select(Campaign).where(Campaign.id == campaign_id)
    )
    return result.scalar_one_or_none()


async def get_crashes_for_campaign(
    session: AsyncSession,
    campaign_id: UUID,
) -> list[Crash]:
    """Retrieve all crashes across all runs of a campaign."""
    result = await session.execute(
        select(Crash)
        .join(FuzzingRun)
        .where(FuzzingRun.campaign_id == campaign_id)
        .order_by(Crash.created_at.desc())
    )
    return list(result.scalars().all())


__all__ = [
    "Base",
    "Campaign",
    "FuzzingRun",
    "Crash",
    "Seed",
    "init_db",
    "close_db",
    "get_session",
    "get_campaigns",
    "get_campaign_by_id",
    "get_crashes_for_campaign",
]
