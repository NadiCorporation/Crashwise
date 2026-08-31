# SPDX-License-Identifier: MIT
"""Web layer database models — ClusterFuzz-style crash deduplication.

Operation Hydra Phase 5: Centralized crash tracking with unique signature
indexing for deduplication across campaigns and workers.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class FuzzingCampaign(Base):
    """Active fuzzing campaign tracker."""

    __tablename__ = "web_campaigns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    target_name = Column(String(256), nullable=False, index=True)
    target_repo = Column(String(512), nullable=False)
    engine = Column(String(32), nullable=False, default="libfuzzer")
    status = Column(String(32), nullable=False, default="running")
    workflow_id = Column(String(256), nullable=True)
    total_executions = Column(Integer, default=0)
    edges_covered = Column(Integer, default=0)
    crash_count = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    crashes = relationship("CrashTestCase", back_populates="campaign", cascade="all, delete-orphan")


class CrashTestCase(Base):
    """Deduplicated crash artifact with full diagnostic context."""

    __tablename__ = "web_crashes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    campaign_id = Column(UUID(as_uuid=True), ForeignKey("web_campaigns.id"), nullable=False)
    crash_type = Column(String(128), nullable=False)
    crash_state = Column(String(512), nullable=False)
    severity = Column(String(32), default="unknown")
    sanitizer_log = Column(Text, default="")
    gdb_backtrace = Column(Text, default="")
    reproducer_path = Column(String(1024), default="")
    status = Column(String(32), default="new")
    found_at = Column(DateTime, default=datetime.utcnow)

    campaign = relationship("FuzzingCampaign", back_populates="crashes")

    __table_args__ = (
        UniqueConstraint("campaign_id", "crash_type", "crash_state", name="uq_crash_signature"),
        Index("ix_crash_dedup", "crash_type", "crash_state"),
    )
