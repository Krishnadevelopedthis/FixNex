from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, JSONType, TimestampMixin


class EnrichmentCache(Base):
    """Cached third-party enrichment payloads (NVD / CWE / SSL Labs).

    Avoids re-querying rate-limited public APIs and lets the platform keep
    working, from cache, when it is offline.
    """

    __tablename__ = "enrichment_cache"
    __table_args__ = (Index("ix_enrichment_source_key", "source", "cache_key", unique=True),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    cache_key: Mapped[str] = mapped_column(String(120), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONType, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class SystemSetting(Base, TimestampMixin):
    """Runtime-configurable settings, e.g. per-severity SLA windows."""

    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    value: Mapped[dict] = mapped_column(JSONType, default=dict)
    description: Mapped[str | None] = mapped_column(Text)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
