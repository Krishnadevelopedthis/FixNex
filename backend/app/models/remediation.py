from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import Priority, RemediationStatus

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.user import User


class Remediation(Base, TimestampMixin):
    __tablename__ = "remediations"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    status: Mapped[str] = mapped_column(
        String(30), default=RemediationStatus.OPEN, nullable=False, index=True
    )
    priority: Mapped[str] = mapped_column(String(10), default=Priority.P3, nullable=False, index=True)
    recommendation: Mapped[str | None] = mapped_column(Text)
    developer_notes: Mapped[str | None] = mapped_column(Text)
    fix_summary: Mapped[str | None] = mapped_column(Text)

    assigned_to_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    assigned_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ready_for_retest_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reopened_count: Mapped[int] = mapped_column(default=0, nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="remediation")
    assigned_to: Mapped["User | None"] = relationship(foreign_keys=[assigned_to_id])
    assigned_by: Mapped["User | None"] = relationship(foreign_keys=[assigned_by_id])


class Retest(Base, TimestampMixin):
    __tablename__ = "retests"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    remediation_id: Mapped[int | None] = mapped_column(ForeignKey("remediations.id", ondelete="SET NULL"))
    result: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    summary: Mapped[str | None] = mapped_column(Text)
    method: Mapped[str | None] = mapped_column(String(200))
    performed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    performed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped["Finding"] = relationship(back_populates="retests")
    performed_by: Mapped["User | None"] = relationship(foreign_keys=[performed_by_id])
    approved_by: Mapped["User | None"] = relationship(foreign_keys=[approved_by_id])
