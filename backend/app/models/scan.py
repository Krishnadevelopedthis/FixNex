from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin
from app.models.enums import ScanProfile, ScannerRunStatus, ScanStatus

if TYPE_CHECKING:
    from app.models.assessment import Assessment
    from app.models.target import Target
    from app.models.user import User


class ScanJob(Base, TimestampMixin):
    """One orchestrated scan of one target, fanning out to several scanners."""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    profile: Mapped[str] = mapped_column(String(20), default=ScanProfile.STANDARD, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.QUEUED, nullable=False, index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_operation: Mapped[str | None] = mapped_column(String(240))

    requested_scanners: Mapped[list] = mapped_column(JSONType, default=list)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duplicates_merged: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    task_runner: Mapped[str | None] = mapped_column(String(20))
    task_id: Mapped[str | None] = mapped_column(String(80))
    cancel_requested: Mapped[bool] = mapped_column(default=False, nullable=False)

    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)

    assessment: Mapped["Assessment"] = relationship(back_populates="scan_jobs")
    target: Mapped["Target"] = relationship()
    created_by: Mapped["User | None"] = relationship()
    scanner_runs: Mapped[list["ScannerRun"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan", order_by="ScannerRun.id"
    )

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class ScannerRun(Base, TimestampMixin):
    """Execution metadata for a single scanner within a scan job.

    Kept for troubleshooting and audit; raw command lines are only exposed to
    users holding the system:view permission.
    """

    __tablename__ = "scanner_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scanner: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default=ScannerRunStatus.PENDING, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    command_summary: Mapped[str | None] = mapped_column(Text)
    raw_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    tool_version: Mapped[str | None] = mapped_column(String(80))
    metrics: Mapped[dict] = mapped_column(JSONType, default=dict)

    scan_job: Mapped["ScanJob"] = relationship(back_populates="scanner_runs")
