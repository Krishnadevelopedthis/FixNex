from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin
from app.models.enums import ReportFormat, ReportStatus

if TYPE_CHECKING:
    from app.models.assessment import Assessment
    from app.models.user import User


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(250), nullable=False)
    format: Mapped[str] = mapped_column(String(10), default=ReportFormat.PDF, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default=ReportStatus.PENDING, nullable=False)
    filename: Mapped[str | None] = mapped_column(String(300))
    storage_key: Mapped[str | None] = mapped_column(String(500))
    storage_backend: Mapped[str | None] = mapped_column(String(20))
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    file_hash: Mapped[str | None] = mapped_column(String(64))
    engine: Mapped[str | None] = mapped_column(String(40))
    options: Mapped[dict] = mapped_column(JSONType, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)

    generated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    generated_by: Mapped["User | None"] = relationship()
    assessment: Mapped["Assessment"] = relationship(back_populates="reports")
