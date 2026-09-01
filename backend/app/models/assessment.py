from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Date, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin
from app.models.enums import AssessmentStatus

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.report import Report
    from app.models.scan import ScanJob
    from app.models.target import ScopeRule, Target
    from app.models.user import User


class Assessment(Base, TimestampMixin):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    client_name: Mapped[str | None] = mapped_column(String(180), index=True)
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), default=AssessmentStatus.DRAFT, nullable=False, index=True)
    methodology: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    engagement_type: Mapped[str | None] = mapped_column(String(60))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    tags: Mapped[list] = mapped_column(JSONType, default=list)

    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    created_by: Mapped["User | None"] = relationship(foreign_keys=[created_by_id])

    members: Mapped[list["AssessmentMember"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    scope_rules: Mapped[list["ScopeRule"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    targets: Mapped[list["Target"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    scan_jobs: Mapped[list["ScanJob"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class AssessmentMember(Base):
    """A user assigned to an assessment team."""

    __tablename__ = "assessment_members"
    __table_args__ = (UniqueConstraint("assessment_id", "user_id", name="assessment_user"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_in_assessment: Mapped[str | None] = mapped_column(String(60))

    assessment: Mapped["Assessment"] = relationship(back_populates="members")
    user: Mapped["User"] = relationship(back_populates="memberships")
