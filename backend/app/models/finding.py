from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin
from app.models.enums import (
    DataOrigin,
    FindingStatus,
    Severity,
    VerificationStatus,
)

if TYPE_CHECKING:
    from app.models.assessment import Assessment
    from app.models.evidence import Evidence
    from app.models.remediation import Remediation, Retest
    from app.models.target import Target
    from app.models.user import User


class Finding(Base, TimestampMixin):
    """A normalised security finding — the unit of work the platform manages."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_assessment_status", "assessment_id", "status"),
        Index("ix_findings_assessment_severity", "assessment_id", "severity"),
        Index("ix_findings_correlation", "assessment_id", "correlation_key"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(30), unique=True, index=True)

    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), index=True)

    # ---------------------------------------------------------------- content
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String(120), index=True)
    endpoint: Mapped[str | None] = mapped_column(String(600))
    parameter: Mapped[str | None] = mapped_column(String(200))
    http_method: Mapped[str | None] = mapped_column(String(10))
    technical_details: Mapped[str | None] = mapped_column(Text)
    request_snippet: Mapped[str | None] = mapped_column(Text)
    response_snippet: Mapped[str | None] = mapped_column(Text)
    remediation_recommendation: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSONType, default=list)

    # ------------------------------------------------------------- provenance
    # Which scanner first reported it; every contributing scanner is recorded
    # in `sources` (see FindingSource) after correlation.
    primary_source: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    data_origin: Mapped[str] = mapped_column(
        String(20), default=DataOrigin.REAL_SCAN, nullable=False, index=True
    )
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    correlation_key: Mapped[str | None] = mapped_column(String(128), index=True)
    source_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    duplicate_hits: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)

    # ------------------------------------------------------------ scoring
    severity: Mapped[str] = mapped_column(String(20), default=Severity.MEDIUM, nullable=False, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, index=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(140))
    cvss_version: Mapped[str | None] = mapped_column(String(10))
    cwe_id: Mapped[str | None] = mapped_column(String(20), index=True)
    cwe_name: Mapped[str | None] = mapped_column(String(240))
    cve_ids: Mapped[list] = mapped_column(JSONType, default=list)
    cve_details: Mapped[list] = mapped_column(JSONType, default=list)
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # FixNex contextual risk — deliberately separate from the CVSS base score.
    risk_score: Mapped[float | None] = mapped_column(Float, index=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), index=True)
    impact: Mapped[str | None] = mapped_column(String(20))
    likelihood: Mapped[str | None] = mapped_column(String(20))
    risk_factors: Mapped[dict] = mapped_column(JSONType, default=dict)

    # ------------------------------------------------------------- workflow
    status: Mapped[str] = mapped_column(
        String(30), default=FindingStatus.DISCOVERED, nullable=False, index=True
    )
    verification_status: Mapped[str] = mapped_column(
        String(30), default=VerificationStatus.UNVERIFIED, nullable=False, index=True
    )
    false_positive_reason: Mapped[str | None] = mapped_column(Text)
    verification_note: Mapped[str | None] = mapped_column(Text)
    verified_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_suppressed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    suppression_reason: Mapped[str | None] = mapped_column(Text)

    assigned_to_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    priority: Mapped[str | None] = mapped_column(String(10), index=True)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    # Cached AI triage suggestion. Advisory only — it never drives status.
    ai_triage: Mapped[dict | None] = mapped_column(JSONType)
    ai_triage_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # ------------------------------------------------------- relationships
    assessment: Mapped["Assessment"] = relationship(back_populates="findings")
    target: Mapped["Target | None"] = relationship()
    assigned_to: Mapped["User | None"] = relationship(foreign_keys=[assigned_to_id])
    verified_by: Mapped["User | None"] = relationship(foreign_keys=[verified_by_id])

    sources: Mapped[list["FindingSource"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="Evidence.id"
    )
    history: Mapped[list["FindingHistory"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingHistory.id"
    )
    comments: Mapped[list["FindingComment"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingComment.id"
    )
    remediation: Mapped["Remediation | None"] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )
    retests: Mapped[list["Retest"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="Retest.id"
    )


class FindingSource(Base, TimestampMixin):
    """Each scanner that independently reported this finding.

    Populated by the correlation engine so that one issue detected by ZAP,
    Nuclei and a built-in check is a single finding with three sources.
    """

    __tablename__ = "finding_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scanner: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    scanner_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("scanner_runs.id", ondelete="SET NULL"), index=True
    )
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"))
    raw_title: Mapped[str | None] = mapped_column(String(300))
    raw_severity: Mapped[str | None] = mapped_column(String(40))
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    raw_data: Mapped[dict] = mapped_column(JSONType, default=dict)

    finding: Mapped["Finding"] = relationship(back_populates="sources")


class FindingHistory(Base):
    """Immutable per-finding timeline, rendered as the finding's activity feed."""

    __tablename__ = "finding_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_name: Mapped[str | None] = mapped_column(String(150))
    event_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String(30))
    to_status: Mapped[str | None] = mapped_column(String(30))
    note: Mapped[str | None] = mapped_column(Text)
    event_metadata: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    finding: Mapped["Finding"] = relationship(back_populates="history")


class FindingComment(Base, TimestampMixin):
    __tablename__ = "finding_comments"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    body: Mapped[str] = mapped_column(Text, nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="comments")
    user: Mapped["User | None"] = relationship()
