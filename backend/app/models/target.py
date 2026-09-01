from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin
from app.models.enums import ScopeRuleType, TargetStatus, TargetType

if TYPE_CHECKING:
    from app.models.assessment import Assessment
    from app.models.asset import Asset
    from app.models.user import User


class ScopeRule(Base, TimestampMixin):
    """One authorised (or explicitly excluded) entry in an assessment's scope.

    No scan may run against anything that does not match an inclusion rule.
    """

    __tablename__ = "scope_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_type: Mapped[str] = mapped_column(String(30), default=ScopeRuleType.DOMAIN, nullable=False)
    value: Mapped[str] = mapped_column(String(300), nullable=False)
    is_exclusion: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)

    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_by: Mapped["User | None"] = relationship()
    assessment: Mapped["Assessment"] = relationship(back_populates="scope_rules")


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), default=TargetType.WEB_APP, nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)  # URL, hostname or IP
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    port: Mapped[int | None] = mapped_column(Integer)
    base_path: Mapped[str | None] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(30), default=TargetStatus.PENDING_AUTHORIZATION, nullable=False, index=True
    )

    # Explicit written authorisation captured in the UI before any scan is allowed.
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_statement: Mapped[str | None] = mapped_column(Text)
    authorized_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Populated by the technology fingerprinting adapter.
    technologies: Mapped[list] = mapped_column(JSONType, default=list)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    assessment: Mapped["Assessment"] = relationship(back_populates="targets")
    asset: Mapped["Asset | None"] = relationship(back_populates="targets")
    authorized_by: Mapped["User | None"] = relationship(foreign_keys=[authorized_by_id])
    endpoints: Mapped[list["TargetEndpoint"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class TargetEndpoint(Base, TimestampMixin):
    """An API operation, typically imported from an OpenAPI specification."""

    __tablename__ = "target_endpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str | None] = mapped_column(String(400))
    source: Mapped[str] = mapped_column(String(20), default="OPENAPI", nullable=False)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    parameters: Mapped[list] = mapped_column(JSONType, default=list)

    target: Mapped["Target"] = relationship(back_populates="endpoints")
