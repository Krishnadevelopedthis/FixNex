from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.permissions import Role, permissions_for_role
from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.assessment import AssessmentMember


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(150), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False, default=Role.VIEWER, index=True)
    job_title: Mapped[str | None] = mapped_column(String(120))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    memberships: Mapped[list["AssessmentMember"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def permissions(self) -> frozenset[str]:
        return permissions_for_role(self.role)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.email} ({self.role})>"
