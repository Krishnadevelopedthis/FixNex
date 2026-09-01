from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin
from app.models.enums import AssetType, Criticality, DataSensitivity, Exposure

if TYPE_CHECKING:
    from app.models.target import Target


class Asset(Base, TimestampMixin):
    """Business asset an assessment target belongs to.

    Asset context (criticality, data sensitivity, exposure) is what turns a raw
    CVSS base score into a meaningful contextual risk score.
    """

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(180), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    asset_type: Mapped[str] = mapped_column(String(40), default=AssetType.WEB_APPLICATION, nullable=False)
    owner: Mapped[str | None] = mapped_column(String(150))
    business_unit: Mapped[str | None] = mapped_column(String(150))
    primary_url: Mapped[str | None] = mapped_column(String(500))

    criticality: Mapped[str] = mapped_column(String(20), default=Criticality.MEDIUM, nullable=False, index=True)
    data_sensitivity: Mapped[str] = mapped_column(String(20), default=DataSensitivity.MEDIUM, nullable=False)
    exposure: Mapped[str] = mapped_column(String(30), default=Exposure.INTERNAL, nullable=False)

    technologies: Mapped[list] = mapped_column(JSONType, default=list)
    tags: Mapped[list] = mapped_column(JSONType, default=list)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    targets: Mapped[list["Target"]] = relationship(back_populates="asset")
