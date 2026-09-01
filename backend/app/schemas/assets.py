from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import AssetType, Criticality, DataSensitivity, Exposure
from app.schemas.common import ORMModel


class AssetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=180)
    description: str | None = None
    asset_type: AssetType = AssetType.WEB_APPLICATION
    owner: str | None = Field(None, max_length=150)
    business_unit: str | None = Field(None, max_length=150)
    primary_url: str | None = Field(None, max_length=500)
    criticality: Criticality = Criticality.MEDIUM
    data_sensitivity: DataSensitivity = DataSensitivity.MEDIUM
    exposure: Exposure = Exposure.INTERNAL
    technologies: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class AssetUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=180)
    description: str | None = None
    asset_type: AssetType | None = None
    owner: str | None = Field(None, max_length=150)
    business_unit: str | None = Field(None, max_length=150)
    primary_url: str | None = Field(None, max_length=500)
    criticality: Criticality | None = None
    data_sensitivity: DataSensitivity | None = None
    exposure: Exposure | None = None
    technologies: list[str] | None = None
    tags: list[str] | None = None


class AssetRead(ORMModel):
    id: int
    reference: str
    name: str
    description: str | None = None
    asset_type: str
    owner: str | None = None
    business_unit: str | None = None
    primary_url: str | None = None
    criticality: str
    data_sensitivity: str
    exposure: str
    technologies: list = Field(default_factory=list)
    tags: list = Field(default_factory=list)
    is_demo: bool
    created_at: datetime
    open_findings: int = 0
    highest_severity: str | None = None
