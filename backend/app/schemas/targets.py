from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.models.enums import TargetType
from app.schemas.common import ORMModel, UserBrief

AUTHORIZATION_STATEMENT = (
    "I confirm that I am authorized to perform security testing against this target."
)


class TargetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    target_type: TargetType = TargetType.WEB_APP
    value: str = Field(min_length=3, max_length=500)
    description: str | None = None
    asset_id: int | None = None
    port: int | None = Field(None, ge=1, le=65535)
    base_path: str | None = Field(None, max_length=300)

    # The user must tick the authorisation box; the API refuses otherwise.
    authorization_confirmed: bool = False

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class TargetUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=200)
    description: str | None = None
    asset_id: int | None = None
    port: int | None = Field(None, ge=1, le=65535)
    base_path: str | None = Field(None, max_length=300)
    status: str | None = None


class TargetEndpointRead(ORMModel):
    id: int
    method: str
    path: str
    summary: str | None = None
    source: str
    auth_required: bool


class TargetRead(ORMModel):
    id: int
    reference: str
    assessment_id: int
    asset_id: int | None = None
    asset_name: str | None = None
    name: str
    target_type: str
    value: str
    hostname: str | None = None
    port: int | None = None
    base_path: str | None = None
    description: str | None = None
    status: str
    authorization_confirmed: bool
    authorization_statement: str | None = None
    authorized_at: datetime | None = None
    authorized_by: UserBrief | None = None
    technologies: list = Field(default_factory=list)
    is_demo: bool
    created_at: datetime
    endpoint_count: int = 0
    findings_count: int = 0
    last_scan_at: datetime | None = None


class OpenAPIImportRequest(BaseModel):
    """Import API operations from an OpenAPI/Swagger document."""

    spec: dict | None = None
    spec_url: str | None = None
    replace_existing: bool = True


class OpenAPIImportResult(BaseModel):
    imported: int
    skipped: int
    endpoints: list[TargetEndpointRead]
    title: str | None = None
    version: str | None = None
