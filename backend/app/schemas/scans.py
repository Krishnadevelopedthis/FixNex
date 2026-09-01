from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import ScanProfile
from app.schemas.common import ORMModel, UserBrief


class ScanCreate(BaseModel):
    assessment_id: int
    target_id: int
    profile: ScanProfile = ScanProfile.STANDARD
    scanners: list[str] | None = None  # override the profile's scanner set
    authorization_confirmed: bool = False


class ScannerRunRead(ORMModel):
    id: int
    scanner: str
    scanner_label: str | None = None
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int | None = None
    exit_code: int | None = None
    raw_findings_count: int
    error_message: str | None = None
    tool_version: str | None = None
    command_summary: str | None = None
    metrics: dict = Field(default_factory=dict)


class ScanRead(ORMModel):
    id: int
    reference: str
    assessment_id: int
    assessment_name: str | None = None
    target_id: int
    target_name: str | None = None
    target_value: str | None = None
    profile: str
    status: str
    progress: int
    current_operation: str | None = None
    requested_scanners: list = Field(default_factory=list)
    findings_count: int
    raw_findings_count: int
    duplicates_merged: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    error_message: str | None = None
    task_runner: str | None = None
    created_at: datetime
    created_by: UserBrief | None = None
    scanner_runs: list[ScannerRunRead] = Field(default_factory=list)


class ScanListItem(ORMModel):
    id: int
    reference: str
    assessment_id: int
    target_id: int
    target_name: str | None = None
    profile: str
    status: str
    progress: int
    findings_count: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime


class ScannerInfo(BaseModel):
    name: str
    label: str
    description: str
    kind: str            # "builtin" | "external"
    available: bool
    availability_detail: str
    version: str | None = None
    requires: str | None = None


class ScanProfileInfo(BaseModel):
    name: str
    label: str
    description: str
    scanners: list[str]
    invasive: bool
    estimated_duration: str
