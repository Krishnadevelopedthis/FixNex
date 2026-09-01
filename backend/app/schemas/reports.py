from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import ReportFormat
from app.schemas.common import ORMModel, UserBrief


class ReportCreate(BaseModel):
    assessment_id: int
    format: ReportFormat = ReportFormat.PDF
    title: str | None = Field(None, max_length=250)
    include_false_positives: bool = False
    include_informational: bool = True
    include_evidence: bool = True
    include_retest: bool = True
    include_audit_summary: bool = True


class ReportRead(ORMModel):
    id: int
    reference: str
    assessment_id: int
    assessment_name: str | None = None
    title: str
    format: str
    status: str
    filename: str | None = None
    size_bytes: int
    file_hash: str | None = None
    engine: str | None = None
    error_message: str | None = None
    created_at: datetime
    generated_by: UserBrief | None = None
    download_url: str | None = None
