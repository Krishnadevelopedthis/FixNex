from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.enums import Priority, RemediationStatus, RetestResult


class RemediationCreate(BaseModel):
    assigned_to_id: int
    priority: Priority = Priority.P3
    sla_hours: int | None = Field(None, ge=1, le=8760)
    recommendation: str | None = None
    note: str | None = None


class RemediationUpdate(BaseModel):
    """Developers may move status and add notes; they may not rescore a finding."""

    status: RemediationStatus | None = None
    developer_notes: str | None = Field(None, max_length=5000)
    fix_summary: str | None = Field(None, max_length=5000)
    priority: Priority | None = None
    assigned_to_id: int | None = None
    sla_hours: int | None = Field(None, ge=1, le=8760)


class ReadyForRetestRequest(BaseModel):
    fix_summary: str | None = Field(None, max_length=5000)


class RetestCreate(BaseModel):
    result: RetestResult
    summary: str | None = Field(None, max_length=5000)
    method: str | None = Field(None, max_length=200)
