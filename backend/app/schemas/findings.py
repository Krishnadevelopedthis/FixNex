from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import (
    Criticality,
    DataSensitivity,
    Exposure,
    FindingStatus,
    Priority,
    Severity,
)
from app.schemas.common import ORMModel, UserBrief


class FindingCreate(BaseModel):
    """Manual finding raised by an analyst during hands-on testing."""

    assessment_id: int
    target_id: int | None = None
    title: str = Field(min_length=4, max_length=300)
    description: str | None = None
    category: str | None = Field(None, max_length=120)
    severity: Severity = Severity.MEDIUM
    endpoint: str | None = Field(None, max_length=600)
    parameter: str | None = Field(None, max_length=200)
    http_method: str | None = Field(None, max_length=10)
    cvss_vector: str | None = Field(None, max_length=140)
    cwe_id: str | None = Field(None, max_length=20)
    cve_ids: list[str] = Field(default_factory=list)
    technical_details: str | None = None
    request_snippet: str | None = None
    response_snippet: str | None = None
    remediation_recommendation: str | None = None
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(0.9, ge=0, le=1)


class FindingUpdate(BaseModel):
    title: str | None = Field(None, min_length=4, max_length=300)
    description: str | None = None
    category: str | None = Field(None, max_length=120)
    endpoint: str | None = Field(None, max_length=600)
    parameter: str | None = Field(None, max_length=200)
    http_method: str | None = Field(None, max_length=10)
    technical_details: str | None = None
    remediation_recommendation: str | None = None
    references: list[str] | None = None


class FindingScoreUpdate(BaseModel):
    """Requires the finding:score permission — developers cannot call this."""

    cvss_vector: str | None = Field(None, max_length=140)
    severity: Severity | None = None
    cwe_id: str | None = Field(None, max_length=20)
    cve_ids: list[str] | None = None
    asset_criticality: Criticality | None = None
    data_sensitivity: DataSensitivity | None = None
    exposure: Exposure | None = None
    exploit_available: bool | None = None
    note: str | None = None


class FindingVerifyRequest(BaseModel):
    confirmed: bool
    reason: str | None = Field(None, max_length=2000)
    note: str | None = Field(None, max_length=2000)


class FindingTriageRequest(BaseModel):
    priority: Priority
    note: str | None = None


class FindingAssignRequest(BaseModel):
    assigned_to_id: int
    priority: Priority | None = None
    sla_hours: int | None = Field(None, ge=1, le=8760)
    recommendation: str | None = None
    note: str | None = None


class FindingSuppressRequest(BaseModel):
    suppressed: bool
    reason: str | None = Field(None, max_length=1000)


class FindingCommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class FindingCommentRead(ORMModel):
    id: int
    body: str
    created_at: datetime
    user: UserBrief | None = None


class FindingSourceRead(ORMModel):
    id: int
    scanner: str
    scanner_label: str | None = None
    scan_job_id: int | None = None
    raw_title: str | None = None
    raw_severity: str | None = None
    confidence: float
    created_at: datetime


class FindingHistoryRead(ORMModel):
    id: int
    event_type: str
    actor_name: str | None = None
    from_status: str | None = None
    to_status: str | None = None
    note: str | None = None
    event_metadata: dict = Field(default_factory=dict)
    created_at: datetime


class CVEDetail(BaseModel):
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    published: str | None = None
    source: str = "NVD"
    url: str | None = None


class RiskBreakdown(BaseModel):
    """Platform-specific contextual risk — explicitly not an official CVSS score."""

    base_cvss: float | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    impact: str | None = None
    likelihood: str | None = None
    factors: dict = Field(default_factory=dict)
    explanation: list[str] = Field(default_factory=list)
    disclaimer: str = (
        "Contextual risk is a FixNex platform score that combines the CVSS base "
        "score with asset context. It is not an official CVSS rating."
    )


class SLAInfo(BaseModel):
    due_at: datetime | None = None
    status: str
    hours_remaining: float | None = None
    breached: bool = False


class FindingListItem(ORMModel):
    id: int
    reference: str
    title: str
    assessment_id: int
    severity: str
    cvss_score: float | None = None
    risk_level: str | None = None
    status: str
    verification_status: str
    primary_source: str
    source_count: int
    data_origin: str
    is_demo: bool
    cwe_id: str | None = None
    cve_ids: list = Field(default_factory=list)
    target_id: int | None = None
    target_name: str | None = None
    endpoint: str | None = None
    assigned_to: UserBrief | None = None
    priority: str | None = None
    sla: SLAInfo | None = None
    updated_at: datetime
    created_at: datetime


class EvidenceRead(ORMModel):
    id: int
    finding_id: int
    filename: str
    content_type: str
    size_bytes: int
    file_hash: str
    description: str | None = None
    version: int
    supersedes_id: int | None = None
    is_current: bool
    annotations: list = Field(default_factory=list)
    created_at: datetime
    uploaded_by: UserBrief | None = None
    download_url: str | None = None


class RemediationRead(ORMModel):
    id: int
    finding_id: int
    status: str
    priority: str
    recommendation: str | None = None
    developer_notes: str | None = None
    fix_summary: str | None = None
    assigned_to: UserBrief | None = None
    assigned_by: UserBrief | None = None
    assigned_at: datetime | None = None
    sla_due_at: datetime | None = None
    started_at: datetime | None = None
    ready_for_retest_at: datetime | None = None
    resolved_at: datetime | None = None
    reopened_count: int
    sla: SLAInfo | None = None


class RetestRead(ORMModel):
    id: int
    finding_id: int
    result: str
    summary: str | None = None
    method: str | None = None
    performed_at: datetime | None = None
    performed_by: UserBrief | None = None
    approved_at: datetime | None = None
    approved_by: UserBrief | None = None
    created_at: datetime


class FindingDetail(FindingListItem):
    description: str | None = None
    category: str | None = None
    parameter: str | None = None
    http_method: str | None = None
    technical_details: str | None = None
    request_snippet: str | None = None
    response_snippet: str | None = None
    remediation_recommendation: str | None = None
    references: list = Field(default_factory=list)
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwe_name: str | None = None
    cve_details: list = Field(default_factory=list)
    confidence: float
    duplicate_hits: int
    correlation_key: str | None = None
    verification_note: str | None = None
    false_positive_reason: str | None = None
    verified_at: datetime | None = None
    verified_by: UserBrief | None = None
    is_suppressed: bool
    suppression_reason: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    closed_at: datetime | None = None
    target_value: str | None = None
    risk: RiskBreakdown | None = None
    sources: list[FindingSourceRead] = Field(default_factory=list)
    evidence: list[EvidenceRead] = Field(default_factory=list)
    history: list[FindingHistoryRead] = Field(default_factory=list)
    comments: list[FindingCommentRead] = Field(default_factory=list)
    remediation: RemediationRead | None = None
    retests: list[RetestRead] = Field(default_factory=list)
    available_transitions: list[str] = Field(default_factory=list)


class FindingFilters(BaseModel):
    assessment_id: int | None = None
    target_id: int | None = None
    severity: list[Severity] | None = None
    status: list[FindingStatus] | None = None
    source: list[str] | None = None
    cwe: str | None = None
    cve: str | None = None
    assigned_to_id: int | None = None
    search: str | None = None
    include_false_positive: bool = True
    include_demo: bool = True
    sla_status: str | None = None


class AITriageSuggestion(BaseModel):
    """An advisory suggestion. It never changes a finding's state."""

    false_positive_confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = ""
    suggested_fix: str = ""
    verification_steps: str = ""
    model: str | None = None
    effort: str | None = None
    generated_at: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached: bool = False
    disclaimer: str = (
        "AI suggestion — not a verdict. It does not change this finding's verification "
        "status, severity or risk; an analyst still confirms or rejects it."
    )
