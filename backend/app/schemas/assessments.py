from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, Field

from app.models.enums import AssessmentStatus, ScopeRuleType
from app.schemas.common import ORMModel, UserBrief


class AssessmentCreate(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    description: str | None = None
    client_name: str | None = Field(None, max_length=180)
    start_date: date | None = None
    end_date: date | None = None
    methodology: str | None = None
    notes: str | None = None
    engagement_type: str | None = Field(None, max_length=60)
    tags: list[str] = Field(default_factory=list)
    member_ids: list[int] = Field(default_factory=list)


class AssessmentUpdate(BaseModel):
    name: str | None = Field(None, min_length=3, max_length=200)
    description: str | None = None
    client_name: str | None = Field(None, max_length=180)
    start_date: date | None = None
    end_date: date | None = None
    status: AssessmentStatus | None = None
    methodology: str | None = None
    notes: str | None = None
    engagement_type: str | None = Field(None, max_length=60)
    tags: list[str] | None = None


class TeamMemberUpdate(BaseModel):
    user_id: int
    role_in_assessment: str | None = Field(None, max_length=60)


class TeamUpdate(BaseModel):
    members: list[TeamMemberUpdate]


class MemberRead(ORMModel):
    id: int
    user_id: int
    role_in_assessment: str | None = None
    user: UserBrief


class SeverityBreakdown(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFORMATIONAL: int = 0


class AssessmentSummaryStats(BaseModel):
    targets: int = 0
    scans: int = 0
    findings_total: int = 0
    findings_open: int = 0
    findings_closed: int = 0
    findings_false_positive: int = 0
    severity: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    remediation_progress: float = 0.0
    overdue: int = 0
    highest_risk_level: str | None = None


class AssessmentRead(ORMModel):
    id: int
    reference: str
    name: str
    description: str | None = None
    client_name: str | None = None
    start_date: date | None = None
    end_date: date | None = None
    status: str
    methodology: str | None = None
    notes: str | None = None
    engagement_type: str | None = None
    tags: list[str] = Field(default_factory=list)
    is_demo: bool
    created_at: datetime
    updated_at: datetime
    created_by: UserBrief | None = None
    members: list[MemberRead] = Field(default_factory=list)
    stats: AssessmentSummaryStats | None = None


class AssessmentListItem(ORMModel):
    id: int
    reference: str
    name: str
    client_name: str | None = None
    status: str
    start_date: date | None = None
    end_date: date | None = None
    is_demo: bool
    created_at: datetime
    stats: AssessmentSummaryStats | None = None


class ScopeRuleCreate(BaseModel):
    rule_type: ScopeRuleType
    value: str = Field(min_length=1, max_length=300)
    is_exclusion: bool = False
    note: str | None = None


class ScopeRuleRead(ORMModel):
    id: int
    assessment_id: int
    rule_type: str
    value: str
    is_exclusion: bool
    note: str | None = None
    created_at: datetime
    created_by: UserBrief | None = None


class ScopeCheckRequest(BaseModel):
    value: str = Field(min_length=1, max_length=500)


class ScopeCheckResponse(BaseModel):
    value: str
    in_scope: bool
    matched_rule: ScopeRuleRead | None = None
    reason: str
