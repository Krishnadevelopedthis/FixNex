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


class AttackPathNode(BaseModel):
    id: str
    kind: str                      # "finding" | "outcome"
    title: str
    severity: str
    finding_id: int | None = None
    reference: str | None = None
    category: str | None = None
    cwe_id: str | None = None
    status: str | None = None
    endpoint: str | None = None
    target_id: int | None = None
    target_name: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    rationale: str | None = None


class AttackPathEdge(BaseModel):
    id: str
    source: str
    target: str
    role: str                      # "prerequisite" | "enabler"
    rule_id: str
    label: str


class AttackPathStep(BaseModel):
    finding_id: int
    reference: str
    title: str
    severity: str


class AttackPath(BaseModel):
    rule_id: str
    rule_name: str
    outcome: str
    outcome_severity: str
    rationale: str
    target_id: int | None = None
    target_name: str | None = None
    prerequisite: AttackPathStep
    enabler: AttackPathStep
    same_surface: bool = False
    escalates: bool


class AttackPathSummary(BaseModel):
    paths: int = 0
    escalating_paths: int = 0
    findings_considered: int = 0
    findings_in_paths: int = 0
    highest_outcome_severity: str | None = None
    rules_evaluated: int = 0


class AttackPathResponse(BaseModel):
    assessment_id: int
    nodes: list[AttackPathNode] = Field(default_factory=list)
    edges: list[AttackPathEdge] = Field(default_factory=list)
    paths: list[AttackPath] = Field(default_factory=list)
    summary: AttackPathSummary
    disclaimer: str = (
        "Attack paths are potential chains inferred from findings that co-occur on the "
        "same surface. They indicate where to look first; they are not proof that the "
        "chain is exploitable end to end."
    )


class ComplianceControl(BaseModel):
    id: str
    title: str
    open_findings: int = 0
    resolved_findings: int = 0
    worst_open_severity: str | None = None
    readiness: float = 100.0
    finding_ids: list[int] = Field(default_factory=list)


class ComplianceFramework(BaseModel):
    key: str
    label: str
    controls_affected: int = 0
    controls_at_risk: int = 0
    readiness: float | None = None
    controls: list[ComplianceControl] = Field(default_factory=list)


class OwaspCategory(BaseModel):
    id: str
    title: str
    open_findings: int = 0
    resolved_findings: int = 0
    worst_open_severity: str | None = None


class ComplianceCoverage(BaseModel):
    findings_considered: int = 0
    findings_mapped: int = 0
    findings_unmapped: int = 0
    mapping_rate: float = 0.0
    unmapped_cwes: list[str] = Field(default_factory=list)
    catalogue_size: int = 0


class ComplianceResponse(BaseModel):
    assessment_id: int
    frameworks: list[ComplianceFramework] = Field(default_factory=list)
    owasp_top_10: list[OwaspCategory] = Field(default_factory=list)
    coverage: ComplianceCoverage
    disclaimer: str
