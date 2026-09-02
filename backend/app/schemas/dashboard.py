from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import CountByKey


class AssessmentCounters(BaseModel):
    total: int = 0
    active: int = 0
    draft: int = 0
    completed: int = 0
    archived: int = 0


class FindingCounters(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    confirmed: int = 0
    false_positive: int = 0
    needs_verification: int = 0
    closed: int = 0


class RemediationCounters(BaseModel):
    open: int = 0
    in_progress: int = 0
    ready_for_retest: int = 0
    retesting: int = 0
    resolved: int = 0
    reopened: int = 0
    overdue: int = 0
    due_soon: int = 0
    progress_percent: float = 0.0


class ScanCounters(BaseModel):
    total: int = 0
    running: int = 0
    queued: int = 0
    completed: int = 0
    failed: int = 0


class RiskyAsset(BaseModel):
    target_id: int | None = None
    asset_id: int | None = None
    name: str
    value: str | None = None
    criticality: str | None = None
    open_findings: int = 0
    max_severity: str | None = None
    risk_score: float | None = None


class RecentScan(BaseModel):
    id: int
    reference: str
    target_name: str | None = None
    profile: str
    status: str
    progress: int
    findings_count: int
    created_at: datetime


class ActivityItem(BaseModel):
    id: int
    action: str
    actor: str | None = None
    description: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    created_at: datetime


class TrendPoint(BaseModel):
    date: str
    discovered: int = 0
    closed: int = 0


class RiskHeatCell(BaseModel):
    impact: str
    likelihood: str
    count: int


class DashboardResponse(BaseModel):
    generated_at: datetime
    demo_mode: bool = False
    assessments: AssessmentCounters
    findings: FindingCounters
    remediation: RemediationCounters
    scans: ScanCounters
    severity_distribution: list[CountByKey] = Field(default_factory=list)
    risk_distribution: list[CountByKey] = Field(default_factory=list)
    cvss_distribution: list[CountByKey] = Field(default_factory=list)
    status_distribution: list[CountByKey] = Field(default_factory=list)
    top_risky_assets: list[RiskyAsset] = Field(default_factory=list)
    recent_scans: list[RecentScan] = Field(default_factory=list)
    recent_activity: list[ActivityItem] = Field(default_factory=list)
    trend: list[TrendPoint] = Field(default_factory=list)
    risk_heatmap: list[RiskHeatCell] = Field(default_factory=list)
    scanner_availability: list[dict] = Field(default_factory=list)
    posture: "PostureScore | None" = None
    asset_heatmap: "AssetHeatmap | None" = None


class HeatmapAsset(BaseModel):
    key: str
    name: str
    asset_id: int | None = None
    target_id: int | None = None
    criticality: str | None = None
    targets: int = 0
    counts: dict[str, int] = Field(default_factory=dict)
    total: int = 0


class AssetHeatmap(BaseModel):
    severities: list[str] = Field(default_factory=list)
    assets: list[HeatmapAsset] = Field(default_factory=list)
    max_count: int = 0


class PostureFactor(BaseModel):
    key: str
    label: str
    count: int
    penalty: float
    max_penalty: float
    explanation: str


class PostureTotals(BaseModel):
    findings: int = 0
    open: int = 0
    closed: int = 0
    resolution_rate: float = 0.0


class PostureScore(BaseModel):
    score: float
    grade: str
    summary: str
    factors: list[PostureFactor] = Field(default_factory=list)
    totals: PostureTotals
    methodology: str


DashboardResponse.model_rebuild()
