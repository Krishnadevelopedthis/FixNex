"""Aggregations for the dashboard and assessment overview screens."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.assessment import Assessment
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.enums import (
    AssessmentStatus,
    FindingStatus,
    RemediationStatus,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.scan import ScanJob
from app.models.target import Target
from app.schemas.common import CountByKey
from app.schemas.dashboard import (
    ActivityItem,
    AssessmentCounters,
    DashboardResponse,
    FindingCounters,
    RecentScan,
    RemediationCounters,
    RiskHeatCell,
    RiskyAsset,
    ScanCounters,
    TrendPoint,
)

SEVERITIES = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]
OPEN_STATUSES = [
    FindingStatus.DISCOVERED,
    FindingStatus.NEEDS_VERIFICATION,
    FindingStatus.CONFIRMED,
    FindingStatus.TRIAGED,
    FindingStatus.REMEDIATION,
    FindingStatus.RETEST,
]


def _counts(db: Session, column, base_filter=None) -> dict[str, int]:
    query = db.query(column, func.count()).group_by(column)
    if base_filter is not None:
        query = query.filter(base_filter)
    return {str(key): count for key, count in query.all() if key is not None}


def severity_breakdown(db: Session, assessment_id: int | None = None) -> dict[str, int]:
    condition = Finding.assessment_id == assessment_id if assessment_id else None
    query = db.query(Finding.severity, func.count()).filter(
        Finding.status != FindingStatus.FALSE_POSITIVE
    )
    if condition is not None:
        query = query.filter(condition)
    raw = dict(query.group_by(Finding.severity).all())
    return {severity: int(raw.get(severity, 0)) for severity in SEVERITIES}


def assessment_stats(db: Session, assessment: Assessment) -> dict:
    """Summary counters shown on the assessment card and overview tab."""
    findings = db.query(Finding).filter(Finding.assessment_id == assessment.id)
    total = findings.count()
    false_positive = findings.filter(Finding.status == FindingStatus.FALSE_POSITIVE).count()
    closed = findings.filter(Finding.status == FindingStatus.CLOSED).count()
    open_count = findings.filter(Finding.status.in_(OPEN_STATUSES)).count()

    overdue = (
        findings.filter(
            Finding.sla_due_at.isnot(None),
            Finding.sla_due_at < utcnow(),
            Finding.status.in_(OPEN_STATUSES),
        ).count()
    )

    resolved_or_fp = closed + false_positive
    progress = round(100 * resolved_or_fp / total, 1) if total else 0.0

    severity = severity_breakdown(db, assessment.id)
    highest = next((s for s in SEVERITIES if severity.get(s)), None)

    return {
        "targets": db.query(Target).filter(Target.assessment_id == assessment.id).count(),
        "scans": db.query(ScanJob).filter(ScanJob.assessment_id == assessment.id).count(),
        "findings_total": total,
        "findings_open": open_count,
        "findings_closed": closed,
        "findings_false_positive": false_positive,
        "severity": severity,
        "remediation_progress": progress,
        "overdue": overdue,
        "highest_risk_level": highest,
    }


def build_dashboard(db: Session, demo_mode: bool = False) -> DashboardResponse:
    now = utcnow()

    # ---------------------------------------------------------- assessments
    assessment_counts = _counts(db, Assessment.status)
    assessments = AssessmentCounters(
        total=sum(assessment_counts.values()),
        active=assessment_counts.get(AssessmentStatus.ACTIVE, 0),
        draft=assessment_counts.get(AssessmentStatus.DRAFT, 0),
        completed=assessment_counts.get(AssessmentStatus.COMPLETED, 0),
        archived=assessment_counts.get(AssessmentStatus.ARCHIVED, 0),
    )

    # -------------------------------------------------------------- findings
    severity_counts = _counts(db, Finding.severity, Finding.status != FindingStatus.FALSE_POSITIVE)
    status_counts = _counts(db, Finding.status)
    verification_counts = _counts(db, Finding.verification_status)

    findings = FindingCounters(
        total=db.query(Finding).count(),
        critical=severity_counts.get(Severity.CRITICAL, 0),
        high=severity_counts.get(Severity.HIGH, 0),
        medium=severity_counts.get(Severity.MEDIUM, 0),
        low=severity_counts.get(Severity.LOW, 0),
        informational=severity_counts.get(Severity.INFORMATIONAL, 0),
        confirmed=verification_counts.get(VerificationStatus.CONFIRMED, 0),
        false_positive=verification_counts.get(VerificationStatus.FALSE_POSITIVE, 0),
        needs_verification=status_counts.get(FindingStatus.NEEDS_VERIFICATION, 0)
        + status_counts.get(FindingStatus.DISCOVERED, 0),
        closed=status_counts.get(FindingStatus.CLOSED, 0),
    )

    # ----------------------------------------------------------- remediation
    remediation_counts = _counts(db, Remediation.status)
    overdue = (
        db.query(Remediation)
        .filter(
            Remediation.sla_due_at.isnot(None),
            Remediation.sla_due_at < now,
            Remediation.status != RemediationStatus.RESOLVED,
        )
        .count()
    )
    due_soon = (
        db.query(Remediation)
        .filter(
            Remediation.sla_due_at.isnot(None),
            Remediation.sla_due_at >= now,
            Remediation.sla_due_at <= now + timedelta(hours=24),
            Remediation.status != RemediationStatus.RESOLVED,
        )
        .count()
    )
    remediation_total = sum(remediation_counts.values())
    resolved = remediation_counts.get(RemediationStatus.RESOLVED, 0)
    remediation = RemediationCounters(
        open=remediation_counts.get(RemediationStatus.OPEN, 0),
        in_progress=remediation_counts.get(RemediationStatus.IN_PROGRESS, 0),
        ready_for_retest=remediation_counts.get(RemediationStatus.READY_FOR_RETEST, 0),
        retesting=remediation_counts.get(RemediationStatus.RETESTING, 0),
        resolved=resolved,
        reopened=remediation_counts.get(RemediationStatus.REOPENED, 0),
        overdue=overdue,
        due_soon=due_soon,
        progress_percent=round(100 * resolved / remediation_total, 1) if remediation_total else 0.0,
    )

    # ----------------------------------------------------------------- scans
    scan_counts = _counts(db, ScanJob.status)
    scans = ScanCounters(
        total=sum(scan_counts.values()),
        running=scan_counts.get(ScanStatus.RUNNING, 0),
        queued=scan_counts.get(ScanStatus.QUEUED, 0),
        completed=scan_counts.get(ScanStatus.COMPLETED, 0),
        failed=scan_counts.get(ScanStatus.FAILED, 0),
    )

    # --------------------------------------------------------- distributions
    severity_distribution = [
        CountByKey(key=s, label=s.title(), count=severity_counts.get(s, 0)) for s in SEVERITIES
    ]
    risk_counts = _counts(db, Finding.risk_level, Finding.status != FindingStatus.FALSE_POSITIVE)
    risk_distribution = [
        CountByKey(key=s, label=s.title(), count=risk_counts.get(s, 0)) for s in SEVERITIES
    ]
    status_distribution = [
        CountByKey(key=key, label=key.replace("_", " ").title(), count=value)
        for key, value in sorted(status_counts.items())
    ]

    cvss_buckets = [("0.1-3.9", 0.1, 4.0), ("4.0-6.9", 4.0, 7.0), ("7.0-8.9", 7.0, 9.0), ("9.0-10.0", 9.0, 10.01)]
    cvss_distribution = [
        CountByKey(
            key=label,
            label=label,
            count=db.query(Finding)
            .filter(
                Finding.cvss_score >= low,
                Finding.cvss_score < high,
                Finding.status != FindingStatus.FALSE_POSITIVE,
            )
            .count(),
        )
        for label, low, high in cvss_buckets
    ]

    # ---------------------------------------------------------- risky assets
    severity_rank = case({s: i for i, s in enumerate(reversed(SEVERITIES), start=1)}, value=Finding.severity, else_=0)
    rows = (
        db.query(
            Target.id,
            Target.name,
            Target.value,
            Target.asset_id,
            func.count(Finding.id).label("open_findings"),
            func.max(severity_rank).label("max_rank"),
            func.max(Finding.risk_score).label("max_risk"),
        )
        .join(Finding, Finding.target_id == Target.id)
        .filter(Finding.status.in_(OPEN_STATUSES))
        .group_by(Target.id, Target.name, Target.value, Target.asset_id)
        .order_by(func.max(Finding.risk_score).desc().nullslast(), func.count(Finding.id).desc())
        .limit(6)
        .all()
    )
    rank_to_severity = {i: s for i, s in enumerate(reversed(SEVERITIES), start=1)}
    top_risky_assets = []
    for row in rows:
        asset = db.get(Asset, row.asset_id) if row.asset_id else None
        top_risky_assets.append(
            RiskyAsset(
                target_id=row.id,
                asset_id=row.asset_id,
                name=row.name,
                value=row.value,
                criticality=asset.criticality if asset else None,
                open_findings=row.open_findings,
                max_severity=rank_to_severity.get(int(row.max_rank or 0)),
                risk_score=float(row.max_risk) if row.max_risk is not None else None,
            )
        )

    # ---------------------------------------------------------- recent scans
    recent_scans = [
        RecentScan(
            id=job.id,
            reference=job.reference,
            target_name=job.target.name if job.target else None,
            profile=job.profile,
            status=job.status,
            progress=job.progress,
            findings_count=job.findings_count,
            created_at=job.created_at,
        )
        for job in db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(6).all()
    ]

    # -------------------------------------------------------- recent activity
    recent_activity = [
        ActivityItem(
            id=entry.id,
            action=entry.action,
            actor=entry.actor_email,
            description=entry.description,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            created_at=entry.created_at,
        )
        for entry in db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(12).all()
    ]

    # ----------------------------------------------------------------- trend
    trend: list[TrendPoint] = []
    for offset in range(13, -1, -1):
        day_start = (now - timedelta(days=offset)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        trend.append(
            TrendPoint(
                date=day_start.strftime("%Y-%m-%d"),
                discovered=db.query(Finding)
                .filter(Finding.created_at >= day_start, Finding.created_at < day_end)
                .count(),
                closed=db.query(Finding)
                .filter(Finding.closed_at >= day_start, Finding.closed_at < day_end)
                .count(),
            )
        )

    # --------------------------------------------------------- risk heat map
    heat_rows = (
        db.query(Finding.impact, Finding.likelihood, func.count())
        .filter(Finding.status != FindingStatus.FALSE_POSITIVE)
        .group_by(Finding.impact, Finding.likelihood)
        .all()
    )
    heat_lookup = {(i, l): c for i, l, c in heat_rows if i and l}
    risk_heatmap = [
        RiskHeatCell(impact=impact, likelihood=likelihood, count=heat_lookup.get((impact, likelihood), 0))
        for impact in ("HIGH", "MEDIUM", "LOW")
        for likelihood in ("LOW", "MEDIUM", "HIGH")
    ]

    from app.scanners.registry import scanner_registry

    return DashboardResponse(
        generated_at=now,
        demo_mode=demo_mode,
        assessments=assessments,
        findings=findings,
        remediation=remediation,
        scans=scans,
        severity_distribution=severity_distribution,
        risk_distribution=risk_distribution,
        cvss_distribution=cvss_distribution,
        status_distribution=status_distribution,
        top_risky_assets=top_risky_assets,
        recent_scans=recent_scans,
        recent_activity=recent_activity,
        trend=trend,
        risk_heatmap=risk_heatmap,
        scanner_availability=scanner_registry.availability_report(),
    )
