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
    AssetHeatmap,
    AssessmentCounters,
    DashboardResponse,
    FindingCounters,
    RecentScan,
    PostureScore,
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
        posture=PostureScore(**posture_score(db)),
        asset_heatmap=AssetHeatmap(**asset_severity_heatmap(db)),
    )


# ---------------------------------------------------------------------------
# Asset x severity heatmap
# ---------------------------------------------------------------------------
def asset_severity_heatmap(
    db: Session, assessment_id: int | None = None, limit: int = 12
) -> dict:
    """Open finding counts per asset per severity.

    Assets are the row axis because that is how remediation is actually
    resourced — a team owns a system, not a severity band. Targets with no
    linked asset are grouped under the target itself rather than dropped.
    """
    query = (
        db.query(
            Target.id.label("target_id"),
            Target.name.label("target_name"),
            Asset.id.label("asset_id"),
            Asset.name.label("asset_name"),
            Asset.criticality.label("criticality"),
            Finding.severity.label("severity"),
            func.count(Finding.id).label("count"),
        )
        .join(Finding, Finding.target_id == Target.id)
        .outerjoin(Asset, Target.asset_id == Asset.id)
        .filter(Finding.status.in_(OPEN_STATUSES))
        .filter(Finding.verification_status != VerificationStatus.FALSE_POSITIVE)
        .filter(Finding.is_suppressed.is_(False))
    )
    if assessment_id is not None:
        query = query.filter(Finding.assessment_id == assessment_id)

    rows = query.group_by(
        Target.id, Target.name, Asset.id, Asset.name, Asset.criticality, Finding.severity
    ).all()

    # Rows are keyed by asset where one is linked, so several targets belonging
    # to the same system merge into one row rather than appearing as duplicates
    # under the same name. Targets with no asset stand on their own.
    grouped: dict[tuple[str, int], dict] = {}
    for row in rows:
        key = ("asset", row.asset_id) if row.asset_id else ("target", row.target_id)
        entry = grouped.setdefault(
            key,
            {
                "key": f"{key[0]}-{key[1]}",
                "target_id": None if row.asset_id else row.target_id,
                "asset_id": row.asset_id,
                "name": row.asset_name or row.target_name,
                "criticality": row.criticality,
                "targets": 0,
                # String keys so the payload serialises as plain JSON.
                "counts": {str(severity): 0 for severity in SEVERITIES},
                "total": 0,
            },
        )
        entry["counts"][str(row.severity)] += row.count
        entry["total"] += row.count
    # Count how many distinct targets contribute to each row.
    seen: dict[tuple[str, int], set] = {}
    for row in rows:
        key = ("asset", row.asset_id) if row.asset_id else ("target", row.target_id)
        seen.setdefault(key, set()).add(row.target_id)
    for key, targets in seen.items():
        grouped[key]["targets"] = len(targets)

    def weight(entry: dict) -> tuple:
        counts = entry["counts"]
        return (
            counts[str(Severity.CRITICAL)],
            counts[str(Severity.HIGH)],
            counts[str(Severity.MEDIUM)],
            entry["total"],
        )

    assets = sorted(grouped.values(), key=weight, reverse=True)[:limit]
    return {
        "severities": [str(s) for s in SEVERITIES],
        "assets": assets,
        "max_count": max((max(a["counts"].values()) for a in assets), default=0),
    }


# ---------------------------------------------------------------------------
# Security posture score
# ---------------------------------------------------------------------------
# Each factor deducts from a perfect 100. The weights are the maximum each
# factor can remove, so the worst possible posture floors at 0 rather than
# going negative, and no single factor can sink the score on its own.
POSTURE_WEIGHTS: dict[str, float] = {
    "open_critical": 30.0,
    "open_high": 20.0,
    "sla_breaches": 20.0,
    "unverified_backlog": 15.0,
    "ageing_findings": 15.0,
}

# Counts at which a factor reaches its full deduction.
_SATURATION = {
    "open_critical": 5,
    "open_high": 10,
    "sla_breaches": 5,
    "unverified_backlog": 20,
    "ageing_findings": 10,
}
AGEING_DAYS = 30


def posture_score(db: Session, assessment_id: int | None = None) -> dict:
    """A single 0-100 posture score, always returned with its workings.

    Every deduction is reported alongside the number so the score can be
    argued with. An unexplained score is worse than no score: nobody can act
    on "you are a 62".
    """
    now = utcnow()

    def base_query():
        query = db.query(Finding).filter(
            Finding.verification_status != VerificationStatus.FALSE_POSITIVE,
            Finding.is_suppressed.is_(False),
        )
        if assessment_id is not None:
            query = query.filter(Finding.assessment_id == assessment_id)
        return query

    open_query = base_query().filter(Finding.status.in_(OPEN_STATUSES))

    open_critical = open_query.filter(Finding.severity == Severity.CRITICAL).count()
    open_high = open_query.filter(Finding.severity == Severity.HIGH).count()
    sla_breaches = open_query.filter(
        Finding.sla_due_at.isnot(None), Finding.sla_due_at < now
    ).count()
    unverified = base_query().filter(
        Finding.status.in_([FindingStatus.DISCOVERED, FindingStatus.NEEDS_VERIFICATION])
    ).count()
    ageing = open_query.filter(Finding.first_seen_at < now - timedelta(days=AGEING_DAYS)).count()

    total_open = open_query.count()
    total_findings = base_query().count()
    closed = base_query().filter(Finding.status == FindingStatus.CLOSED).count()

    measured = {
        "open_critical": open_critical,
        "open_high": open_high,
        "sla_breaches": sla_breaches,
        "unverified_backlog": unverified,
        "ageing_findings": ageing,
    }

    labels = {
        "open_critical": "Open critical findings",
        "open_high": "Open high findings",
        "sla_breaches": "Findings past their SLA",
        "unverified_backlog": "Findings awaiting verification",
        "ageing_findings": f"Findings open longer than {AGEING_DAYS} days",
    }
    explanations = {
        "open_critical": "Unresolved critical issues are the single strongest signal of exposure.",
        "open_high": "High-severity issues compound; a backlog of them is a standing risk.",
        "sla_breaches": "Missing agreed remediation deadlines indicates the process is not keeping up.",
        "unverified_backlog": "Findings nobody has triaged are unknown risk, not absent risk.",
        "ageing_findings": "Issues that stay open for a month rarely get easier to fix.",
    }

    factors = []
    deducted = 0.0
    for key, weight in POSTURE_WEIGHTS.items():
        count = measured[key]
        saturation = _SATURATION[key]
        # Linear up to saturation, then capped at the factor's full weight.
        penalty = round(weight * min(count / saturation, 1.0), 1) if saturation else 0.0
        deducted += penalty
        factors.append({
            "key": key,
            "label": labels[key],
            "count": count,
            "penalty": penalty,
            "max_penalty": weight,
            "explanation": explanations[key],
        })

    score = round(max(0.0, 100.0 - deducted), 1)
    if score >= 85:
        grade, summary = "A", "Strong posture with no material outstanding exposure."
    elif score >= 70:
        grade, summary = "B", "Reasonable posture; a small number of issues need attention."
    elif score >= 55:
        grade, summary = "C", "Mixed posture; several findings are overdue or unverified."
    elif score >= 35:
        grade, summary = "D", "Weak posture; critical or overdue findings are accumulating."
    else:
        grade, summary = "F", "Poor posture; urgent remediation is required."

    factors.sort(key=lambda f: -f["penalty"])
    return {
        "score": score,
        "grade": grade,
        "summary": summary,
        "factors": factors,
        "totals": {
            "findings": total_findings,
            "open": total_open,
            "closed": closed,
            "resolution_rate": round(100.0 * closed / total_findings, 1) if total_findings else 0.0,
        },
        "methodology": (
            "The score starts at 100 and subtracts a weighted penalty for each factor below. "
            "Each factor has a maximum deduction and saturates at the count shown, so no "
            "single factor can sink the score on its own. It is a FixNex platform "
            "measure, not an industry standard."
        ),
    }
