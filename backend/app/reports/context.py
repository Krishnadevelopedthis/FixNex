"""Assemble the data model for a generated assessment report."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.assessment import Assessment
from app.models.audit import AuditLog
from app.models.enums import SEVERITY_ORDER, FindingStatus, Severity
from app.models.finding import Finding
from app.models.scan import ScanJob
from app.models.target import ScopeRule, Target
from app.services import sla as sla_service, stats

SEVERITY_COLOURS = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#c2410c",
    Severity.MEDIUM: "#a16207",
    Severity.LOW: "#1d4ed8",
    Severity.INFORMATIONAL: "#4b5563",
}


def _executive_summary(assessment: Assessment, counters: dict, findings: list[Finding]) -> str:
    severity = counters["severity"]
    total = counters["findings_total"]
    critical_high = severity.get(Severity.CRITICAL, 0) + severity.get(Severity.HIGH, 0)

    if total == 0:
        return (
            f"The security assessment of {assessment.client_name or assessment.name} did not "
            "identify any findings within the authorised scope during this engagement."
        )

    parts = [
        f"This assessment of {assessment.client_name or assessment.name} examined "
        f"{counters['targets']} authorised target(s) across {counters['scans']} scan(s) and "
        f"produced {total} finding(s) after correlation and deduplication."
    ]
    if critical_high:
        parts.append(
            f"{critical_high} finding(s) are rated High or Critical and warrant prompt "
            "remediation; these are the issues most likely to lead to a compromise of the "
            "application or its data."
        )
    else:
        parts.append(
            "No Critical or High severity issues were identified. The findings recorded are "
            "predominantly hardening and configuration improvements."
        )
    if counters["findings_false_positive"]:
        parts.append(
            f"{counters['findings_false_positive']} scanner result(s) were manually reviewed and "
            "recorded as false positives; these are retained in the platform for audit purposes "
            "and are excluded from the risk figures above."
        )
    if counters["findings_closed"]:
        parts.append(
            f"{counters['findings_closed']} finding(s) have been remediated and confirmed closed "
            "by retest."
        )
    if counters["overdue"]:
        parts.append(
            f"{counters['overdue']} finding(s) are currently past their remediation SLA deadline."
        )
    return " ".join(parts)


def build(db: Session, assessment: Assessment, options: dict) -> dict:
    """Everything the renderers need, independent of output format."""
    query = db.query(Finding).filter(Finding.assessment_id == assessment.id)
    if not options.get("include_false_positives", False):
        query = query.filter(Finding.status != FindingStatus.FALSE_POSITIVE)
    if not options.get("include_informational", True):
        query = query.filter(Finding.severity != Severity.INFORMATIONAL)

    findings = sorted(
        query.all(),
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -(f.cvss_score or 0), f.id),
    )
    false_positives = (
        db.query(Finding)
        .filter(
            Finding.assessment_id == assessment.id,
            Finding.status == FindingStatus.FALSE_POSITIVE,
        )
        .all()
    )

    counters = stats.assessment_stats(db, assessment)
    scope_rules = db.query(ScopeRule).filter(ScopeRule.assessment_id == assessment.id).all()
    targets = db.query(Target).filter(Target.assessment_id == assessment.id).all()
    scans = (
        db.query(ScanJob)
        .filter(ScanJob.assessment_id == assessment.id)
        .order_by(ScanJob.created_at)
        .all()
    )

    scanners_used = sorted(
        {run.scanner for job in scans for run in job.scanner_runs if run.raw_findings_count}
    )

    finding_rows = []
    for finding in findings:
        sla = sla_service.evaluate(
            finding.sla_due_at,
            resolved_at=finding.closed_at,
            is_closed=finding.status in (FindingStatus.CLOSED, FindingStatus.FALSE_POSITIVE),
        )
        finding_rows.append(
            {
                "obj": finding,
                "reference": finding.reference,
                "title": finding.title,
                "severity": finding.severity,
                "severity_colour": SEVERITY_COLOURS.get(finding.severity, "#4b5563"),
                "cvss_score": finding.cvss_score,
                "cvss_vector": finding.cvss_vector,
                "risk_score": finding.risk_score,
                "risk_level": finding.risk_level,
                "cwe": f"{finding.cwe_id} — {finding.cwe_name}" if finding.cwe_id else None,
                "cves": finding.cve_ids or [],
                "status": finding.status,
                "verification_status": finding.verification_status,
                "source": finding.primary_source,
                "sources": sorted({s.scanner for s in finding.sources}) or [finding.primary_source],
                "target": finding.target.value if finding.target else None,
                "endpoint": finding.endpoint,
                "parameter": finding.parameter,
                "description": finding.description,
                "technical_details": finding.technical_details,
                "remediation": finding.remediation_recommendation,
                "references": finding.references or [],
                "data_origin": finding.data_origin,
                "assigned_to": finding.assigned_to.full_name if finding.assigned_to else None,
                "remediation_status": finding.remediation.status if finding.remediation else None,
                "sla_status": sla["status"],
                "sla_due_at": finding.sla_due_at,
                "evidence": [
                    {
                        "filename": e.filename,
                        "description": e.description,
                        "sha256": e.file_hash,
                        "uploaded_by": e.uploaded_by.full_name if e.uploaded_by else None,
                        "created_at": e.created_at,
                        "version": e.version,
                    }
                    for e in finding.evidence
                    if not e.is_deleted
                ]
                if options.get("include_evidence", True)
                else [],
                "retests": [
                    {
                        "result": r.result,
                        "summary": r.summary,
                        "performed_by": r.performed_by.full_name if r.performed_by else None,
                        "performed_at": r.performed_at,
                    }
                    for r in finding.retests
                ]
                if options.get("include_retest", True)
                else [],
            }
        )

    audit_summary = []
    if options.get("include_audit_summary", True):
        audit_summary = [
            {
                "created_at": entry.created_at,
                "actor": entry.actor_email,
                "action": entry.action,
                "description": entry.description,
            }
            for entry in db.query(AuditLog)
            .filter(AuditLog.assessment_id == assessment.id)
            .order_by(AuditLog.created_at.desc())
            .limit(40)
            .all()
        ]

    contains_demo = assessment.is_demo or any(f.is_demo for f in findings)

    return {
        "generated_at": utcnow(),
        "assessment": assessment,
        "counters": counters,
        "severity_counts": counters["severity"],
        "severity_colours": SEVERITY_COLOURS,
        "executive_summary": _executive_summary(assessment, counters, findings),
        "scope_rules": scope_rules,
        "targets": targets,
        "scans": scans,
        "scanners_used": scanners_used,
        "findings": finding_rows,
        "false_positives": [
            {
                "reference": f.reference,
                "title": f.title,
                "reason": f.false_positive_reason,
                "verified_by": f.verified_by.full_name if f.verified_by else None,
                "verified_at": f.verified_at,
            }
            for f in false_positives
        ],
        "audit_summary": audit_summary,
        "team": [
            {"name": m.user.full_name, "role": m.user.role, "assignment": m.role_in_assessment}
            for m in assessment.members
        ],
        "contains_demo_data": contains_demo,
        "options": options,
    }
