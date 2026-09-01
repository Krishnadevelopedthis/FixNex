"""Finding lifecycle transitions.

    DISCOVERED → NEEDS_VERIFICATION → CONFIRMED / FALSE_POSITIVE
              → TRIAGED → REMEDIATION → RETEST → CLOSED

Every transition is validated against ALLOWED_TRANSITIONS, appended to the
finding's own history and written to the global audit log. False positives are
never deleted — they stay for audit and history.
"""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.exceptions import ValidationError, WorkflowError
from app.db.base import utcnow
from app.models.enums import (
    FindingStatus,
    HistoryEventType,
    Priority,
    RemediationStatus,
    VerificationStatus,
)
from app.models.finding import Finding, FindingComment
from app.models.remediation import Remediation
from app.models.user import User
from app.services import audit, cwe as cwe_service, history, risk as risk_engine, sla as sla_service
from app.services.audit import AuditAction
from app.services.cvss import score_finding
from app.services.findings import ALLOWED_TRANSITIONS

# Severity drives the default remediation priority.
_SEVERITY_PRIORITY = {
    "CRITICAL": Priority.P1,
    "HIGH": Priority.P2,
    "MEDIUM": Priority.P3,
    "LOW": Priority.P4,
    "INFORMATIONAL": Priority.P4,
}


def _assert_transition(finding: Finding, new_status: str) -> None:
    if finding.status == new_status:
        return
    allowed = ALLOWED_TRANSITIONS.get(finding.status, set())
    if new_status not in allowed:
        raise WorkflowError(
            f"Finding {finding.reference} is {finding.status} and cannot move to "
            f"{new_status}. Allowed next states: {', '.join(sorted(allowed)) or 'none'}."
        )


def _recalculate_risk(db: Session, finding: Finding) -> None:
    context = risk_engine.context_from_target(finding.target)
    cvss = score_finding(finding.cvss_vector, finding.cvss_score, finding.severity)
    risk = risk_engine.calculate(
        cvss_score=finding.cvss_score,
        severity=finding.severity,
        verification_status=finding.verification_status,
        confidence=finding.confidence,
        cvss_metrics=cvss.metrics,
        exploit_available=bool((finding.risk_factors or {}).get("exploit_available")),
        **context,
    )
    finding.risk_score = risk["risk_score"]
    finding.risk_level = risk["risk_level"]
    finding.impact = risk["impact"]
    finding.likelihood = risk["likelihood"]
    finding.risk_factors = {**risk["factors"], "explanation": risk["explanation"]}


# ---------------------------------------------------------------------------
def verify(
    db: Session,
    user: User,
    finding: Finding,
    *,
    confirmed: bool,
    reason: str | None = None,
    note: str | None = None,
    request: Request | None = None,
) -> Finding:
    """Confirm a finding, or record it as a false positive with a reason."""
    new_status = FindingStatus.CONFIRMED if confirmed else FindingStatus.FALSE_POSITIVE
    _assert_transition(finding, new_status)

    if not confirmed and not (reason or "").strip():
        raise ValidationError(
            "A reason is required when marking a finding as a false positive. This is "
            "retained for audit and to justify the suppression."
        )

    previous_status = finding.status
    finding.status = new_status
    finding.verification_status = (
        VerificationStatus.CONFIRMED if confirmed else VerificationStatus.FALSE_POSITIVE
    )
    finding.verified_by_id = user.id
    finding.verified_at = utcnow()
    finding.verification_note = note
    if not confirmed:
        finding.false_positive_reason = reason
        finding.closed_at = utcnow()
    else:
        finding.false_positive_reason = None
        finding.closed_at = None

    _recalculate_risk(db, finding)

    history.record(
        db,
        finding,
        event_type=HistoryEventType.VERIFIED if confirmed else HistoryEventType.FALSE_POSITIVE,
        user=user,
        from_status=previous_status,
        to_status=new_status,
        note=(
            f"Confirmed by {user.full_name}." + (f" {note}" if note else "")
            if confirmed
            else f"Marked as a false positive by {user.full_name}. Reason: {reason}"
        ),
        metadata={"reason": reason, "note": note},
    )
    audit.record(
        db,
        action=AuditAction.FINDING_VERIFIED if confirmed else AuditAction.FINDING_FALSE_POSITIVE,
        user=user,
        resource_type="Finding",
        resource_id=finding.id,
        assessment_id=finding.assessment_id,
        description=(
            f"{finding.reference} confirmed as a genuine finding."
            if confirmed
            else f"{finding.reference} marked as a false positive: {reason}"
        ),
        old_value={"status": previous_status},
        new_value={"status": new_status, "reason": reason},
        request=request,
    )
    db.commit()
    db.refresh(finding)
    return finding


def triage(
    db: Session, user: User, finding: Finding, *, priority: str, note: str | None = None,
    request: Request | None = None,
) -> Finding:
    _assert_transition(finding, FindingStatus.TRIAGED)
    previous = finding.status
    finding.status = FindingStatus.TRIAGED
    finding.priority = priority

    history.record(
        db, finding,
        event_type=HistoryEventType.TRIAGED,
        user=user,
        from_status=previous,
        to_status=FindingStatus.TRIAGED,
        note=f"Triaged as {priority} by {user.full_name}." + (f" {note}" if note else ""),
        metadata={"priority": priority},
    )
    audit.record(
        db, action=AuditAction.FINDING_TRIAGED, user=user,
        resource_type="Finding", resource_id=finding.id, assessment_id=finding.assessment_id,
        description=f"{finding.reference} triaged as {priority}.",
        old_value={"status": previous}, new_value={"status": FindingStatus.TRIAGED, "priority": priority},
        request=request,
    )
    db.commit()
    db.refresh(finding)
    return finding


def assign(
    db: Session,
    user: User,
    finding: Finding,
    *,
    assigned_to: User,
    priority: str | None = None,
    sla_hours: int | None = None,
    recommendation: str | None = None,
    note: str | None = None,
    request: Request | None = None,
) -> Finding:
    """Assign a confirmed finding to a developer and open its remediation."""
    if finding.verification_status != VerificationStatus.CONFIRMED:
        raise WorkflowError(
            f"Finding {finding.reference} must be confirmed before it can be assigned "
            "for remediation."
        )
    _assert_transition(finding, FindingStatus.REMEDIATION)

    previous = finding.status
    priority = priority or finding.priority or _SEVERITY_PRIORITY.get(finding.severity, Priority.P3)
    now = utcnow()
    due = sla_service.due_at(finding.severity, now, db, override_hours=sla_hours)

    finding.status = FindingStatus.REMEDIATION
    finding.assigned_to_id = assigned_to.id
    finding.priority = priority
    finding.sla_due_at = due
    finding.closed_at = None

    remediation = finding.remediation
    if remediation is None:
        remediation = Remediation(finding_id=finding.id)
        db.add(remediation)
    remediation.status = RemediationStatus.OPEN
    remediation.priority = priority
    remediation.assigned_to_id = assigned_to.id
    remediation.assigned_by_id = user.id
    remediation.assigned_at = now
    remediation.sla_due_at = due
    remediation.recommendation = recommendation or finding.remediation_recommendation

    history.record(
        db, finding,
        event_type=HistoryEventType.ASSIGNED,
        user=user,
        from_status=previous,
        to_status=FindingStatus.REMEDIATION,
        note=(
            f"Assigned to {assigned_to.full_name} at {priority} with an SLA of "
            f"{due:%Y-%m-%d %H:%M} UTC." + (f" {note}" if note else "")
        ),
        metadata={"assigned_to": assigned_to.full_name, "priority": priority, "sla_due_at": due.isoformat()},
    )
    audit.record(
        db, action=AuditAction.FINDING_ASSIGNED, user=user,
        resource_type="Finding", resource_id=finding.id, assessment_id=finding.assessment_id,
        description=f"{finding.reference} assigned to {assigned_to.full_name} ({priority}).",
        old_value={"status": previous, "assigned_to_id": None},
        new_value={"status": FindingStatus.REMEDIATION, "assigned_to_id": assigned_to.id, "priority": priority},
        request=request,
    )
    db.commit()
    db.refresh(finding)
    return finding


def rescore(
    db: Session, user: User, finding: Finding, payload, request: Request | None = None
) -> Finding:
    """Update CVSS / CWE / CVE and the contextual risk inputs.

    Gated by the finding:score permission, which developers do not hold.
    """
    old = {
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "severity": finding.severity,
        "cwe_id": finding.cwe_id,
    }

    if payload.cvss_vector:
        cvss = score_finding(payload.cvss_vector, None, finding.severity)
        if cvss.vector is None or cvss.estimated:
            raise ValidationError(f"'{payload.cvss_vector}' is not a valid CVSS vector string.")
        finding.cvss_score = cvss.score
        finding.cvss_vector = cvss.vector
        finding.cvss_version = cvss.version
        finding.severity = cvss.severity
    if payload.severity:
        finding.severity = payload.severity
    if payload.cwe_id is not None:
        cwe_id = cwe_service.normalize_cwe_id(payload.cwe_id)
        entry = cwe_service.lookup(cwe_id)
        finding.cwe_id = cwe_id
        finding.cwe_name = entry["name"] if entry else None
    if payload.cve_ids is not None:
        finding.cve_ids = [c.strip().upper() for c in payload.cve_ids if c.strip()]

    context = risk_engine.context_from_target(finding.target)
    if payload.asset_criticality:
        context["asset_criticality"] = payload.asset_criticality
    if payload.data_sensitivity:
        context["data_sensitivity"] = payload.data_sensitivity
    if payload.exposure:
        context["exposure"] = payload.exposure

    cvss_now = score_finding(finding.cvss_vector, finding.cvss_score, finding.severity)
    risk = risk_engine.calculate(
        cvss_score=finding.cvss_score,
        severity=finding.severity,
        verification_status=finding.verification_status,
        confidence=finding.confidence,
        cvss_metrics=cvss_now.metrics,
        exploit_available=(
            payload.exploit_available
            if payload.exploit_available is not None
            else bool((finding.risk_factors or {}).get("exploit_available"))
        ),
        **context,
    )
    finding.risk_score = risk["risk_score"]
    finding.risk_level = risk["risk_level"]
    finding.impact = risk["impact"]
    finding.likelihood = risk["likelihood"]
    finding.risk_factors = {**risk["factors"], "explanation": risk["explanation"]}
    finding.sla_due_at = sla_service.due_at(finding.severity, finding.created_at, db)

    history.record(
        db, finding,
        event_type=HistoryEventType.SCORED,
        user=user,
        note=(
            f"Rescored by {user.full_name}: CVSS {finding.cvss_score} ({finding.severity}), "
            f"contextual risk {finding.risk_score} ({finding.risk_level})."
            + (f" {payload.note}" if payload.note else "")
        ),
        metadata={"old": old, "new": {"cvss_score": finding.cvss_score, "severity": finding.severity}},
    )
    audit.record(
        db, action=AuditAction.FINDING_SCORED, user=user,
        resource_type="Finding", resource_id=finding.id, assessment_id=finding.assessment_id,
        description=f"{finding.reference} rescored to CVSS {finding.cvss_score} ({finding.severity}).",
        old_value=old,
        new_value={"cvss_score": finding.cvss_score, "severity": finding.severity, "cwe_id": finding.cwe_id},
        request=request,
    )
    db.commit()
    db.refresh(finding)
    return finding


def suppress(
    db: Session, user: User, finding: Finding, *, suppressed: bool, reason: str | None,
    request: Request | None = None,
) -> Finding:
    if suppressed and not (reason or "").strip():
        raise ValidationError("A reason is required when suppressing a finding.")
    finding.is_suppressed = suppressed
    finding.suppression_reason = reason if suppressed else None
    history.record(
        db, finding,
        event_type=HistoryEventType.STATUS_CHANGED,
        user=user,
        note=(
            f"Suppressed by {user.full_name}: {reason}" if suppressed
            else f"Suppression removed by {user.full_name}."
        ),
    )
    audit.record(
        db, action=AuditAction.FINDING_SUPPRESSED, user=user,
        resource_type="Finding", resource_id=finding.id, assessment_id=finding.assessment_id,
        description=f"{finding.reference} suppression set to {suppressed}.",
        new_value={"is_suppressed": suppressed, "reason": reason},
        request=request,
    )
    db.commit()
    db.refresh(finding)
    return finding


def add_comment(
    db: Session, user: User, finding: Finding, body: str, request: Request | None = None
) -> FindingComment:
    comment = FindingComment(finding_id=finding.id, user_id=user.id, body=body)
    db.add(comment)
    history.record(
        db, finding,
        event_type=HistoryEventType.COMMENT,
        user=user,
        note=body[:500],
    )
    audit.record(
        db, action=AuditAction.FINDING_COMMENTED, user=user,
        resource_type="Finding", resource_id=finding.id, assessment_id=finding.assessment_id,
        description=f"Comment added to {finding.reference}.",
        request=request,
    )
    db.commit()
    db.refresh(comment)
    return comment
