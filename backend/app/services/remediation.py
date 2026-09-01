"""Remediation tracking and retest workflow."""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.exceptions import PermissionDeniedError, ValidationError, WorkflowError
from app.core.permissions import Permission
from app.db.base import utcnow
from app.models.enums import (
    FindingStatus,
    HistoryEventType,
    RemediationStatus,
    RetestResult,
)
from app.models.finding import Finding
from app.models.remediation import Remediation, Retest
from app.models.user import User
from app.schemas.findings import RemediationRead, RetestRead, SLAInfo
from app.services import audit, history, sla as sla_service
from app.services.audit import AuditAction

# Statuses a developer may set directly. RESOLVED is reachable only by a
# passing retest, so a developer can never close their own finding.
DEVELOPER_ALLOWED_STATUSES = {
    RemediationStatus.OPEN,
    RemediationStatus.IN_PROGRESS,
    RemediationStatus.READY_FOR_RETEST,
}

_TRANSITIONS: dict[str, set[str]] = {
    RemediationStatus.OPEN: {RemediationStatus.IN_PROGRESS, RemediationStatus.READY_FOR_RETEST},
    RemediationStatus.IN_PROGRESS: {RemediationStatus.READY_FOR_RETEST, RemediationStatus.OPEN},
    RemediationStatus.READY_FOR_RETEST: {RemediationStatus.RETESTING, RemediationStatus.IN_PROGRESS},
    RemediationStatus.RETESTING: {RemediationStatus.RESOLVED, RemediationStatus.REOPENED},
    RemediationStatus.REOPENED: {RemediationStatus.IN_PROGRESS, RemediationStatus.READY_FOR_RETEST},
    RemediationStatus.RESOLVED: {RemediationStatus.REOPENED},
}


def _user_brief(user: User | None):
    from app.services.findings import user_brief

    return user_brief(user)


def remediation_read(remediation: Remediation) -> RemediationRead:
    sla = sla_service.evaluate(
        remediation.sla_due_at,
        resolved_at=remediation.resolved_at,
        is_closed=remediation.status == RemediationStatus.RESOLVED,
    )
    return RemediationRead(
        id=remediation.id,
        finding_id=remediation.finding_id,
        status=remediation.status,
        priority=remediation.priority,
        recommendation=remediation.recommendation,
        developer_notes=remediation.developer_notes,
        fix_summary=remediation.fix_summary,
        assigned_to=_user_brief(remediation.assigned_to),
        assigned_by=_user_brief(remediation.assigned_by),
        assigned_at=remediation.assigned_at,
        sla_due_at=remediation.sla_due_at,
        started_at=remediation.started_at,
        ready_for_retest_at=remediation.ready_for_retest_at,
        resolved_at=remediation.resolved_at,
        reopened_count=remediation.reopened_count,
        sla=SLAInfo(**sla),
    )


def retest_read(retest: Retest) -> RetestRead:
    return RetestRead(
        id=retest.id,
        finding_id=retest.finding_id,
        result=retest.result,
        summary=retest.summary,
        method=retest.method,
        performed_at=retest.performed_at,
        performed_by=_user_brief(retest.performed_by),
        approved_at=retest.approved_at,
        approved_by=_user_brief(retest.approved_by),
        created_at=retest.created_at,
    )


def _require_remediation(finding: Finding) -> Remediation:
    if finding.remediation is None:
        raise WorkflowError(
            f"Finding {finding.reference} has no remediation record yet. It must be "
            "confirmed and assigned to a developer first."
        )
    return finding.remediation


def _assert_assignee_or_manager(user: User, remediation: Remediation) -> None:
    """A developer may only act on their own assigned work."""
    if user.has_permission(Permission.FINDING_ASSIGN) or user.has_permission(Permission.RETEST_CREATE):
        return
    if remediation.assigned_to_id != user.id:
        raise PermissionDeniedError("This finding is not assigned to you.")


def update(
    db: Session, user: User, finding: Finding, payload, request: Request | None = None
) -> Remediation:
    remediation = _require_remediation(finding)
    _assert_assignee_or_manager(user, remediation)

    old_status = remediation.status
    is_developer = not user.has_permission(Permission.FINDING_ASSIGN)

    if payload.status and payload.status != old_status:
        if is_developer and payload.status not in DEVELOPER_ALLOWED_STATUSES:
            raise PermissionDeniedError(
                f"Developers cannot set the remediation status to {payload.status}. "
                "A finding is only resolved by a passing retest."
            )
        allowed = _TRANSITIONS.get(old_status, set())
        if payload.status not in allowed:
            raise WorkflowError(
                f"Remediation is {old_status} and cannot move to {payload.status}. "
                f"Allowed: {', '.join(sorted(allowed)) or 'none'}."
            )
        remediation.status = payload.status
        if payload.status == RemediationStatus.IN_PROGRESS and remediation.started_at is None:
            remediation.started_at = utcnow()

    if payload.developer_notes is not None:
        remediation.developer_notes = payload.developer_notes
    if payload.fix_summary is not None:
        remediation.fix_summary = payload.fix_summary

    # Only a manager may re-prioritise, reassign or extend the SLA.
    if payload.priority and payload.priority != remediation.priority:
        if is_developer:
            raise PermissionDeniedError("Developers cannot change the remediation priority.")
        remediation.priority = payload.priority
        finding.priority = payload.priority
    if payload.assigned_to_id and payload.assigned_to_id != remediation.assigned_to_id:
        if is_developer:
            raise PermissionDeniedError("Developers cannot reassign a finding.")
        assignee = db.get(User, payload.assigned_to_id)
        if assignee is None:
            raise ValidationError("The assignee was not found.")
        remediation.assigned_to_id = assignee.id
        finding.assigned_to_id = assignee.id
    if payload.sla_hours:
        if is_developer:
            raise PermissionDeniedError("Developers cannot change the SLA deadline.")
        remediation.sla_due_at = sla_service.due_at(
            finding.severity, remediation.assigned_at or utcnow(), db, override_hours=payload.sla_hours
        )
        finding.sla_due_at = remediation.sla_due_at

    history.record(
        db, finding,
        event_type=HistoryEventType.REMEDIATION_UPDATED,
        user=user,
        from_status=old_status,
        to_status=remediation.status,
        note=(
            f"Remediation updated by {user.full_name}"
            + (f": {old_status} → {remediation.status}." if old_status != remediation.status else ".")
            + (f" {payload.developer_notes}" if payload.developer_notes else "")
        ),
    )
    audit.record(
        db, action=AuditAction.REMEDIATION_UPDATED, user=user,
        resource_type="Remediation", resource_id=remediation.id, assessment_id=finding.assessment_id,
        description=f"Remediation for {finding.reference} updated ({old_status} → {remediation.status}).",
        old_value={"status": old_status}, new_value={"status": remediation.status},
        request=request,
    )
    db.commit()
    db.refresh(remediation)
    return remediation


def mark_ready_for_retest(
    db: Session, user: User, finding: Finding, fix_summary: str | None = None,
    request: Request | None = None,
) -> Remediation:
    """A developer declares their fix complete and requests verification."""
    remediation = _require_remediation(finding)
    _assert_assignee_or_manager(user, remediation)

    if remediation.status not in (
        RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS, RemediationStatus.REOPENED
    ):
        raise WorkflowError(
            f"Remediation is {remediation.status} and cannot be marked ready for retest."
        )

    old_status = remediation.status
    previous_finding_status = finding.status
    now = utcnow()
    remediation.status = RemediationStatus.READY_FOR_RETEST
    remediation.ready_for_retest_at = now
    if fix_summary:
        remediation.fix_summary = fix_summary
    finding.status = FindingStatus.RETEST

    history.record(
        db, finding,
        event_type=HistoryEventType.REMEDIATION_UPDATED,
        user=user,
        from_status=previous_finding_status,
        to_status=FindingStatus.RETEST,
        note=(
            f"{user.full_name} marked the fix ready for retest."
            + (f" Summary: {fix_summary}" if fix_summary else "")
        ),
    )
    audit.record(
        db, action=AuditAction.REMEDIATION_UPDATED, user=user,
        resource_type="Remediation", resource_id=remediation.id, assessment_id=finding.assessment_id,
        description=f"{finding.reference} marked ready for retest by {user.full_name}.",
        old_value={"status": old_status}, new_value={"status": RemediationStatus.READY_FOR_RETEST},
        request=request,
    )
    db.commit()
    db.refresh(remediation)
    return remediation


def perform_retest(
    db: Session,
    user: User,
    finding: Finding,
    *,
    result: str,
    summary: str | None = None,
    method: str | None = None,
    request: Request | None = None,
) -> Retest:
    """A security engineer verifies the fix.

    PASS closes the finding; FAIL sends it back to remediation and increments
    the reopen counter. Either way the full history is preserved.
    """
    remediation = _require_remediation(finding)
    if finding.status not in (FindingStatus.RETEST, FindingStatus.REMEDIATION):
        raise WorkflowError(
            f"Finding {finding.reference} is {finding.status}; a retest can only be recorded "
            "once remediation work has been submitted."
        )

    now = utcnow()
    previous_finding_status = finding.status
    retest = Retest(
        finding_id=finding.id,
        remediation_id=remediation.id,
        result=result,
        summary=summary,
        method=method,
        performed_by_id=user.id,
        performed_at=now,
    )
    db.add(retest)

    if result == RetestResult.PASS:
        finding.status = FindingStatus.CLOSED
        finding.closed_at = now
        remediation.status = RemediationStatus.RESOLVED
        remediation.resolved_at = now
        note = f"Retest PASSED — the issue is no longer reproducible. Verified by {user.full_name}."
        action = AuditAction.RETEST_PERFORMED
        event = HistoryEventType.CLOSED
    else:
        finding.status = FindingStatus.REMEDIATION
        finding.closed_at = None
        remediation.status = RemediationStatus.REOPENED
        remediation.resolved_at = None
        remediation.reopened_count += 1
        note = (
            f"Retest FAILED — the issue is still reproducible. Returned to remediation by "
            f"{user.full_name}."
        )
        action = AuditAction.RETEST_PERFORMED
        event = HistoryEventType.REOPENED

    if summary:
        note = f"{note} {summary}"

    history.record(
        db, finding,
        event_type=HistoryEventType.RETEST_PERFORMED,
        user=user,
        from_status=previous_finding_status,
        to_status=finding.status,
        note=note,
        metadata={"result": result, "method": method},
    )
    history.record(
        db, finding,
        event_type=event,
        user=user,
        to_status=finding.status,
        note=(
            "Finding closed following a successful retest."
            if result == RetestResult.PASS
            else "Finding reopened for further remediation work."
        ),
    )
    audit.record(
        db, action=action, user=user,
        resource_type="Finding", resource_id=finding.id, assessment_id=finding.assessment_id,
        description=f"Retest of {finding.reference} recorded as {result}.",
        old_value={"status": previous_finding_status},
        new_value={"status": finding.status, "result": result},
        request=request,
    )
    db.commit()
    db.refresh(retest)
    return retest


def approve_retest(
    db: Session, user: User, retest: Retest, request: Request | None = None
) -> Retest:
    """Optional sign-off on a retest by the security lead."""
    retest.approved_by_id = user.id
    retest.approved_at = utcnow()
    history.record(
        db, retest.finding,
        event_type=HistoryEventType.RETEST_PERFORMED,
        user=user,
        note=f"Retest result approved by {user.full_name}.",
    )
    audit.record(
        db, action=AuditAction.RETEST_APPROVED, user=user,
        resource_type="Retest", resource_id=retest.id, assessment_id=retest.finding.assessment_id,
        description=f"Retest {retest.id} for {retest.finding.reference} approved.",
        request=request,
    )
    db.commit()
    db.refresh(retest)
    return retest
