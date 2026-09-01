"""Audit trail.

Audit records are append-only: this module offers `record()` and read helpers
and deliberately provides no update or delete operation.
"""
from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.audit import AuditLog
from app.models.user import User


class AuditAction:
    LOGIN = "auth.login"
    LOGIN_FAILED = "auth.login_failed"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGED = "auth.password_changed"

    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    ROLE_CHANGED = "user.role_changed"

    ASSESSMENT_CREATED = "assessment.created"
    ASSESSMENT_UPDATED = "assessment.updated"
    ASSESSMENT_DELETED = "assessment.deleted"
    ASSESSMENT_STATUS_CHANGED = "assessment.status_changed"
    TEAM_UPDATED = "assessment.team_updated"

    SCOPE_RULE_CREATED = "scope.rule_created"
    SCOPE_RULE_DELETED = "scope.rule_deleted"
    SCOPE_VIOLATION_BLOCKED = "scope.violation_blocked"

    ASSET_CREATED = "asset.created"
    ASSET_UPDATED = "asset.updated"

    TARGET_CREATED = "target.created"
    TARGET_UPDATED = "target.updated"
    TARGET_DELETED = "target.deleted"
    TARGET_AUTHORIZED = "target.authorized"

    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"

    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    FINDING_VERIFIED = "finding.verified"
    FINDING_FALSE_POSITIVE = "finding.false_positive"
    FINDING_TRIAGED = "finding.triaged"
    FINDING_ASSIGNED = "finding.assigned"
    FINDING_SCORED = "finding.scored"
    FINDING_CLOSED = "finding.closed"
    FINDING_REOPENED = "finding.reopened"
    FINDING_SUPPRESSED = "finding.suppressed"
    FINDING_COMMENTED = "finding.commented"

    EVIDENCE_UPLOADED = "evidence.uploaded"
    EVIDENCE_VIEWED = "evidence.viewed"
    EVIDENCE_DOWNLOADED = "evidence.downloaded"
    EVIDENCE_DELETED = "evidence.deleted"
    EVIDENCE_ANNOTATED = "evidence.annotated"

    REMEDIATION_CREATED = "remediation.created"
    REMEDIATION_UPDATED = "remediation.updated"
    RETEST_PERFORMED = "retest.performed"
    RETEST_APPROVED = "retest.approved"

    REPORT_GENERATED = "report.generated"
    REPORT_DOWNLOADED = "report.downloaded"

    SETTINGS_UPDATED = "settings.updated"
    DEMO_DATA_SEEDED = "system.demo_data_seeded"


def client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:60]
    return request.client.host[:60] if request.client else None


def record(
    db: Session,
    *,
    action: str,
    user: User | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    assessment_id: int | None = None,
    description: str | None = None,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
    request: Request | None = None,
    actor_email: str | None = None,
) -> AuditLog:
    """Append one audit record. The caller owns the transaction."""
    entry = AuditLog(
        user_id=user.id if user else None,
        actor_email=(user.email if user else actor_email),
        actor_role=user.role if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        assessment_id=assessment_id,
        description=description,
        old_value=old_value,
        new_value=new_value,
        ip_address=client_ip(request),
        user_agent=(request.headers.get("user-agent", "")[:300] or None) if request else None,
        created_at=utcnow(),
    )
    db.add(entry)
    return entry
