from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import CurrentUser, DbSession, Pagination, require_permission
from app.core.permissions import Permission
from app.models.audit import AuditLog
from app.schemas.audit import AuditLogRead
from app.schemas.common import Page
from app.services.audit import AuditAction
from app.services.findings import user_brief

router = APIRouter(prefix="/audit-logs", tags=["Audit"])


@router.get(
    "",
    response_model=Page[AuditLogRead],
    dependencies=[Depends(require_permission(Permission.AUDIT_VIEW))],
    summary="Read the immutable audit trail",
)
def list_audit_logs(
    db: DbSession,
    user: CurrentUser,
    pagination: Pagination,
    action: Annotated[list[str] | None, Query()] = None,
    resource_type: Annotated[str | None, Query(max_length=60)] = None,
    assessment_id: Annotated[int | None, Query()] = None,
    user_id: Annotated[int | None, Query()] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    date_from: Annotated[datetime | None, Query()] = None,
    date_to: Annotated[datetime | None, Query()] = None,
) -> Page[AuditLogRead]:
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action.in_(action))
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if assessment_id:
        query = query.filter(AuditLog.assessment_id == assessment_id)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            AuditLog.description.ilike(term)
            | AuditLog.actor_email.ilike(term)
            | AuditLog.action.ilike(term)
        )
    if date_from:
        query = query.filter(AuditLog.created_at >= date_from)
    if date_to:
        query = query.filter(AuditLog.created_at <= date_to)

    total = query.count()
    rows = (
        query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset(pagination.offset)
        .limit(pagination.page_size)
        .all()
    )
    items = [
        AuditLogRead(
            id=entry.id,
            action=entry.action,
            actor_email=entry.actor_email,
            actor_role=entry.actor_role,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            assessment_id=entry.assessment_id,
            description=entry.description,
            old_value=entry.old_value,
            new_value=entry.new_value,
            ip_address=entry.ip_address,
            created_at=entry.created_at,
            user=user_brief(entry.user),
        )
        for entry in rows
    ]
    return Page.build(items, total, pagination.page, pagination.page_size)


@router.get(
    "/actions",
    response_model=list[str],
    dependencies=[Depends(require_permission(Permission.AUDIT_VIEW))],
    summary="Every audit action the platform records",
)
def list_actions(user: CurrentUser) -> list[str]:
    return sorted(
        value for key, value in vars(AuditAction).items()
        if not key.startswith("_") and isinstance(value, str)
    )
