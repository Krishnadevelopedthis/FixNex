"""Cross-assessment remediation queue (the 'my work' view for developers)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import CurrentUser, DbSession, Pagination, require_permission
from app.core.permissions import Permission
from app.db.base import utcnow
from app.models.enums import RemediationStatus
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.schemas.common import Page
from app.schemas.findings import FindingListItem
from app.services import findings as finding_service

router = APIRouter(prefix="/remediation", tags=["Remediation"])


@router.get(
    "",
    response_model=Page[FindingListItem],
    dependencies=[Depends(require_permission(Permission.REMEDIATION_VIEW))],
    summary="Remediation queue",
)
def remediation_queue(
    db: DbSession,
    user: CurrentUser,
    pagination: Pagination,
    status_filter: Annotated[list[RemediationStatus] | None, Query(alias="status")] = None,
    assigned_to_id: Annotated[int | None, Query()] = None,
    assessment_id: Annotated[int | None, Query()] = None,
    overdue_only: bool = False,
    mine: bool = False,
) -> Page[FindingListItem]:
    query = finding_service.visible_findings_query(db, user).join(
        Remediation, Remediation.finding_id == Finding.id
    )
    if status_filter:
        query = query.filter(Remediation.status.in_([s.value for s in status_filter]))
    if assigned_to_id:
        query = query.filter(Remediation.assigned_to_id == assigned_to_id)
    if mine:
        query = query.filter(Remediation.assigned_to_id == user.id)
    if assessment_id:
        query = query.filter(Finding.assessment_id == assessment_id)
    if overdue_only:
        query = query.filter(
            Remediation.sla_due_at.isnot(None),
            Remediation.sla_due_at < utcnow(),
            Remediation.status != RemediationStatus.RESOLVED,
        )

    total = query.count()
    rows = (
        query.order_by(Remediation.sla_due_at.asc().nullslast(), Finding.id.desc())
        .offset(pagination.offset)
        .limit(pagination.page_size)
        .all()
    )
    return Page.build(
        [finding_service.to_list_item(f) for f in rows], total, pagination.page, pagination.page_size
    )
