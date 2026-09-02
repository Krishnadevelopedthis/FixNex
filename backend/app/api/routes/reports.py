from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import Response

from app.api.deps import CurrentUser, DbSession, Pagination, require_assessment_access, require_permission
from app.core.exceptions import ConflictError, NotFoundError
from app.core.permissions import Permission
from app.models.enums import ReportStatus
from app.models.report import Report
from app.schemas.common import Page
from app.schemas.reports import ReportCreate, ReportRead
from app.services import reports as service

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post(
    "",
    response_model=ReportRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.REPORT_CREATE))],
    summary="Generate an assessment report (PDF, CSV, JSON, XLSX or HTML)",
)
def create_report(
    payload: ReportCreate, request: Request, db: DbSession, user: CurrentUser
) -> ReportRead:
    assessment = require_assessment_access(db, user, payload.assessment_id)
    report = service.generate(db, user, assessment, payload, request)
    return service.to_read(report)


@router.get(
    "",
    response_model=Page[ReportRead],
    dependencies=[Depends(require_permission(Permission.REPORT_VIEW))],
    summary="List generated reports",
)
def list_reports(
    db: DbSession,
    user: CurrentUser,
    pagination: Pagination,
    assessment_id: Annotated[int | None, Query()] = None,
) -> Page[ReportRead]:
    """Paginated to match every other collection endpoint on this API."""
    query = db.query(Report)
    if assessment_id:
        require_assessment_access(db, user, assessment_id)
        query = query.filter(Report.assessment_id == assessment_id)

    total = query.count()
    rows = (
        query.order_by(Report.created_at.desc())
        .offset(pagination.offset)
        .limit(pagination.page_size)
        .all()
    )
    return Page.build(
        [service.to_read(r) for r in rows], total, pagination.page, pagination.page_size
    )


@router.get(
    "/{report_id}",
    response_model=ReportRead,
    dependencies=[Depends(require_permission(Permission.REPORT_VIEW))],
    summary="Report metadata",
)
def get_report(report_id: int, db: DbSession, user: CurrentUser) -> ReportRead:
    report = db.get(Report, report_id)
    if report is None:
        raise NotFoundError(f"Report {report_id} was not found.")
    require_assessment_access(db, user, report.assessment_id)
    return service.to_read(report)


@router.get(
    "/{report_id}/download",
    dependencies=[Depends(require_permission(Permission.REPORT_DOWNLOAD))],
    summary="Download a generated report",
)
def download_report(report_id: int, request: Request, db: DbSession, user: CurrentUser) -> Response:
    report = db.get(Report, report_id)
    if report is None:
        raise NotFoundError(f"Report {report_id} was not found.")
    require_assessment_access(db, user, report.assessment_id)
    if report.status != ReportStatus.READY or not report.storage_key:
        raise ConflictError(
            f"Report {report.reference} is {report.status} and cannot be downloaded."
            + (f" {report.error_message}" if report.error_message else "")
        )
    content = service.download(db, user, report, request)
    return Response(
        content=content,
        media_type=service.media_type(report.format),
        headers={
            "Content-Disposition": f'attachment; filename="{report.filename}"',
            "X-Report-SHA256": report.file_hash or "",
        },
    )
