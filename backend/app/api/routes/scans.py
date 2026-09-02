from __future__ import annotations

import asyncio
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)

from app.api.deps import CurrentUser, DbSession, Pagination, require_assessment_access, require_permission
from app.core.config import settings
from app.core.exceptions import NotFoundError, ValidationError
from app.core.permissions import Permission
from app.db.session import SessionLocal
from app.models.enums import ScanStatus
from app.models.scan import ScanJob
from app.schemas.common import Page
from app.schemas.scans import (
    ScanCreate,
    ScanListItem,
    ScannerInfo,
    ScannerRunRead,
    ScanProfileInfo,
    ScanRead,
)
from app.scanners.registry import profile_info, scanner_registry
from app.services import scanning as service
from app.services.findings import scanner_label, user_brief

router = APIRouter(prefix="/scans", tags=["Scans"])


def _to_read(job: ScanJob, include_commands: bool = False) -> ScanRead:
    return ScanRead(
        id=job.id,
        reference=job.reference,
        assessment_id=job.assessment_id,
        assessment_name=job.assessment.name if job.assessment else None,
        target_id=job.target_id,
        target_name=job.target.name if job.target else None,
        target_value=job.target.value if job.target else None,
        profile=job.profile,
        status=job.status,
        progress=job.progress,
        current_operation=job.current_operation,
        requested_scanners=job.requested_scanners or [],
        findings_count=job.findings_count,
        raw_findings_count=job.raw_findings_count,
        duplicates_merged=job.duplicates_merged,
        started_at=job.started_at,
        completed_at=job.completed_at,
        duration_seconds=job.duration_seconds,
        error_message=job.error_message,
        task_runner=job.task_runner,
        created_at=job.created_at,
        created_by=user_brief(job.created_by),
        scanner_runs=[
            ScannerRunRead(
                id=run.id,
                scanner=run.scanner,
                scanner_label=scanner_label(run.scanner),
                status=run.status,
                started_at=run.started_at,
                completed_at=run.completed_at,
                duration_ms=run.duration_ms,
                exit_code=run.exit_code,
                raw_findings_count=run.raw_findings_count,
                error_message=run.error_message,
                tool_version=run.tool_version,
                # Raw command lines are only shown to users who can view system internals.
                command_summary=run.command_summary if include_commands else None,
                metrics=run.metrics or {},
            )
            for run in job.scanner_runs
        ],
    )


def _to_list_item(job: ScanJob) -> ScanListItem:
    return ScanListItem(
        id=job.id,
        reference=job.reference,
        assessment_id=job.assessment_id,
        target_id=job.target_id,
        target_name=job.target.name if job.target else None,
        profile=job.profile,
        status=job.status,
        progress=job.progress,
        findings_count=job.findings_count,
        started_at=job.started_at,
        completed_at=job.completed_at,
        created_at=job.created_at,
    )


@router.get("/profiles", response_model=list[ScanProfileInfo], summary="Available scan profiles")
def list_profiles(user: CurrentUser, target_type: str = "WEB_APP") -> list[ScanProfileInfo]:
    return [ScanProfileInfo(**p) for p in profile_info(target_type)]


@router.get("/scanners", response_model=list[ScannerInfo], summary="Registered scanner adapters")
def list_scanners(user: CurrentUser) -> list[ScannerInfo]:
    return [ScannerInfo(**s) for s in scanner_registry.availability_report()]


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_permission(Permission.SCAN_CREATE))],
    summary="Start a scan against an authorised target",
)
def create_scan(payload: ScanCreate, request: Request, db: DbSession, user: CurrentUser) -> ScanRead:
    require_assessment_access(db, user, payload.assessment_id)
    job = service.create_scan_job(
        db,
        user,
        assessment_id=payload.assessment_id,
        target_id=payload.target_id,
        profile=payload.profile,
        scanners=payload.scanners,
        authorization_confirmed=payload.authorization_confirmed,
        request=request,
    )
    return _to_read(job, include_commands=user.has_permission(Permission.SYSTEM_VIEW))


@router.get(
    "",
    response_model=Page[ScanListItem],
    dependencies=[Depends(require_permission(Permission.SCAN_VIEW))],
    summary="List scans",
)
def list_scans(
    db: DbSession,
    user: CurrentUser,
    pagination: Pagination,
    assessment_id: Annotated[int | None, Query()] = None,
    status_filter: Annotated[list[ScanStatus] | None, Query(alias="status")] = None,
) -> Page[ScanListItem]:
    query = db.query(ScanJob)
    if assessment_id:
        require_assessment_access(db, user, assessment_id)
        query = query.filter(ScanJob.assessment_id == assessment_id)
    if status_filter:
        query = query.filter(ScanJob.status.in_([s.value for s in status_filter]))
    total = query.count()
    rows = (
        query.order_by(ScanJob.created_at.desc())
        .offset(pagination.offset)
        .limit(pagination.page_size)
        .all()
    )
    return Page.build([_to_list_item(j) for j in rows], total, pagination.page, pagination.page_size)


@router.get(
    "/{scan_id}",
    response_model=ScanRead,
    dependencies=[Depends(require_permission(Permission.SCAN_VIEW))],
    summary="Scan detail with per-scanner execution metadata",
)
def get_scan(scan_id: int, db: DbSession, user: CurrentUser) -> ScanRead:
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise NotFoundError(f"Scan {scan_id} was not found.")
    require_assessment_access(db, user, job.assessment_id)
    return _to_read(job, include_commands=user.has_permission(Permission.SYSTEM_VIEW))


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanRead,
    dependencies=[Depends(require_permission(Permission.SCAN_CANCEL))],
    summary="Request cancellation of a running scan",
)
def cancel_scan(scan_id: int, request: Request, db: DbSession, user: CurrentUser) -> ScanRead:
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise NotFoundError(f"Scan {scan_id} was not found.")
    require_assessment_access(db, user, job.assessment_id)
    job = service.cancel_scan_job(db, user, job, request)
    return _to_read(job, include_commands=user.has_permission(Permission.SYSTEM_VIEW))


# Tools whose SARIF output is commonly imported. The list is advisory — any tool
# emitting SARIF 2.1.0 is accepted, this only drives the UI picker.
KNOWN_SARIF_TOOLS = [
    "semgrep", "trivy", "gitleaks", "snyk", "checkov", "codeql",
    "sonarqube", "bandit", "tfsec", "grype", "kics", "eslint",
]


@router.get(
    "/import/tools",
    response_model=list[str],
    dependencies=[Depends(require_permission(Permission.SCAN_CREATE))],
    summary="Tools commonly imported via SARIF",
)
def sarif_tools() -> list[str]:
    return KNOWN_SARIF_TOOLS


@router.post(
    "/import",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.SCAN_CREATE))],
    summary="Import a SARIF report produced by another tool",
)
def import_scan(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    assessment_id: Annotated[int, Form(description="Assessment to attach the findings to")],
    target_id: Annotated[int, Form(description="Authorised target the results relate to")],
    tool_name: Annotated[str, Form(description="Tool that produced the report, e.g. semgrep")],
    file: Annotated[UploadFile, File(description="SARIF 2.1.0 document")],
) -> ScanRead:
    """Ingest results from any SARIF-emitting scanner.

    The upload is parsed into the platform's normalised finding format and run
    through the same pipeline as a live scan, so correlation, CVSS/CWE scoring,
    contextual risk and SLA all apply. Findings are recorded with an IMPORTED
    origin and an `imported:<tool>` source so their provenance stays explicit —
    they are never presented as a scan FixNex executed.
    """
    require_assessment_access(db, user, assessment_id)

    raw = file.file.read()
    if not raw:
        raise ValidationError("The uploaded file is empty.")

    job = service.import_scan_results(
        db,
        user,
        assessment_id=assessment_id,
        target_id=target_id,
        tool_name=tool_name,
        raw=raw,
        request=request,
    )
    return _to_read(job, include_commands=user.has_permission(Permission.SYSTEM_VIEW))


@router.websocket("/{scan_id}/progress")
async def scan_progress(websocket: WebSocket, scan_id: int, token: str = Query(...)) -> None:
    """Live scan progress.

    Progress is read from the database, so this works identically whether the
    scan is executing in a Celery worker or in the in-process thread runner.
    """
    from app.security.tokens import decode_token

    await websocket.accept()
    try:
        decode_token(token, expected_type="access")
    except Exception:
        await websocket.send_json({"error": "Invalid or expired token."})
        await websocket.close(code=4401)
        return

    last_payload: dict | None = None
    # A socket must not outlive the scan it is watching. Without a deadline a
    # client watching a job that never terminates keeps the connection - and
    # the server's graceful shutdown - open indefinitely.
    deadline = asyncio.get_event_loop().time() + settings.SCANNER_TIMEOUT_SECONDS + 120
    try:
        while asyncio.get_event_loop().time() < deadline:
            db = SessionLocal()
            try:
                job = db.get(ScanJob, scan_id)
                if job is None:
                    await websocket.send_json({"error": "Scan not found."})
                    break
                payload = {
                    "id": job.id,
                    "reference": job.reference,
                    "status": job.status,
                    "progress": job.progress,
                    "current_operation": job.current_operation,
                    "findings_count": job.findings_count,
                    "raw_findings_count": job.raw_findings_count,
                    "duplicates_merged": job.duplicates_merged,
                    "scanner_runs": [
                        {
                            "scanner": r.scanner,
                            "label": scanner_label(r.scanner),
                            "status": r.status,
                            "raw_findings_count": r.raw_findings_count,
                            "error_message": r.error_message,
                        }
                        for r in job.scanner_runs
                    ],
                }
                finished = job.status in (
                    ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED
                )
            finally:
                db.close()

            if payload != last_payload:
                await websocket.send_json(payload)
                last_payload = payload
            if finished:
                break
            await asyncio.sleep(1)
        else:
            # Fell out on the deadline rather than on completion.
            await websocket.send_json(
                {"error": "This progress stream timed out. Reload to resume watching."}
            )
    except WebSocketDisconnect:
        return
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass
