from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile, status

from app.api.deps import (
    CurrentUser,
    DbSession,
    Pagination,
    require_assessment_access,
    require_permission,
)
from app.core.exceptions import NotFoundError, ValidationError
from app.core.permissions import Permission
from app.models.enums import FindingStatus, Severity
from app.models.user import User
from app.schemas.common import MessageResponse, Page
from app.schemas.findings import (
    AITriageSuggestion,
    EvidenceRead,
    FindingAssignRequest,
    FindingCommentCreate,
    FindingCommentRead,
    FindingCreate,
    FindingDetail,
    FindingListItem,
    FindingScoreUpdate,
    FindingSuppressRequest,
    FindingTriageRequest,
    FindingUpdate,
    FindingVerifyRequest,
    RemediationRead,
    RetestRead,
)
from app.schemas.remediation import (
    ReadyForRetestRequest,
    RemediationCreate,
    RemediationUpdate,
    RetestCreate,
)
from app.services import ai_triage as ai_triage_service
from app.services import audit, evidence as evidence_service, findings as service
from app.services import remediation as remediation_service, workflow
from app.services.audit import AuditAction

router = APIRouter(prefix="/findings", tags=["Findings"])


def _evidence_url(evidence_id: int) -> str:
    return f"/api/evidence/{evidence_id}/download"


def _detail(finding) -> FindingDetail:
    return service.to_detail(finding, evidence_url_builder=_evidence_url)


@router.get(
    "",
    response_model=Page[FindingListItem],
    dependencies=[Depends(require_permission(Permission.FINDING_VIEW))],
    summary="Search and filter findings",
)
def list_findings(
    db: DbSession,
    user: CurrentUser,
    pagination: Pagination,
    assessment_id: Annotated[int | None, Query()] = None,
    target_id: Annotated[int | None, Query()] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    status_filter: Annotated[list[FindingStatus] | None, Query(alias="status")] = None,
    source: Annotated[list[str] | None, Query()] = None,
    risk_level: Annotated[list[Severity] | None, Query()] = None,
    cwe: Annotated[str | None, Query(max_length=20)] = None,
    cve: Annotated[str | None, Query(max_length=30)] = None,
    assigned_to_id: Annotated[int | None, Query()] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    sla_status: Annotated[str | None, Query()] = None,
    include_false_positive: bool = True,
    include_demo: bool = True,
    sort_by: str = "severity",
    order: str = "desc",
) -> Page[FindingListItem]:
    if assessment_id:
        require_assessment_access(db, user, assessment_id)

    query = service.visible_findings_query(db, user)
    query = service.apply_filters(
        query,
        {
            "assessment_id": assessment_id,
            "target_id": target_id,
            "severity": [s.value for s in severity] if severity else None,
            "status": [s.value for s in status_filter] if status_filter else None,
            "source": source,
            "risk_level": [r.value for r in risk_level] if risk_level else None,
            "cwe": cwe,
            "cve": cve,
            "assigned_to_id": assigned_to_id,
            "search": search,
            "sla_status": sla_status,
            "include_false_positive": include_false_positive,
            "include_demo": include_demo,
        },
    )
    total = query.count()
    rows = (
        service.apply_sort(query, sort_by, order)
        .offset(pagination.offset)
        .limit(pagination.page_size)
        .all()
    )
    return Page.build(
        [service.to_list_item(f) for f in rows], total, pagination.page, pagination.page_size
    )


@router.post(
    "",
    response_model=FindingDetail,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.FINDING_CREATE))],
    summary="Raise a finding from manual testing",
)
def create_finding(
    payload: FindingCreate, request: Request, db: DbSession, user: CurrentUser
) -> FindingDetail:
    require_assessment_access(db, user, payload.assessment_id)
    return _detail(service.create_manual_finding(db, user, payload, request))


@router.get(
    "/{finding_id}",
    response_model=FindingDetail,
    dependencies=[Depends(require_permission(Permission.FINDING_VIEW))],
    summary="Full finding detail",
)
def get_finding(finding_id: int, db: DbSession, user: CurrentUser) -> FindingDetail:
    return _detail(service.get_finding_for_user(db, user, finding_id))


@router.patch(
    "/{finding_id}",
    response_model=FindingDetail,
    dependencies=[Depends(require_permission(Permission.FINDING_UPDATE))],
    summary="Edit a finding's descriptive fields",
)
def update_finding(
    finding_id: int, payload: FindingUpdate, request: Request, db: DbSession, user: CurrentUser
) -> FindingDetail:
    finding = service.get_finding_for_user(db, user, finding_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(finding, field, value)
    audit.record(
        db,
        action=AuditAction.FINDING_UPDATED,
        user=user,
        resource_type="Finding",
        resource_id=finding.id,
        assessment_id=finding.assessment_id,
        description=f"{finding.reference} updated.",
        request=request,
    )
    db.commit()
    db.refresh(finding)
    return _detail(finding)


@router.post(
    "/{finding_id}/verify",
    response_model=FindingDetail,
    dependencies=[Depends(require_permission(Permission.FINDING_VERIFY))],
    summary="Confirm a finding, or record it as a false positive",
)
def verify_finding(
    finding_id: int, payload: FindingVerifyRequest, request: Request, db: DbSession, user: CurrentUser
) -> FindingDetail:
    finding = service.get_finding_for_user(db, user, finding_id)
    finding = workflow.verify(
        db, user, finding,
        confirmed=payload.confirmed, reason=payload.reason, note=payload.note, request=request,
    )
    return _detail(finding)


@router.post(
    "/{finding_id}/triage",
    response_model=FindingDetail,
    dependencies=[Depends(require_permission(Permission.FINDING_TRIAGE))],
    summary="Triage a confirmed finding",
)
def triage_finding(
    finding_id: int, payload: FindingTriageRequest, request: Request, db: DbSession, user: CurrentUser
) -> FindingDetail:
    finding = service.get_finding_for_user(db, user, finding_id)
    return _detail(
        workflow.triage(db, user, finding, priority=payload.priority, note=payload.note, request=request)
    )


@router.post(
    "/{finding_id}/assign",
    response_model=FindingDetail,
    dependencies=[Depends(require_permission(Permission.FINDING_ASSIGN))],
    summary="Assign a finding to a developer for remediation",
)
def assign_finding(
    finding_id: int, payload: FindingAssignRequest, request: Request, db: DbSession, user: CurrentUser
) -> FindingDetail:
    finding = service.get_finding_for_user(db, user, finding_id)
    assignee = db.get(User, payload.assigned_to_id)
    if assignee is None:
        raise ValidationError(f"User {payload.assigned_to_id} was not found.")
    finding = workflow.assign(
        db, user, finding,
        assigned_to=assignee,
        priority=payload.priority,
        sla_hours=payload.sla_hours,
        recommendation=payload.recommendation,
        note=payload.note,
        request=request,
    )
    return _detail(finding)


@router.post(
    "/{finding_id}/score",
    response_model=FindingDetail,
    dependencies=[Depends(require_permission(Permission.FINDING_SCORE))],
    summary="Update CVSS, CWE/CVE and contextual risk inputs",
)
def score_finding(
    finding_id: int, payload: FindingScoreUpdate, request: Request, db: DbSession, user: CurrentUser
) -> FindingDetail:
    finding = service.get_finding_for_user(db, user, finding_id)
    return _detail(workflow.rescore(db, user, finding, payload, request))


@router.post(
    "/{finding_id}/suppress",
    response_model=FindingDetail,
    dependencies=[Depends(require_permission(Permission.FINDING_SUPPRESS))],
    summary="Suppress or unsuppress a finding",
)
def suppress_finding(
    finding_id: int, payload: FindingSuppressRequest, request: Request, db: DbSession, user: CurrentUser
) -> FindingDetail:
    finding = service.get_finding_for_user(db, user, finding_id)
    return _detail(
        workflow.suppress(
            db, user, finding, suppressed=payload.suppressed, reason=payload.reason, request=request
        )
    )


@router.post(
    "/{finding_id}/comments",
    response_model=FindingCommentRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.FINDING_COMMENT))],
    summary="Comment on a finding",
)
def comment_on_finding(
    finding_id: int, payload: FindingCommentCreate, request: Request, db: DbSession, user: CurrentUser
) -> FindingCommentRead:
    finding = service.get_finding_for_user(db, user, finding_id)
    comment = workflow.add_comment(db, user, finding, payload.body, request)
    return FindingCommentRead(
        id=comment.id, body=comment.body, created_at=comment.created_at, user=service.user_brief(user)
    )


# ------------------------------------------------------------------- evidence
@router.get(
    "/{finding_id}/evidence",
    response_model=list[EvidenceRead],
    dependencies=[Depends(require_permission(Permission.EVIDENCE_VIEW))],
    summary="List a finding's evidence",
)
def list_evidence(finding_id: int, db: DbSession, user: CurrentUser) -> list[EvidenceRead]:
    finding = service.get_finding_for_user(db, user, finding_id)
    return _detail(finding).evidence


@router.post(
    "/{finding_id}/evidence",
    response_model=EvidenceRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.EVIDENCE_UPLOAD))],
    summary="Upload evidence (screenshot, request/response, notes)",
)
def upload_evidence(
    finding_id: int,
    request: Request,
    db: DbSession,
    user: CurrentUser,
    file: Annotated[UploadFile, File(description="Evidence file")],
    description: Annotated[str | None, Form()] = None,
    supersedes_id: Annotated[int | None, Form()] = None,
) -> EvidenceRead:
    finding = service.get_finding_for_user(db, user, finding_id)
    item = evidence_service.upload(
        db, user, finding, file,
        description=description, supersedes_id=supersedes_id, request=request,
    )
    return EvidenceRead(
        id=item.id,
        finding_id=item.finding_id,
        filename=item.filename,
        content_type=item.content_type,
        size_bytes=item.size_bytes,
        file_hash=item.file_hash,
        description=item.description,
        version=item.version,
        supersedes_id=item.supersedes_id,
        is_current=item.is_current,
        annotations=item.annotations or [],
        created_at=item.created_at,
        uploaded_by=service.user_brief(user),
        download_url=_evidence_url(item.id),
    )


# ---------------------------------------------------------------- remediation
@router.post(
    "/{finding_id}/remediation",
    response_model=RemediationRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.FINDING_ASSIGN))],
    summary="Open remediation and assign an owner",
)
def create_remediation(
    finding_id: int, payload: RemediationCreate, request: Request, db: DbSession, user: CurrentUser
) -> RemediationRead:
    finding = service.get_finding_for_user(db, user, finding_id)
    assignee = db.get(User, payload.assigned_to_id)
    if assignee is None:
        raise ValidationError(f"User {payload.assigned_to_id} was not found.")
    finding = workflow.assign(
        db, user, finding,
        assigned_to=assignee,
        priority=payload.priority,
        sla_hours=payload.sla_hours,
        recommendation=payload.recommendation,
        note=payload.note,
        request=request,
    )
    return remediation_service.remediation_read(finding.remediation)


@router.patch(
    "/{finding_id}/remediation",
    response_model=RemediationRead,
    dependencies=[Depends(require_permission(Permission.REMEDIATION_UPDATE))],
    summary="Update remediation status and developer notes",
)
def update_remediation(
    finding_id: int, payload: RemediationUpdate, request: Request, db: DbSession, user: CurrentUser
) -> RemediationRead:
    finding = service.get_finding_for_user(db, user, finding_id)
    return remediation_service.remediation_read(
        remediation_service.update(db, user, finding, payload, request)
    )


@router.post(
    "/{finding_id}/ready-for-retest",
    response_model=RemediationRead,
    dependencies=[Depends(require_permission(Permission.RETEST_REQUEST))],
    summary="Developer marks the fix ready for retest",
)
def ready_for_retest(
    finding_id: int, payload: ReadyForRetestRequest, request: Request, db: DbSession, user: CurrentUser
) -> RemediationRead:
    finding = service.get_finding_for_user(db, user, finding_id)
    return remediation_service.remediation_read(
        remediation_service.mark_ready_for_retest(db, user, finding, payload.fix_summary, request)
    )


# --------------------------------------------------------------------- retest
@router.post(
    "/{finding_id}/retest",
    response_model=RetestRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.RETEST_CREATE))],
    summary="Record a retest result (PASS closes the finding)",
)
def perform_retest(
    finding_id: int, payload: RetestCreate, request: Request, db: DbSession, user: CurrentUser
) -> RetestRead:
    finding = service.get_finding_for_user(db, user, finding_id)
    retest = remediation_service.perform_retest(
        db, user, finding,
        result=payload.result, summary=payload.summary, method=payload.method, request=request,
    )
    return remediation_service.retest_read(retest)


@router.get(
    "/{finding_id}/retests",
    response_model=list[RetestRead],
    dependencies=[Depends(require_permission(Permission.FINDING_VIEW))],
    summary="Retest history for a finding",
)
def list_retests(finding_id: int, db: DbSession, user: CurrentUser) -> list[RetestRead]:
    finding = service.get_finding_for_user(db, user, finding_id)
    return [remediation_service.retest_read(r) for r in finding.retests]


@router.get(
    "/{finding_id}/ai-triage",
    response_model=AITriageSuggestion,
    dependencies=[Depends(require_permission(Permission.FINDING_VIEW))],
    summary="AI-assisted triage suggestion for a finding",
)
def ai_triage(
    finding_id: int,
    db: DbSession,
    user: CurrentUser,
    refresh: Annotated[bool, Query(description="Ignore the cached suggestion")] = False,
) -> AITriageSuggestion:
    """Ask a model how likely this finding is a false positive, and how to fix it.

    The result is advisory. This endpoint does not modify the finding's
    verification status, severity, risk or workflow state — the analyst still
    confirms or rejects it through the normal verify action. Requires an
    ANTHROPIC_API_KEY; without one it returns 503 and nothing else changes.
    """
    finding = service.get_finding_for_user(db, user, finding_id)
    return AITriageSuggestion(**ai_triage_service.suggest(db, finding, refresh=refresh))
