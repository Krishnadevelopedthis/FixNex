from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, DbSession, require_assessment_access, require_permission
from app.core.exceptions import NotFoundError
from app.core.permissions import Permission
from app.models.evidence import Evidence
from app.schemas.common import MessageResponse
from app.schemas.findings import EvidenceRead
from app.services import evidence as service, findings as finding_service

router = APIRouter(prefix="/evidence", tags=["Evidence"])


class AnnotationUpdate(BaseModel):
    annotations: list[dict] = Field(default_factory=list)


def _get(db, user, evidence_id: int) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.is_deleted:
        raise NotFoundError(f"Evidence {evidence_id} was not found.")
    require_assessment_access(db, user, evidence.finding.assessment_id)
    # Developers may only reach evidence on findings assigned to them.
    finding_service.get_finding_for_user(db, user, evidence.finding_id)
    return evidence


def _read(evidence: Evidence, integrity: bool | None = None) -> EvidenceRead:
    return EvidenceRead(
        id=evidence.id,
        finding_id=evidence.finding_id,
        filename=evidence.filename,
        content_type=evidence.content_type,
        size_bytes=evidence.size_bytes,
        file_hash=evidence.file_hash,
        description=evidence.description,
        version=evidence.version,
        supersedes_id=evidence.supersedes_id,
        is_current=evidence.is_current,
        annotations=evidence.annotations or [],
        created_at=evidence.created_at,
        uploaded_by=finding_service.user_brief(evidence.uploaded_by),
        download_url=f"/api/evidence/{evidence.id}/download",
    )


@router.get(
    "/{evidence_id}",
    response_model=EvidenceRead,
    dependencies=[Depends(require_permission(Permission.EVIDENCE_VIEW))],
    summary="Evidence metadata and chain of custody",
)
def get_evidence(evidence_id: int, db: DbSession, user: CurrentUser) -> EvidenceRead:
    return _read(_get(db, user, evidence_id))


@router.get(
    "/{evidence_id}/download",
    dependencies=[Depends(require_permission(Permission.EVIDENCE_VIEW))],
    summary="Download an evidence file (access is audited)",
)
def download_evidence(evidence_id: int, request: Request, db: DbSession, user: CurrentUser) -> Response:
    evidence = _get(db, user, evidence_id)
    content, content_type, filename = service.download(db, user, evidence, request)
    return Response(
        content=content,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Evidence-SHA256": evidence.file_hash,
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get(
    "/{evidence_id}/verify",
    dependencies=[Depends(require_permission(Permission.EVIDENCE_VIEW))],
    summary="Verify the stored file still matches its recorded SHA-256",
)
def verify_evidence(evidence_id: int, db: DbSession, user: CurrentUser) -> dict:
    evidence = _get(db, user, evidence_id)
    ok = service.verify_integrity(evidence)
    return {
        "evidence_id": evidence.id,
        "recorded_hash": evidence.file_hash,
        "integrity_verified": ok,
        "detail": (
            "The stored file matches its recorded hash."
            if ok
            else "The stored file does NOT match its recorded hash."
        ),
    }


@router.put(
    "/{evidence_id}/annotations",
    response_model=EvidenceRead,
    dependencies=[Depends(require_permission(Permission.EVIDENCE_UPLOAD))],
    summary="Save annotation overlays drawn on a screenshot",
)
def annotate_evidence(
    evidence_id: int, payload: AnnotationUpdate, request: Request, db: DbSession, user: CurrentUser
) -> EvidenceRead:
    evidence = _get(db, user, evidence_id)
    return _read(service.annotate(db, user, evidence, payload.annotations, request))


@router.delete(
    "/{evidence_id}",
    response_model=MessageResponse,
    dependencies=[Depends(require_permission(Permission.EVIDENCE_DELETE))],
    summary="Withdraw evidence (soft delete; the custody record is retained)",
)
def delete_evidence(
    evidence_id: int, request: Request, db: DbSession, user: CurrentUser
) -> MessageResponse:
    evidence = _get(db, user, evidence_id)
    service.soft_delete(db, user, evidence, request)
    return MessageResponse(
        message="Evidence withdrawn.",
        detail="The metadata and hash are retained for audit purposes.",
    )
