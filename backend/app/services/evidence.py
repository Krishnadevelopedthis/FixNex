"""Evidence management with chain of custody.

Files are written to object storage; PostgreSQL keeps the metadata, the
SHA-256 hash and the version chain. Evidence is never overwritten in place:
replacing a file creates a new version that supersedes the previous one, so the
custody trail stays intact.
"""
from __future__ import annotations

import re
import uuid

from fastapi import Request, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import NotFoundError, ValidationError
from app.models.enums import HistoryEventType
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.user import User
from app.services import audit, history
from app.services.audit import AuditAction
from app.storage import get_storage, sha256_hex

_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]")
_MAX_FILENAME_LENGTH = 120

# Magic bytes checked against the declared content type for image uploads.
_MAGIC_SIGNATURES: dict[str, tuple[bytes, ...]] = {
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/gif": (b"GIF87a", b"GIF89a"),
    "image/webp": (b"RIFF",),
    "application/pdf": (b"%PDF-",),
}


def sanitize_filename(filename: str | None) -> str:
    """Strip any path component and unsafe characters from an uploaded name."""
    name = (filename or "evidence").replace("\\", "/").split("/")[-1]
    name = _SAFE_FILENAME.sub("_", name).lstrip(".") or "evidence"
    if len(name) > _MAX_FILENAME_LENGTH:
        stem, _, extension = name.rpartition(".")
        name = f"{stem[:_MAX_FILENAME_LENGTH - len(extension) - 1]}.{extension}" if extension else name[:_MAX_FILENAME_LENGTH]
    return name


def _validate(content: bytes, content_type: str, filename: str) -> None:
    if not content:
        raise ValidationError("The uploaded file is empty.")
    if len(content) > settings.MAX_UPLOAD_BYTES:
        limit_mb = settings.MAX_UPLOAD_BYTES / (1024 * 1024)
        raise ValidationError(f"The file exceeds the {limit_mb:.0f} MB upload limit.")
    if content_type not in settings.allowed_evidence_types:
        raise ValidationError(
            f"'{content_type}' is not an accepted evidence type. Allowed types: "
            + ", ".join(sorted(settings.allowed_evidence_types))
        )
    signatures = _MAGIC_SIGNATURES.get(content_type)
    if signatures and not any(content.startswith(sig) for sig in signatures):
        raise ValidationError(
            f"The file contents do not match the declared type '{content_type}'."
        )


def storage_key(finding: Finding, filename: str) -> str:
    return (
        f"assessments/{finding.assessment_id}/findings/{finding.id}/"
        f"{uuid.uuid4().hex}_{filename}"
    )


def upload(
    db: Session,
    user: User,
    finding: Finding,
    file: UploadFile,
    *,
    description: str | None = None,
    supersedes_id: int | None = None,
    request: Request | None = None,
) -> Evidence:
    content = file.file.read()
    filename = sanitize_filename(file.filename)
    content_type = (file.content_type or "application/octet-stream").split(";")[0].strip()
    _validate(content, content_type, filename)

    digest = sha256_hex(content)
    version = 1
    superseded: Evidence | None = None

    if supersedes_id is not None:
        superseded = db.get(Evidence, supersedes_id)
        if superseded is None or superseded.finding_id != finding.id:
            raise NotFoundError("The evidence item being replaced was not found on this finding.")
        version = superseded.version + 1
        superseded.is_current = False

    storage = get_storage()
    key = storage_key(finding, filename)
    storage.put(key, content, content_type)

    evidence = Evidence(
        finding_id=finding.id,
        filename=filename,
        storage_key=key,
        storage_backend=storage.name,
        content_type=content_type,
        size_bytes=len(content),
        file_hash=digest,
        description=description,
        version=version,
        supersedes_id=superseded.id if superseded else None,
        is_current=True,
        uploaded_by_id=user.id,
    )
    db.add(evidence)
    db.flush()

    history.record(
        db,
        finding,
        event_type=HistoryEventType.EVIDENCE_ADDED,
        user=user,
        note=(
            f"{user.full_name} uploaded evidence '{filename}'"
            + (f" (version {version}, replacing #{superseded.id})" if superseded else "")
            + f". SHA-256 {digest[:16]}…"
        ),
        metadata={"evidence_id": evidence.id, "sha256": digest, "version": version},
    )
    audit.record(
        db,
        action=AuditAction.EVIDENCE_UPLOADED,
        user=user,
        resource_type="Evidence",
        resource_id=evidence.id,
        assessment_id=finding.assessment_id,
        description=f"Evidence '{filename}' uploaded to {finding.reference} (SHA-256 {digest}).",
        new_value={
            "filename": filename,
            "sha256": digest,
            "size_bytes": len(content),
            "version": version,
        },
        request=request,
    )
    db.commit()
    db.refresh(evidence)
    return evidence


def download(
    db: Session, user: User, evidence: Evidence, request: Request | None = None
) -> tuple[bytes, str, str]:
    """Read the bytes back, recording the access in the audit trail."""
    storage = get_storage()
    content = storage.get(evidence.storage_key)

    # Detect tampering: the stored bytes must still match the recorded hash.
    integrity_ok = sha256_hex(content) == evidence.file_hash
    audit.record(
        db,
        action=AuditAction.EVIDENCE_DOWNLOADED,
        user=user,
        resource_type="Evidence",
        resource_id=evidence.id,
        assessment_id=evidence.finding.assessment_id,
        description=(
            f"Evidence '{evidence.filename}' downloaded from {evidence.finding.reference}."
            + ("" if integrity_ok else " WARNING: the stored file no longer matches its recorded hash.")
        ),
        new_value={"integrity_verified": integrity_ok},
        request=request,
    )
    db.commit()
    return content, evidence.content_type, evidence.filename


def verify_integrity(evidence: Evidence) -> bool:
    try:
        return sha256_hex(get_storage().get(evidence.storage_key)) == evidence.file_hash
    except Exception:
        return False


def annotate(
    db: Session,
    user: User,
    evidence: Evidence,
    annotations: list[dict],
    request: Request | None = None,
) -> Evidence:
    """Store lightweight rectangle / arrow / highlight / text overlays."""
    allowed_kinds = {"rect", "arrow", "highlight", "text"}
    cleaned: list[dict] = []
    for item in annotations[:100]:
        kind = str(item.get("kind", "rect"))
        if kind not in allowed_kinds:
            raise ValidationError(f"'{kind}' is not a supported annotation type.")
        cleaned.append(
            {
                "kind": kind,
                "x": float(item.get("x", 0)),
                "y": float(item.get("y", 0)),
                "width": float(item.get("width", 0)),
                "height": float(item.get("height", 0)),
                "color": str(item.get("color", "#ef4444"))[:20],
                "text": str(item.get("text", ""))[:200],
            }
        )
    evidence.annotations = cleaned
    audit.record(
        db,
        action=AuditAction.EVIDENCE_ANNOTATED,
        user=user,
        resource_type="Evidence",
        resource_id=evidence.id,
        assessment_id=evidence.finding.assessment_id,
        description=f"Evidence '{evidence.filename}' annotated ({len(cleaned)} marks).",
        request=request,
    )
    db.commit()
    db.refresh(evidence)
    return evidence


def soft_delete(
    db: Session, user: User, evidence: Evidence, request: Request | None = None
) -> None:
    """Withdraw evidence from view without destroying the custody record."""
    evidence.is_deleted = True
    evidence.is_current = False
    history.record(
        db,
        evidence.finding,
        event_type=HistoryEventType.STATUS_CHANGED,
        user=user,
        note=f"{user.full_name} withdrew evidence '{evidence.filename}' (record retained for audit).",
        metadata={"evidence_id": evidence.id},
    )
    audit.record(
        db,
        action=AuditAction.EVIDENCE_DELETED,
        user=user,
        resource_type="Evidence",
        resource_id=evidence.id,
        assessment_id=evidence.finding.assessment_id,
        description=f"Evidence '{evidence.filename}' withdrawn from {evidence.finding.reference}.",
        old_value={"is_deleted": False},
        new_value={"is_deleted": True},
        request=request,
    )
    db.commit()
