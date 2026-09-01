"""Report generation and retrieval."""
from __future__ import annotations

import logging

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.db.base import utcnow
from app.models.assessment import Assessment
from app.models.enums import ReportFormat, ReportStatus
from app.models.report import Report
from app.models.user import User
from app.reports import context as report_context, renderers
from app.schemas.reports import ReportRead
from app.services import audit
from app.services.audit import AuditAction
from app.services.references import assign_reference
from app.storage import get_storage, sha256_hex

logger = logging.getLogger("prcampus.reports")

_MEDIA_TYPES = {
    ReportFormat.PDF: ("application/pdf", "pdf"),
    ReportFormat.CSV: ("text/csv", "csv"),
    ReportFormat.JSON: ("application/json", "json"),
    ReportFormat.XLSX: ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
    ReportFormat.HTML: ("text/html", "html"),
}


def media_type(report_format: str) -> str:
    return _MEDIA_TYPES.get(report_format, ("application/octet-stream", "bin"))[0]


def to_read(report: Report) -> ReportRead:
    from app.services.findings import user_brief

    return ReportRead(
        id=report.id,
        reference=report.reference,
        assessment_id=report.assessment_id,
        assessment_name=report.assessment.name if report.assessment else None,
        title=report.title,
        format=report.format,
        status=report.status,
        filename=report.filename,
        size_bytes=report.size_bytes,
        file_hash=report.file_hash,
        engine=report.engine,
        error_message=report.error_message,
        created_at=report.created_at,
        generated_by=user_brief(report.generated_by),
        download_url=(
            f"/api/reports/{report.id}/download" if report.status == ReportStatus.READY else None
        ),
    )


def generate(
    db: Session, user: User, assessment: Assessment, payload, request: Request | None = None
) -> Report:
    options = {
        "include_false_positives": payload.include_false_positives,
        "include_informational": payload.include_informational,
        "include_evidence": payload.include_evidence,
        "include_retest": payload.include_retest,
        "include_audit_summary": payload.include_audit_summary,
    }
    title = payload.title or f"{assessment.name} - Security Assessment Report"

    report = Report(
        assessment_id=assessment.id,
        title=title,
        format=payload.format,
        status=ReportStatus.GENERATING,
        options=options,
        generated_by_id=user.id,
    )
    db.add(report)
    assign_reference(db, report)
    db.flush()

    try:
        context = report_context.build(db, assessment, options)
        engine = payload.format.lower()

        if payload.format == ReportFormat.PDF:
            content, engine = renderers.render_pdf(context)
        elif payload.format == ReportFormat.CSV:
            content = renderers.render_csv(context)
        elif payload.format == ReportFormat.JSON:
            content = renderers.render_json(context)
        elif payload.format == ReportFormat.XLSX:
            content = renderers.render_xlsx(context)
        elif payload.format == ReportFormat.HTML:
            content = renderers.render_html(context)
        else:  # pragma: no cover - guarded by the schema enum
            raise AppError(f"Unsupported report format: {payload.format}")

        extension = _MEDIA_TYPES[payload.format][1]
        safe_name = assessment.reference.replace("/", "-")
        filename = f"{safe_name}_{utcnow():%Y%m%d-%H%M}.{extension}"
        key = f"reports/{assessment.id}/{report.id}_{filename}"

        storage = get_storage()
        storage.put(key, content, media_type(payload.format))

        report.status = ReportStatus.READY
        report.filename = filename
        report.storage_key = key
        report.storage_backend = storage.name
        report.size_bytes = len(content)
        report.file_hash = sha256_hex(content)
        report.engine = engine

    except Exception as exc:
        logger.exception("Report generation failed for assessment %s", assessment.id)
        report.status = ReportStatus.FAILED
        report.error_message = f"{type(exc).__name__}: {exc}"[:500]
        audit.record(
            db,
            action=AuditAction.REPORT_GENERATED,
            user=user,
            resource_type="Report",
            resource_id=report.id,
            assessment_id=assessment.id,
            description=f"Report generation FAILED for {assessment.reference}: {report.error_message}",
            request=request,
        )
        db.commit()
        db.refresh(report)
        return report

    audit.record(
        db,
        action=AuditAction.REPORT_GENERATED,
        user=user,
        resource_type="Report",
        resource_id=report.id,
        assessment_id=assessment.id,
        description=(
            f"{payload.format} report {report.reference} generated for {assessment.reference} "
            f"({report.size_bytes} bytes, engine {engine}, SHA-256 {report.file_hash[:16]})."
        ),
        new_value={
            "format": payload.format,
            "engine": engine,
            "size_bytes": report.size_bytes,
            "options": options,
        },
        request=request,
    )
    db.commit()
    db.refresh(report)
    return report


def download(db: Session, user: User, report: Report, request: Request | None = None) -> bytes:
    content = get_storage().get(report.storage_key)
    audit.record(
        db,
        action=AuditAction.REPORT_DOWNLOADED,
        user=user,
        resource_type="Report",
        resource_id=report.id,
        assessment_id=report.assessment_id,
        description=f"Report {report.reference} ({report.format}) downloaded.",
        request=request,
    )
    db.commit()
    return content
