"""Finding queries, serialisation and manual creation."""
from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy import func, or_
from sqlalchemy.orm import Query, Session, joinedload

from app.core.exceptions import NotFoundError, PermissionDeniedError
from app.core.permissions import Permission, Role
from app.db.base import utcnow
from app.models.enums import (
    DataOrigin,
    FindingStatus,
    ScannerName,
    VerificationStatus,
)
from app.models.finding import Finding
from app.models.target import Target
from app.models.user import User
from app.schemas.common import UserBrief
from app.schemas.findings import (
    CVEDetail,
    EvidenceRead,
    FindingCommentRead,
    FindingDetail,
    FindingHistoryRead,
    FindingListItem,
    FindingSourceRead,
    RemediationRead,
    RetestRead,
    RiskBreakdown,
    SLAInfo,
)
from app.services import audit, cwe as cwe_service, history, risk as risk_engine, sla as sla_service
from app.services.audit import AuditAction
from app.services.cvss import score_finding
from app.services.references import assign_reference

# Which statuses a finding may legally move to next.
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    FindingStatus.DISCOVERED: {FindingStatus.NEEDS_VERIFICATION, FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE},
    FindingStatus.NEEDS_VERIFICATION: {FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE},
    FindingStatus.CONFIRMED: {FindingStatus.TRIAGED, FindingStatus.FALSE_POSITIVE, FindingStatus.REMEDIATION},
    FindingStatus.TRIAGED: {FindingStatus.REMEDIATION, FindingStatus.FALSE_POSITIVE},
    FindingStatus.REMEDIATION: {FindingStatus.RETEST, FindingStatus.CLOSED},
    FindingStatus.RETEST: {FindingStatus.CLOSED, FindingStatus.REMEDIATION},
    FindingStatus.CLOSED: {FindingStatus.REMEDIATION},
    # False positives are never deleted; they can be reopened for re-review.
    FindingStatus.FALSE_POSITIVE: {FindingStatus.NEEDS_VERIFICATION},
}

SCANNER_LABELS = {
    ScannerName.HTTP_HEADERS: "HTTP Security Headers",
    ScannerName.TLS: "TLS / Certificate",
    ScannerName.TECH_FINGERPRINT: "Technology Fingerprint",
    ScannerName.PORT_SCAN: "TCP Port Discovery",
    ScannerName.NMAP: "Nmap",
    ScannerName.NUCLEI: "Nuclei",
    ScannerName.ZAP: "OWASP ZAP",
    ScannerName.WHATWEB: "WhatWeb",
    ScannerName.SSL_LABS: "SSL Labs",
    ScannerName.MANUAL: "Manual testing",
}


def scanner_label(name: str | None) -> str | None:
    if not name:
        return None
    return SCANNER_LABELS.get(name, str(name).replace("_", " ").title())


def user_brief(user: User | None) -> UserBrief | None:
    if user is None:
        return None
    return UserBrief(id=user.id, full_name=user.full_name, email=user.email, role=user.role)


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------
def visible_findings_query(db: Session, user: User) -> Query:
    """Base query respecting row-level visibility.

    A developer only ever sees findings assigned to them.
    """
    query = db.query(Finding)
    if not user.has_permission(Permission.FINDING_VIEW_ALL):
        query = query.filter(Finding.assigned_to_id == user.id)
    return query


def get_finding_for_user(db: Session, user: User, finding_id: int) -> Finding:
    finding = (
        visible_findings_query(db, user)
        .options(
            joinedload(Finding.target),
            joinedload(Finding.assigned_to),
            joinedload(Finding.verified_by),
        )
        .filter(Finding.id == finding_id)
        .first()
    )
    if finding is None:
        # Distinguish "does not exist" from "not yours" only for privileged users.
        exists = db.query(Finding.id).filter(Finding.id == finding_id).first() is not None
        if exists and not user.has_permission(Permission.FINDING_VIEW_ALL):
            raise PermissionDeniedError(
                "This finding is not assigned to you. Developers can only view their own "
                "assigned findings."
            )
        raise NotFoundError(f"Finding {finding_id} was not found.")
    return finding


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------
def apply_filters(query: Query, filters: dict[str, Any]) -> Query:
    if filters.get("assessment_id"):
        query = query.filter(Finding.assessment_id == filters["assessment_id"])
    if filters.get("target_id"):
        query = query.filter(Finding.target_id == filters["target_id"])
    if filters.get("severity"):
        query = query.filter(Finding.severity.in_(filters["severity"]))
    if filters.get("status"):
        query = query.filter(Finding.status.in_(filters["status"]))
    if filters.get("source"):
        query = query.filter(Finding.primary_source.in_(filters["source"]))
    if filters.get("risk_level"):
        query = query.filter(Finding.risk_level.in_(filters["risk_level"]))
    if filters.get("cwe"):
        query = query.filter(Finding.cwe_id == cwe_service.normalize_cwe_id(filters["cwe"]))
    if filters.get("cve"):
        cve = filters["cve"].upper()
        query = query.filter(func.cast(Finding.cve_ids, __import__("sqlalchemy").String).ilike(f"%{cve}%"))
    if filters.get("assigned_to_id"):
        query = query.filter(Finding.assigned_to_id == filters["assigned_to_id"])
    if filters.get("search"):
        term = f"%{filters['search'].strip()}%"
        query = query.filter(
            or_(
                Finding.title.ilike(term),
                Finding.description.ilike(term),
                Finding.endpoint.ilike(term),
                Finding.reference.ilike(term),
                Finding.cwe_id.ilike(term),
            )
        )
    if not filters.get("include_false_positive", True):
        query = query.filter(Finding.status != FindingStatus.FALSE_POSITIVE)
    if not filters.get("include_demo", True):
        query = query.filter(Finding.is_demo.is_(False))
    if filters.get("sla_status") == "OVERDUE":
        query = query.filter(
            Finding.sla_due_at.isnot(None),
            Finding.sla_due_at < utcnow(),
            Finding.status.notin_([FindingStatus.CLOSED, FindingStatus.FALSE_POSITIVE]),
        )
    return query


SORT_COLUMNS = {
    "severity": Finding.severity,
    "cvss": Finding.cvss_score,
    "risk": Finding.risk_score,
    "status": Finding.status,
    "title": Finding.title,
    "created_at": Finding.created_at,
    "updated_at": Finding.updated_at,
    "sla": Finding.sla_due_at,
    "id": Finding.id,
}

# Severity is a string column, so ordering uses an explicit rank.
_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1}


def apply_sort(query: Query, sort_by: str = "severity", order: str = "desc") -> Query:
    if sort_by == "severity":
        import sqlalchemy as sa

        rank = sa.case(_SEVERITY_RANK, value=Finding.severity, else_=0)
        column = rank
    else:
        column = SORT_COLUMNS.get(sort_by, Finding.updated_at)
    ordering = column.desc() if order == "desc" else column.asc()
    # Secondary sort keeps pagination stable.
    return query.order_by(ordering, Finding.id.desc())


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------
def sla_info(finding: Finding) -> SLAInfo:
    resolved = finding.closed_at
    is_closed = finding.status in (FindingStatus.CLOSED, FindingStatus.FALSE_POSITIVE)
    data = sla_service.evaluate(finding.sla_due_at, resolved_at=resolved, is_closed=is_closed)
    return SLAInfo(**data)


def to_list_item(finding: Finding) -> FindingListItem:
    return FindingListItem(
        id=finding.id,
        reference=finding.reference,
        title=finding.title,
        assessment_id=finding.assessment_id,
        severity=finding.severity,
        cvss_score=finding.cvss_score,
        risk_level=finding.risk_level,
        status=finding.status,
        verification_status=finding.verification_status,
        primary_source=finding.primary_source,
        source_count=finding.source_count,
        data_origin=finding.data_origin,
        is_demo=finding.is_demo,
        cwe_id=finding.cwe_id,
        cve_ids=finding.cve_ids or [],
        target_id=finding.target_id,
        target_name=finding.target.name if finding.target else None,
        endpoint=finding.endpoint,
        assigned_to=user_brief(finding.assigned_to),
        priority=finding.priority,
        sla=sla_info(finding),
        updated_at=finding.updated_at,
        created_at=finding.created_at,
    )


def to_detail(finding: Finding, evidence_url_builder=None) -> FindingDetail:
    from app.services.remediation import remediation_read, retest_read

    factors = dict(finding.risk_factors or {})
    explanation = factors.pop("explanation", [])
    risk = RiskBreakdown(
        base_cvss=finding.cvss_score,
        risk_score=finding.risk_score,
        risk_level=finding.risk_level,
        impact=finding.impact,
        likelihood=finding.likelihood,
        factors=factors,
        explanation=explanation if isinstance(explanation, list) else [],
    )

    evidence_items = []
    for item in finding.evidence:
        if item.is_deleted:
            continue
        evidence_items.append(
            EvidenceRead(
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
                uploaded_by=user_brief(item.uploaded_by),
                download_url=(evidence_url_builder(item.id) if evidence_url_builder else None),
            )
        )

    base = to_list_item(finding)
    return FindingDetail(
        **base.model_dump(),
        description=finding.description,
        category=finding.category,
        parameter=finding.parameter,
        http_method=finding.http_method,
        technical_details=finding.technical_details,
        request_snippet=finding.request_snippet,
        response_snippet=finding.response_snippet,
        remediation_recommendation=finding.remediation_recommendation,
        references=finding.references or [],
        cvss_vector=finding.cvss_vector,
        cvss_version=finding.cvss_version,
        cwe_name=finding.cwe_name,
        cve_details=[CVEDetail(**_cve_detail(d)).model_dump() for d in (finding.cve_details or [])],
        confidence=finding.confidence,
        duplicate_hits=finding.duplicate_hits,
        correlation_key=finding.correlation_key,
        verification_note=finding.verification_note,
        false_positive_reason=finding.false_positive_reason,
        verified_at=finding.verified_at,
        verified_by=user_brief(finding.verified_by),
        is_suppressed=finding.is_suppressed,
        suppression_reason=finding.suppression_reason,
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        closed_at=finding.closed_at,
        target_value=finding.target.value if finding.target else None,
        risk=risk,
        sources=[
            FindingSourceRead(
                id=s.id,
                scanner=s.scanner,
                scanner_label=scanner_label(s.scanner),
                scan_job_id=s.scan_job_id,
                raw_title=s.raw_title,
                raw_severity=s.raw_severity,
                confidence=s.confidence,
                created_at=s.created_at,
            )
            for s in finding.sources
        ],
        evidence=evidence_items,
        history=[
            FindingHistoryRead(
                id=h.id,
                event_type=h.event_type,
                actor_name=h.actor_name,
                from_status=h.from_status,
                to_status=h.to_status,
                note=h.note,
                event_metadata=h.event_metadata or {},
                created_at=h.created_at,
            )
            for h in finding.history
        ],
        comments=[
            FindingCommentRead(
                id=c.id, body=c.body, created_at=c.created_at, user=user_brief(c.user)
            )
            for c in finding.comments
        ],
        remediation=remediation_read(finding.remediation) if finding.remediation else None,
        retests=[retest_read(r) for r in finding.retests],
        available_transitions=sorted(ALLOWED_TRANSITIONS.get(finding.status, set())),
    )


def _cve_detail(raw: dict) -> dict:
    return {
        "cve_id": raw.get("cve_id", "UNKNOWN"),
        "description": raw.get("description"),
        "cvss_score": raw.get("cvss_score"),
        "cvss_vector": raw.get("cvss_vector"),
        "severity": raw.get("severity"),
        "published": raw.get("published"),
        "source": raw.get("source", "NVD"),
        "url": raw.get("url"),
    }


# ---------------------------------------------------------------------------
# Manual finding creation
# ---------------------------------------------------------------------------
def create_manual_finding(db: Session, user: User, payload, request: Request | None = None) -> Finding:
    """Raise a finding discovered during hands-on testing."""
    from app.models.assessment import Assessment

    assessment = db.get(Assessment, payload.assessment_id)
    if assessment is None:
        raise NotFoundError(f"Assessment {payload.assessment_id} was not found.")

    target = db.get(Target, payload.target_id) if payload.target_id else None
    if payload.target_id and (target is None or target.assessment_id != assessment.id):
        raise NotFoundError("The target was not found in this assessment.")

    cvss = score_finding(payload.cvss_vector, None, payload.severity)
    cwe_id = cwe_service.normalize_cwe_id(payload.cwe_id) or cwe_service.infer_from_text(
        payload.title, payload.description
    )
    cwe_entry = cwe_service.lookup(cwe_id)
    severity = cvss.severity if payload.cvss_vector else payload.severity

    context = risk_engine.context_from_target(target)
    risk = risk_engine.calculate(
        cvss_score=cvss.score,
        severity=severity,
        confidence=payload.confidence,
        cvss_metrics=cvss.metrics,
        **context,
    )

    now = utcnow()
    finding = Finding(
        assessment_id=assessment.id,
        target_id=target.id if target else None,
        title=payload.title,
        description=payload.description,
        category=payload.category or (cwe_entry["category"] if cwe_entry else None),
        endpoint=payload.endpoint,
        parameter=payload.parameter,
        http_method=payload.http_method,
        technical_details=payload.technical_details,
        request_snippet=payload.request_snippet,
        response_snippet=payload.response_snippet,
        remediation_recommendation=payload.remediation_recommendation,
        references=payload.references,
        primary_source=ScannerName.MANUAL,
        data_origin=DataOrigin.MANUAL,
        is_demo=assessment.is_demo,
        confidence=payload.confidence,
        severity=severity,
        cvss_score=cvss.score,
        cvss_vector=cvss.vector,
        cvss_version=cvss.version,
        cwe_id=cwe_id,
        cwe_name=cwe_entry["name"] if cwe_entry else None,
        cve_ids=[c.upper() for c in payload.cve_ids],
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        impact=risk["impact"],
        likelihood=risk["likelihood"],
        risk_factors={**risk["factors"], "explanation": risk["explanation"]},
        # A human-reported finding starts life awaiting peer verification.
        status=FindingStatus.NEEDS_VERIFICATION,
        verification_status=VerificationStatus.UNVERIFIED,
        sla_due_at=sla_service.due_at(severity, now, db),
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(finding)
    assign_reference(db, finding)

    from app.services.correlation import correlation_key
    from app.scanners.base import NormalizedFinding

    finding.correlation_key = correlation_key(
        NormalizedFinding(
            title=finding.title,
            target=target.value if target else "",
            endpoint=finding.endpoint,
            source=ScannerName.MANUAL,
            cwe=finding.cwe_id,
            cve=finding.cve_ids or [],
            parameter=finding.parameter,
        )
    )

    history.record(
        db,
        finding,
        event_type="CREATED",
        user=user,
        to_status=FindingStatus.NEEDS_VERIFICATION,
        note=f"Raised manually by {user.full_name} during hands-on testing.",
    )
    audit.record(
        db,
        action=AuditAction.FINDING_CREATED,
        user=user,
        resource_type="Finding",
        resource_id=finding.id,
        assessment_id=assessment.id,
        description=f"Manual finding {finding.reference} created: {finding.title}",
        new_value={"severity": severity, "title": finding.title},
        request=request,
    )
    db.commit()
    db.refresh(finding)
    return finding
