"""Scan result ingestion.

Turns the normalised output of every scanner adapter into persisted findings:

    normalise → correlate → deduplicate → score (CVSS) → classify (CWE) →
    enrich (CVE) → contextual risk → SLA → persist
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.base import utcnow
from app.models.enums import (
    SEVERITY_ORDER,
    DataOrigin,
    FindingStatus,
    HistoryEventType,
    Severity,
    VerificationStatus,
)
from app.models.finding import Finding, FindingSource
from app.models.scan import ScanJob, ScannerRun
from app.scanners.base import NormalizedFinding
from app.services import correlation, cwe as cwe_service, enrichment, history, risk as risk_engine
from app.services import sla as sla_service
from app.services.cvss import score_finding
from app.services.references import assign_reference

logger = logging.getLogger("prcampus.ingest")


@dataclass
class IngestStats:
    raw: int = 0
    created: int = 0
    merged: int = 0

    @property
    def total(self) -> int:
        return self.created + self.merged


def ingest(
    db: Session,
    scan_job: ScanJob,
    scanner_run: ScannerRun | None,
    normalized: list[NormalizedFinding],
    data_origin: str = DataOrigin.REAL_SCAN,
) -> IngestStats:
    """Persist one scanner's normalised findings into the assessment.

    `data_origin` records how the findings came to exist. It defaults to
    REAL_SCAN for scanners this platform executed; uploaded SARIF passes
    IMPORTED so a result produced elsewhere is never presented as a local scan.
    """
    stats = IngestStats(raw=len(normalized))
    if not normalized:
        return stats

    target = scan_job.target
    context = risk_engine.context_from_target(target)

    for key, group in correlation.deduplicate(normalized):
        merged = correlation.merge_group(group)
        existing = (
            db.query(Finding)
            .filter(Finding.assessment_id == scan_job.assessment_id, Finding.correlation_key == key)
            .first()
        )
        if existing is not None:
            _merge_into_existing(db, existing, merged, scan_job, scanner_run, group)
            stats.merged += 1
        else:
            _create_finding(db, merged, key, scan_job, scanner_run, group, context, data_origin)
            stats.created += 1

    db.flush()
    return stats


# ---------------------------------------------------------------------------
def _create_finding(
    db: Session,
    merged: NormalizedFinding,
    key: str,
    scan_job: ScanJob,
    scanner_run: ScannerRun | None,
    group: list[NormalizedFinding],
    context: dict,
    data_origin: str = DataOrigin.REAL_SCAN,
) -> Finding:
    cvss = score_finding(merged.cvss_vector, merged.cvss, merged.severity)

    cwe_id = cwe_service.normalize_cwe_id(merged.cwe) or cwe_service.infer_from_text(
        merged.title, merged.description
    )
    cwe_entry = cwe_service.lookup(cwe_id)

    # A vector supplied by the scanner is authoritative for severity; an
    # estimated vector must not silently override what the tool reported.
    severity = cvss.severity if not cvss.estimated else merged.severity

    cve_details = []
    if merged.cve and not settings.OFFLINE_MODE:
        cve_details = enrichment.enrich_cves(db, merged.cve, limit=3)
        # A CVE with a published CVSS score refines an otherwise estimated score.
        for detail in cve_details:
            if detail.get("cvss_score") and cvss.estimated:
                cvss = score_finding(detail.get("cvss_vector"), detail["cvss_score"], severity)
                severity = cvss.severity
                break

    exploit_available = any(d.get("cvss_score", 0) and d.get("enriched") for d in cve_details)
    risk = risk_engine.calculate(
        cvss_score=cvss.score,
        severity=severity,
        exploit_available=exploit_available,
        confidence=merged.confidence,
        cvss_metrics=cvss.metrics,
        **context,
    )

    now = utcnow()
    finding = Finding(
        assessment_id=scan_job.assessment_id,
        target_id=scan_job.target_id,
        title=merged.title[:300],
        description=merged.description,
        category=merged.category or (cwe_entry["category"] if cwe_entry else None),
        endpoint=(merged.endpoint or "")[:600] or None,
        parameter=merged.parameter,
        http_method=merged.http_method,
        technical_details=merged.evidence,
        request_snippet=merged.request_snippet,
        response_snippet=merged.response_snippet,
        remediation_recommendation=merged.remediation,
        references=merged.references,
        primary_source=str(merged.source),
        data_origin=data_origin,
        is_demo=scan_job.assessment.is_demo,
        correlation_key=key,
        source_count=len({f.source for f in group}),
        duplicate_hits=max(len(group) - 1, 0),
        confidence=round(merged.confidence, 2),
        severity=severity,
        cvss_score=cvss.score,
        cvss_vector=cvss.vector,
        cvss_version=cvss.version,
        cwe_id=cwe_id,
        cwe_name=cwe_entry["name"] if cwe_entry else None,
        cve_ids=merged.cve,
        cve_details=cve_details,
        enriched_at=now if cve_details else None,
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        impact=risk["impact"],
        likelihood=risk["likelihood"],
        risk_factors={**risk["factors"], "explanation": risk["explanation"], "estimated_cvss": cvss.estimated},
        status=FindingStatus.DISCOVERED,
        verification_status=VerificationStatus.UNVERIFIED,
        sla_due_at=sla_service.due_at(severity, now, db),
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(finding)
    assign_reference(db, finding)

    for item in group:
        _add_source(db, finding, item, scan_job, scanner_run)

    history.record(
        db,
        finding,
        event_type=HistoryEventType.CREATED,
        actor_name=f"{merged.source} scanner",
        to_status=FindingStatus.DISCOVERED,
        note=(
            f"Reported by {', '.join(sorted({str(f.source) for f in group}))} during scan "
            f"{scan_job.reference}."
        ),
        metadata={
            "scan_job_id": scan_job.id,
            "scanners": sorted({str(f.source) for f in group}),
            "cvss_estimated": cvss.estimated,
        },
    )
    if len(group) > 1:
        history.record(
            db,
            finding,
            event_type=HistoryEventType.CORRELATED,
            actor_name="Correlation engine",
            note=f"{len(group)} scanner reports were correlated into this single finding.",
            metadata={"correlation_key": key, "reports": len(group)},
        )
    return finding


def _merge_into_existing(
    db: Session,
    finding: Finding,
    merged: NormalizedFinding,
    scan_job: ScanJob,
    scanner_run: ScannerRun | None,
    group: list[NormalizedFinding],
) -> None:
    """Fold a repeat detection into an existing finding rather than duplicating it."""
    finding.last_seen_at = utcnow()
    finding.duplicate_hits += len(group)

    new_sources = {str(f.source) for f in group}
    known_sources = {s.scanner for s in finding.sources}
    added = new_sources - known_sources

    for item in group:
        _add_source(db, finding, item, scan_job, scanner_run)
    if added:
        finding.source_count = len(known_sources | new_sources)
        # Independent confirmation from an additional tool raises confidence.
        finding.confidence = round(min(0.99, finding.confidence + 0.05), 2)

    # Escalate severity only; never silently downgrade an analyst's assessment.
    if SEVERITY_ORDER.get(merged.severity, 0) > SEVERITY_ORDER.get(finding.severity, 0):
        previous = finding.severity
        finding.severity = merged.severity
        history.record(
            db,
            finding,
            event_type=HistoryEventType.SCORED,
            actor_name="Correlation engine",
            note=f"Severity escalated from {previous} to {merged.severity} by a later scan.",
            metadata={"scan_job_id": scan_job.id},
        )

    for cve in merged.cve:
        if cve not in (finding.cve_ids or []):
            finding.cve_ids = [*(finding.cve_ids or []), cve]

    history.record(
        db,
        finding,
        event_type=HistoryEventType.CORRELATED,
        actor_name="Correlation engine",
        note=(
            f"Re-detected during scan {scan_job.reference}"
            + (f" by {', '.join(sorted(added))}." if added else " (already known source).")
        ),
        metadata={"scan_job_id": scan_job.id, "new_sources": sorted(added)},
    )


def _add_source(
    db: Session,
    finding: Finding,
    item: NormalizedFinding,
    scan_job: ScanJob,
    scanner_run: ScannerRun | None,
) -> None:
    db.add(
        FindingSource(
            finding=finding,
            scanner=str(item.source),
            scanner_run_id=scanner_run.id if scanner_run else None,
            scan_job_id=scan_job.id,
            raw_title=item.title[:300],
            raw_severity=item.severity,
            confidence=item.confidence,
            raw_data=item.raw or {},
        )
    )
