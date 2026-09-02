"""Scan orchestration.

One scan job fans out to every scanner that supports the chosen profile and
target type:

    STANDARD scan
        ├── HTTP header analysis   (built-in)
        ├── TLS assessment         (built-in)
        ├── Technology fingerprint (built-in / WhatWeb)
        ├── Port discovery         (built-in / Nmap)
        ├── Nuclei                 (if installed)
        └── OWASP ZAP              (if the daemon is reachable)
                    ↓
             normalised findings
                    ↓
              correlate + dedupe
                    ↓
                 Findings

A scanner that is missing or fails is recorded on its own ScannerRun and the
rest of the scan continues.
"""
from __future__ import annotations

import logging
import re

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    ScopeViolationError,
    ValidationError,
)
from app.db.base import utcnow
from app.db.session import session_scope
from app.models.assessment import Assessment
from app.models.enums import (
    AssessmentStatus,
    DataOrigin,
    ScannerRunStatus,
    ScanProfile,
    ScanStatus,
    TargetStatus,
)
from app.models.scan import ScanJob, ScannerRun
from app.models.target import Target
from app.models.user import User
from app.scanners.base import ScanContext
from app.scanners.registry import scanner_registry
from app.services import audit, ingest, scope
from app.services.audit import AuditAction
from app.services.references import assign_reference

logger = logging.getLogger("prcampus.scanning")


# ---------------------------------------------------------------------------
# Job creation
# ---------------------------------------------------------------------------
def create_scan_job(
    db: Session,
    user: User,
    *,
    assessment_id: int,
    target_id: int,
    profile: str = ScanProfile.STANDARD,
    scanners: list[str] | None = None,
    authorization_confirmed: bool = False,
    request: Request | None = None,
) -> ScanJob:
    assessment = db.get(Assessment, assessment_id)
    if assessment is None:
        raise NotFoundError(f"Assessment {assessment_id} was not found.")
    if assessment.status in (AssessmentStatus.ARCHIVED, AssessmentStatus.COMPLETED):
        raise ConflictError(
            f"Assessment {assessment.reference} is {assessment.status.lower()} and cannot be scanned."
        )

    target = db.get(Target, target_id)
    if target is None or target.assessment_id != assessment_id:
        raise NotFoundError("The target was not found in this assessment.")

    # ---- authorisation gate -------------------------------------------------
    if not target.authorization_confirmed:
        raise ScopeViolationError(
            f"Target {target.value} has not been marked as authorised for testing. "
            "Confirm written authorisation on the target before scanning."
        )
    if not authorization_confirmed:
        raise ScopeViolationError(
            "You must confirm that you are authorised to perform security testing "
            "against this target before a scan can start."
        )

    # ---- scope gate ---------------------------------------------------------
    decision = scope.check(db, assessment, target.value)
    if not decision.in_scope:
        audit.record(
            db,
            action=AuditAction.SCOPE_VIOLATION_BLOCKED,
            user=user,
            resource_type="Target",
            resource_id=target.id,
            assessment_id=assessment.id,
            description=f"Scan of {target.value} was blocked: {decision.reason}",
            request=request,
        )
        db.commit()
        raise ScopeViolationError(decision.reason)

    selected = _select_scanners(profile, target.target_type, scanners)
    if not selected:
        raise ValidationError(
            "No scanner is available for this profile and target type. Check the "
            "System Health page to see which scanners are installed."
        )

    job = ScanJob(
        assessment_id=assessment.id,
        target_id=target.id,
        profile=profile,
        status=ScanStatus.QUEUED,
        progress=0,
        current_operation="Queued",
        requested_scanners=selected,
        created_by_id=user.id,
    )
    db.add(job)
    assign_reference(db, job)

    for name in selected:
        db.add(ScannerRun(scan_job_id=job.id, scanner=name, status=ScannerRunStatus.PENDING))

    audit.record(
        db,
        action=AuditAction.SCAN_STARTED,
        user=user,
        resource_type="ScanJob",
        resource_id=job.id,
        assessment_id=assessment.id,
        description=(
            f"{profile} scan {job.reference} queued for {target.value} "
            f"({len(selected)} scanners). Authorisation: {decision.reason}"
        ),
        new_value={"profile": profile, "scanners": selected, "target": target.value},
        request=request,
    )
    db.commit()
    db.refresh(job)

    from app.workers.runner import get_task_runner

    runner = get_task_runner()
    job.task_runner = runner.name
    job.task_id = runner.submit_scan(job.id)
    db.commit()
    db.refresh(job)
    return job


def _select_scanners(profile: str, target_type: str, requested: list[str] | None) -> list[str]:
    available = scanner_registry.for_profile(profile, target_type, only_available=True)
    names = [str(a.name) for a in available]
    if requested:
        # An explicit request is still filtered by availability and profile.
        return [n for n in names if n in {str(r) for r in requested}]
    return names


def cancel_scan_job(db: Session, user: User, job: ScanJob, request: Request | None = None) -> ScanJob:
    if job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        raise ConflictError(f"Scan {job.reference} has already finished.")
    job.cancel_requested = True
    if job.status == ScanStatus.QUEUED:
        job.status = ScanStatus.CANCELLED
        job.completed_at = utcnow()
        job.current_operation = "Cancelled before it started"
    audit.record(
        db,
        action=AuditAction.SCAN_CANCELLED,
        user=user,
        resource_type="ScanJob",
        resource_id=job.id,
        assessment_id=job.assessment_id,
        description=f"Scan {job.reference} cancellation requested.",
        request=request,
    )
    db.commit()
    db.refresh(job)
    return job


# ---------------------------------------------------------------------------
# Job execution (runs in a Celery worker or a background thread)
# ---------------------------------------------------------------------------
def execute_scan_job(scan_job_id: int) -> dict:
    """Run every selected scanner and ingest the results."""
    with session_scope() as db:
        job = db.get(ScanJob, scan_job_id)
        if job is None:
            logger.warning("Scan job %s no longer exists.", scan_job_id)
            return {"status": "missing"}
        if job.status != ScanStatus.QUEUED:
            logger.info("Scan job %s is %s; not executing again.", job.reference, job.status)
            return {"status": job.status}

        job.status = ScanStatus.RUNNING
        job.started_at = utcnow()
        job.current_operation = "Starting scan"
        job.progress = 1
        target_value = job.target.value
        target_type = job.target.target_type
        target_port = job.target.port
        base_path = job.target.base_path
        endpoints = [{"method": e.method, "path": e.path} for e in job.target.endpoints]
        profile = job.profile
        selected = list(job.requested_scanners or [])
        assessment_id = job.assessment_id

    adapters = [a for a in (scanner_registry.get(n) for n in selected) if a is not None]
    total_weight = sum(a.weight for a in adapters) or 1
    completed_weight = 0
    total_created = total_merged = total_raw = 0

    for adapter in adapters:
        if _is_cancelled(scan_job_id):
            _finalise(scan_job_id, ScanStatus.CANCELLED, "Cancelled by operator")
            return {"status": ScanStatus.CANCELLED}

        run_id = _start_scanner_run(scan_job_id, str(adapter.name))
        base_progress = int(100 * completed_weight / total_weight)
        span = int(100 * adapter.weight / total_weight)

        def progress(message: str, percent: int, _base=base_progress, _span=span) -> None:
            _update_progress(
                scan_job_id,
                min(99, _base + int(_span * max(0, min(percent, 100)) / 100)),
                f"{adapter.label}: {message}" if not message.startswith(adapter.label) else message,
            )

        ctx = ScanContext(
            target_value=target_value,
            target_type=target_type,
            profile=profile,
            port=target_port,
            base_path=base_path,
            endpoints=endpoints,
            progress=progress,
            is_cancelled=lambda: _is_cancelled(scan_job_id),
        )

        progress("starting", 0)
        try:
            result = adapter.run(ctx)
        except Exception as exc:  # a broken adapter must not abort the whole scan
            logger.exception("Scanner %s raised while scanning job %s", adapter.name, scan_job_id)
            _finish_scanner_run(
                run_id, ScannerRunStatus.FAILED, error=f"{type(exc).__name__}: {exc}"[:500]
            )
            completed_weight += adapter.weight
            continue

        with session_scope() as db:
            job = db.get(ScanJob, scan_job_id)
            run = db.get(ScannerRun, run_id)
            if job is None or run is None:
                break

            run.completed_at = utcnow()
            run.exit_code = result.exit_code
            run.command_summary = result.command_summary
            run.tool_version = result.tool_version
            run.metrics = result.metrics or {}
            run.raw_findings_count = len(result.findings)
            if run.started_at:
                run.duration_ms = int((run.completed_at - run.started_at).total_seconds() * 1000)

            if result.skipped_reason:
                run.status = ScannerRunStatus.UNAVAILABLE
                run.error_message = result.skipped_reason
            elif result.error:
                run.status = ScannerRunStatus.FAILED
                run.error_message = result.error
            else:
                run.status = ScannerRunStatus.COMPLETED

            if result.findings:
                stats = ingest.ingest(db, job, run, result.findings)
                total_created += stats.created
                total_merged += stats.merged
                total_raw += stats.raw
                job.findings_count = total_created
                job.raw_findings_count = total_raw
                job.duplicates_merged = total_merged

            # Technology fingerprints feed the target's inventory.
            technologies = (result.metrics or {}).get("technologies")
            if technologies and job.target:
                job.target.technologies = technologies

        completed_weight += adapter.weight
        _update_progress(
            scan_job_id,
            min(99, int(100 * completed_weight / total_weight)),
            f"{adapter.label} finished",
        )

    status = ScanStatus.CANCELLED if _is_cancelled(scan_job_id) else ScanStatus.COMPLETED
    _finalise(scan_job_id, status, "Scan complete" if status == ScanStatus.COMPLETED else "Cancelled")

    with session_scope() as db:
        job = db.get(ScanJob, scan_job_id)
        if job:
            audit.record(
                db,
                action=AuditAction.SCAN_COMPLETED if status == ScanStatus.COMPLETED else AuditAction.SCAN_CANCELLED,
                user=job.created_by,
                resource_type="ScanJob",
                resource_id=job.id,
                assessment_id=assessment_id,
                description=(
                    f"Scan {job.reference} {status.lower()}: {total_created} new findings, "
                    f"{total_merged} correlated with existing findings, {total_raw} raw results."
                ),
                new_value={
                    "created": total_created,
                    "merged": total_merged,
                    "raw": total_raw,
                    "status": status,
                },
            )

    return {
        "status": status,
        "created": total_created,
        "merged": total_merged,
        "raw": total_raw,
    }


# ---------------------------------------------------------------------------
# Small transactional helpers (each keeps its own short-lived session so that
# progress is visible to API readers while the scan is still running)
# ---------------------------------------------------------------------------
def _is_cancelled(scan_job_id: int) -> bool:
    with session_scope() as db:
        job = db.get(ScanJob, scan_job_id)
        return bool(job and job.cancel_requested)


def _update_progress(scan_job_id: int, progress: int, operation: str) -> None:
    with session_scope() as db:
        job = db.get(ScanJob, scan_job_id)
        if job and job.status == ScanStatus.RUNNING:
            job.progress = max(job.progress, progress)
            job.current_operation = operation[:240]


def _start_scanner_run(scan_job_id: int, scanner: str) -> int:
    with session_scope() as db:
        run = (
            db.query(ScannerRun)
            .filter(ScannerRun.scan_job_id == scan_job_id, ScannerRun.scanner == scanner)
            .first()
        )
        if run is None:
            run = ScannerRun(scan_job_id=scan_job_id, scanner=scanner)
            db.add(run)
            db.flush()
        run.status = ScannerRunStatus.RUNNING
        run.started_at = utcnow()
        return run.id


def _finish_scanner_run(run_id: int, status: str, error: str | None = None) -> None:
    with session_scope() as db:
        run = db.get(ScannerRun, run_id)
        if run is None:
            return
        run.status = status
        run.error_message = error
        run.completed_at = utcnow()
        if run.started_at:
            run.duration_ms = int((run.completed_at - run.started_at).total_seconds() * 1000)


def _finalise(scan_job_id: int, status: str, operation: str) -> None:
    with session_scope() as db:
        job = db.get(ScanJob, scan_job_id)
        if job is None:
            return
        job.status = status
        job.progress = 100 if status == ScanStatus.COMPLETED else job.progress
        job.current_operation = operation
        job.completed_at = utcnow()
        # A scan where every scanner failed is a failed scan.
        runs = job.scanner_runs
        if runs and all(r.status == ScannerRunStatus.FAILED for r in runs):
            job.status = ScanStatus.FAILED
            job.error_message = "Every scanner failed. See the individual scanner runs for detail."


# ---------------------------------------------------------------------------
# Imported results (SARIF)
# ---------------------------------------------------------------------------
def import_scan_results(
    db: Session,
    user: User,
    *,
    assessment_id: int,
    target_id: int,
    tool_name: str,
    raw: bytes,
    request: Request | None = None,
) -> ScanJob:
    """Ingest a SARIF report produced by a tool run outside FixNex.

    Nothing is executed here — the file is parsed into the same
    `NormalizedFinding` list a live adapter produces and handed to the existing
    ingest pipeline, so correlation, scoring, risk and SLA behave identically.

    The scope gate still applies: findings may only be attached to a target that
    is inside the assessment's authorised scope, and a blocked attempt is
    audited exactly as a blocked scan is.
    """
    from app.scanners.sarif_import import parse_sarif_bytes

    assessment = db.get(Assessment, assessment_id)
    if assessment is None:
        raise NotFoundError(f"Assessment {assessment_id} was not found.")
    if assessment.status in (AssessmentStatus.ARCHIVED, AssessmentStatus.COMPLETED):
        raise ConflictError(
            f"Assessment {assessment.reference} is {assessment.status.lower()} and cannot "
            "accept new findings."
        )

    target = db.get(Target, target_id)
    if target is None or target.assessment_id != assessment_id:
        raise NotFoundError("The target was not found in this assessment.")

    if not target.authorization_confirmed:
        raise ScopeViolationError(
            f"Target {target.value} has not been marked as authorised for testing. "
            "Findings cannot be attached to an unauthorised target."
        )

    decision = scope.check(db, assessment, target.value)
    if not decision.in_scope:
        audit.record(
            db,
            action=AuditAction.SCOPE_VIOLATION_BLOCKED,
            user=user,
            resource_type="Target",
            resource_id=target.id,
            assessment_id=assessment.id,
            description=f"SARIF import for {target.value} was blocked: {decision.reason}",
            request=request,
        )
        db.commit()
        raise ScopeViolationError(decision.reason)

    clean_tool = re.sub(r"[^a-zA-Z0-9_.-]", "", (tool_name or "").strip())[:40].lower()
    if not clean_tool:
        raise ValidationError("A tool name is required so the findings can be attributed.")

    findings, metrics = parse_sarif_bytes(raw, clean_tool, target.value)
    scanner_name = f"imported:{clean_tool}"

    now = utcnow()
    job = ScanJob(
        assessment_id=assessment.id,
        target_id=target.id,
        profile=ScanProfile.IMPORTED,
        status=ScanStatus.RUNNING,
        progress=0,
        current_operation=f"Importing {clean_tool} results",
        requested_scanners=[scanner_name],
        created_by_id=user.id,
        started_at=now,
        task_runner="import",
    )
    db.add(job)
    assign_reference(db, job)

    run = ScannerRun(
        scan_job_id=job.id,
        scanner=scanner_name,
        status=ScannerRunStatus.RUNNING,
        started_at=now,
        command_summary=f"SARIF import ({len(raw)} bytes) from {clean_tool}",
        tool_version=metrics.get("sarif_version"),
    )
    db.add(run)
    db.flush()

    stats = ingest.ingest(db, job, run, findings, data_origin=DataOrigin.IMPORTED)

    completed = utcnow()
    run.status = ScannerRunStatus.COMPLETED
    run.completed_at = completed
    run.duration_ms = int((completed - now).total_seconds() * 1000)
    run.exit_code = 0
    run.raw_findings_count = stats.raw
    run.metrics = metrics

    job.status = ScanStatus.COMPLETED
    job.progress = 100
    job.current_operation = f"Imported {stats.created} findings from {clean_tool}"
    job.completed_at = completed
    job.findings_count = stats.created
    job.raw_findings_count = stats.raw
    job.duplicates_merged = stats.merged

    audit.record(
        db,
        action=AuditAction.SCAN_COMPLETED,
        user=user,
        resource_type="ScanJob",
        resource_id=job.id,
        assessment_id=assessment.id,
        description=(
            f"Imported {stats.raw} {clean_tool} results for {target.value}: "
            f"{stats.created} new findings, {stats.merged} correlated with existing ones."
        ),
        new_value={"tool": clean_tool, **metrics},
        request=request,
    )
    db.commit()
    db.refresh(job)
    return job


def reconcile_orphaned_jobs(db: Session | None = None) -> int:
    """Fail scans that were executing in this process when it last stopped.

    A scan running on the in-process thread runner cannot survive a restart:
    the thread is gone, but the row still says RUNNING, so the job hangs at
    whatever percentage it reached, the dashboard reports a scan that is not
    happening, and the progress socket for it never terminates.

    Only jobs recorded as `task_runner="thread"` are reconciled. A Celery job
    may legitimately still be running in a separate worker that outlived the
    API process, so those are left alone.

    Accepts an optional session so callers (and tests) can supply their own;
    otherwise it opens and commits one of its own.
    """
    if db is not None:
        return _reconcile(db)
    with session_scope() as owned:
        return _reconcile(owned)


def _reconcile(db: Session) -> int:
    orphans = (
        db.query(ScanJob)
        .filter(
            ScanJob.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]),
            ScanJob.task_runner == "thread",
        )
        .all()
    )
    for job in orphans:
        job.status = ScanStatus.FAILED
        job.completed_at = utcnow()
        job.error_message = (
            "The scan was interrupted because the server restarted while it was "
            "running. Findings recorded before the interruption were kept; start a "
            "new scan to finish the rest."
        )
        job.current_operation = "Interrupted by a server restart"
        for run in job.scanner_runs:
            if run.status in (ScannerRunStatus.RUNNING, ScannerRunStatus.PENDING):
                run.status = ScannerRunStatus.FAILED
                run.completed_at = utcnow()
                run.error_message = "Interrupted by a server restart."

    if orphans:
        db.commit()
        logger.warning("Reconciled %d scan job(s) orphaned by a restart.", len(orphans))
    return len(orphans)
