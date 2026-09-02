"""Recovery from a process restart mid-scan."""
from __future__ import annotations

from app.core.permissions import Role
from app.db.base import utcnow
from app.models.enums import ScannerRunStatus, ScanStatus
from app.models.scan import ScanJob, ScannerRun
from app.services.references import assign_reference
from app.services.scanning import reconcile_orphaned_jobs


def _job(db, assessment, target, status=ScanStatus.RUNNING, runner="thread", progress=27):
    job = ScanJob(
        assessment_id=assessment.id, target_id=target.id, profile="STANDARD",
        status=status, progress=progress, task_runner=runner,
        started_at=utcnow(), current_operation="Scanning",
        requested_scanners=["http_headers"],
    )
    db.add(job)
    assign_reference(db, job)
    db.add(ScannerRun(scan_job_id=job.id, scanner="http_headers", status=ScannerRunStatus.RUNNING))
    db.commit()
    return job


def test_in_process_scan_is_failed_after_a_restart(db, assessment, target):
    """Regression: a thread-runner scan stayed RUNNING for ever after a restart.

    The thread does not survive the process, so the row was stranded at
    whatever percentage it reached — the dashboard reported a scan that was not
    happening and its progress socket never terminated.
    """
    job = _job(db, assessment, target)
    assert reconcile_orphaned_jobs(db) == 1

    db.expire_all()
    refreshed = db.get(ScanJob, job.id)
    assert refreshed.status == ScanStatus.FAILED
    assert refreshed.completed_at is not None
    assert "restarted" in refreshed.error_message
    assert all(r.status == ScannerRunStatus.FAILED for r in refreshed.scanner_runs)


def test_queued_in_process_scans_are_also_reconciled(db, assessment, target):
    _job(db, assessment, target, status=ScanStatus.QUEUED, progress=0)
    assert reconcile_orphaned_jobs(db) == 1


def test_celery_scans_are_left_alone(db, assessment, target):
    """A Celery worker may have outlived the API process, so its job stands."""
    job = _job(db, assessment, target, runner="celery")
    assert reconcile_orphaned_jobs(db) == 0

    db.expire_all()
    assert db.get(ScanJob, job.id).status == ScanStatus.RUNNING


def test_finished_scans_are_untouched(db, assessment, target):
    for status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        job = _job(db, assessment, target, status=status)
        reconcile_orphaned_jobs(db)
        db.expire_all()
        assert db.get(ScanJob, job.id).status == status


def test_reconciliation_is_idempotent(db, assessment, target):
    _job(db, assessment, target)
    assert reconcile_orphaned_jobs(db) == 1
    assert reconcile_orphaned_jobs(db) == 0


def test_findings_from_the_partial_scan_are_kept(db, assessment, target, finding):
    """An interrupted scan keeps whatever it already found."""
    _job(db, assessment, target)
    before = db.query(type(finding)).count()
    reconcile_orphaned_jobs(db)
    assert db.query(type(finding)).count() == before


def test_reconciled_job_is_visible_as_failed_through_the_api(client, auth, db, assessment, target):
    job = _job(db, assessment, target)
    reconcile_orphaned_jobs(db)
    body = client.get(f"/api/scans/{job.id}", headers=auth(Role.SECURITY_ENGINEER)).json()
    assert body["status"] == ScanStatus.FAILED
    assert "restarted" in body["error_message"]
