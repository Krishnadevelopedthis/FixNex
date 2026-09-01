"""Celery application and task definitions."""
from __future__ import annotations

import logging

from celery import Celery

from app.core.config import settings

logger = logging.getLogger("prcampus.celery")

celery_app = Celery(
    "prcampus",
    broker=settings.broker_url or "memory://",
    backend=settings.result_backend or "cache+memory://",
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.SCANNER_TIMEOUT_SECONDS + 300,
    task_soft_time_limit=settings.SCANNER_TIMEOUT_SECONDS + 120,
    worker_max_tasks_per_child=50,
    broker_connection_retry_on_startup=True,
)


@celery_app.task(name="prcampus.run_scan_job", bind=True)
def run_scan_job(self, scan_job_id: int) -> dict:
    """Execute one scan job inside a Celery worker."""
    from app.services.scanning import execute_scan_job

    logger.info("Celery worker executing scan job %s", scan_job_id)
    return execute_scan_job(scan_job_id)
