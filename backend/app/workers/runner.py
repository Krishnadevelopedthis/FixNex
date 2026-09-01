"""Background task dispatch.

`TASK_RUNNER=auto` uses Celery when its broker is reachable and otherwise falls
back to an in-process thread pool, so a long scan never blocks an API request
even on a laptop with no Redis running.
"""
from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor

from app.core.config import settings

logger = logging.getLogger("prcampus.runner")


class TaskRunner(ABC):
    name: str = "base"

    @abstractmethod
    def submit_scan(self, scan_job_id: int) -> str | None: ...

    @abstractmethod
    def health(self) -> tuple[bool, str]: ...

    def shutdown(self) -> None:  # pragma: no cover - overridden where needed
        return None


class ThreadTaskRunner(TaskRunner):
    """In-process executor. Scans run on background threads in the API process."""

    name = "thread"

    def __init__(self, max_workers: int):
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="prcampus-scan")

    def submit_scan(self, scan_job_id: int) -> str | None:
        from app.services.scanning import execute_scan_job

        def _run() -> None:
            try:
                execute_scan_job(scan_job_id)
            except Exception:  # pragma: no cover - failures are recorded on the job
                logger.exception("Scan job %s crashed in the thread runner", scan_job_id)

        self._pool.submit(_run)
        return f"thread-{scan_job_id}"

    def health(self) -> tuple[bool, str]:
        return True, f"In-process thread pool ({self._pool._max_workers} workers)"

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=False)


class CeleryTaskRunner(TaskRunner):
    name = "celery"

    def __init__(self):
        from app.workers.celery_app import celery_app

        self._celery = celery_app

    def submit_scan(self, scan_job_id: int) -> str | None:
        result = self._celery.send_task("prcampus.run_scan_job", args=[scan_job_id])
        return result.id

    def health(self) -> tuple[bool, str]:
        try:
            with self._celery.connection_for_write() as connection:
                connection.ensure_connection(max_retries=1, timeout=3)
            return True, f"Celery broker at {settings.broker_url}"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"[:200]


_runner: TaskRunner | None = None
_lock = threading.Lock()


def _broker_reachable() -> bool:
    if not settings.broker_url:
        return False
    try:
        import redis

        client = redis.Redis.from_url(settings.broker_url, socket_connect_timeout=2)
        client.ping()
        return True
    except Exception as exc:
        logger.info("Celery broker unreachable (%s); using the in-process runner.", exc)
        return False


def get_task_runner() -> TaskRunner:
    global _runner
    if _runner is not None:
        return _runner
    with _lock:
        if _runner is not None:
            return _runner
        if settings.TASK_RUNNER == "celery" or (settings.TASK_RUNNER == "auto" and _broker_reachable()):
            try:
                _runner = CeleryTaskRunner()
                logger.info("Using the Celery task runner.")
                return _runner
            except Exception as exc:
                logger.warning("Could not initialise Celery (%s); using the thread runner.", exc)
        _runner = ThreadTaskRunner(settings.MAX_CONCURRENT_SCANS)
        return _runner


def reset_task_runner() -> None:
    """Test helper."""
    global _runner
    _runner = None
