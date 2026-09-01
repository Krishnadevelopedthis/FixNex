"""Storage backend selection.

`STORAGE_BACKEND=auto` prefers MinIO and silently falls back to the local
filesystem so that evidence upload always works, even on a laptop.
"""
from __future__ import annotations

import logging
import threading

from app.core.config import settings
from app.storage.base import StorageBackend, sha256_hex
from app.storage.local import LocalStorage

logger = logging.getLogger("prcampus.storage")

_storage: StorageBackend | None = None
_lock = threading.Lock()


def _build_minio() -> StorageBackend | None:
    if not settings.MINIO_ENDPOINT:
        return None
    try:
        from app.storage.minio_backend import MinIOStorage

        backend = MinIOStorage(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            bucket=settings.MINIO_BUCKET,
            secure=settings.MINIO_SECURE,
        )
        ok, detail = backend.health()
        if ok:
            return backend
        logger.warning("MinIO unreachable (%s)", detail)
    except Exception as exc:
        logger.warning("MinIO unavailable, falling back to local storage: %s", exc)
    return None


def get_storage() -> StorageBackend:
    global _storage
    if _storage is not None:
        return _storage
    with _lock:
        if _storage is not None:
            return _storage
        if settings.STORAGE_BACKEND in ("minio", "auto"):
            backend = _build_minio()
            if backend is not None:
                _storage = backend
                return _storage
            if settings.STORAGE_BACKEND == "minio":
                logger.error("STORAGE_BACKEND=minio but MinIO is unreachable; using local storage.")
        _storage = LocalStorage(settings.LOCAL_STORAGE_PATH)
        return _storage


def reset_storage() -> None:
    """Test helper."""
    global _storage
    _storage = None


__all__ = ["StorageBackend", "get_storage", "reset_storage", "sha256_hex"]
