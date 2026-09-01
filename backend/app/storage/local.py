"""Filesystem storage backend — the default when MinIO is not running."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from app.core.exceptions import NotFoundError, StorageError
from app.storage.base import StorageBackend


class LocalStorage(StorageBackend):
    name = "local"

    def __init__(self, root: str):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        """Resolve a key inside the storage root, refusing path traversal."""
        if not key or key.startswith("/") or "\x00" in key:
            raise StorageError("Invalid storage key.")
        candidate = (self.root / key).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise StorageError("Storage key escapes the storage root.")
        return candidate

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        path = self._resolve(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
        return key

    def get(self, key: str) -> bytes:
        path = self._resolve(key)
        if not path.is_file():
            raise NotFoundError("The stored file could not be found.")
        return path.read_bytes()

    def delete(self, key: str) -> None:
        path = self._resolve(key)
        if path.is_file():
            path.unlink()

    def exists(self, key: str) -> bool:
        try:
            return self._resolve(key).is_file()
        except StorageError:
            return False

    def health(self) -> tuple[bool, str]:
        try:
            usage = shutil.disk_usage(self.root)
            free_gb = usage.free / (1024**3)
            return True, f"filesystem at {self.root} ({free_gb:.1f} GB free)"
        except Exception as exc:  # pragma: no cover
            return False, str(exc)[:200]
