"""Object storage abstraction for evidence and generated reports."""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod


class StorageBackend(ABC):
    """Minimal object-store interface.

    PostgreSQL only ever holds metadata; the bytes live here.
    """

    name: str = "base"

    @abstractmethod
    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str: ...

    @abstractmethod
    def get(self, key: str) -> bytes: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def health(self) -> tuple[bool, str]: ...


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
