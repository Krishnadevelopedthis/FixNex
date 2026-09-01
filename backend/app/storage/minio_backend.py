"""MinIO / S3-compatible storage backend."""
from __future__ import annotations

import io

from app.core.exceptions import NotFoundError, StorageError
from app.storage.base import StorageBackend


class MinIOStorage(StorageBackend):
    name = "minio"

    def __init__(self, endpoint: str, access_key: str, secret_key: str, bucket: str, secure: bool = False):
        from minio import Minio

        self.bucket = bucket
        self.endpoint = endpoint
        self.client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
        if not self.client.bucket_exists(bucket):
            self.client.make_bucket(bucket)

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        try:
            self.client.put_object(
                self.bucket, key, io.BytesIO(data), length=len(data), content_type=content_type
            )
        except Exception as exc:
            raise StorageError(f"Could not store the object: {exc}") from exc
        return key

    def get(self, key: str) -> bytes:
        response = None
        try:
            response = self.client.get_object(self.bucket, key)
            return response.read()
        except Exception as exc:
            raise NotFoundError(f"The stored file could not be retrieved: {exc}") from exc
        finally:
            if response is not None:
                response.close()
                response.release_conn()

    def delete(self, key: str) -> None:
        try:
            self.client.remove_object(self.bucket, key)
        except Exception as exc:  # pragma: no cover
            raise StorageError(f"Could not delete the object: {exc}") from exc

    def exists(self, key: str) -> bool:
        try:
            self.client.stat_object(self.bucket, key)
            return True
        except Exception:
            return False

    def health(self) -> tuple[bool, str]:
        try:
            self.client.bucket_exists(self.bucket)
            return True, f"MinIO at {self.endpoint}, bucket '{self.bucket}'"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"[:200]
