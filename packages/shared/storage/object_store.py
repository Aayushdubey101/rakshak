"""Object storage: screenshots, PDFs, audio, evidence/report artifacts.

`attachments.object_key` (packages/shared/db/models.py) points here — the
database never holds a blob. No `S3_ENDPOINT_URL`/`S3_ACCESS_KEY` configured
means a local-filesystem store under `data/objects/`, same
DISABLED-not-a-stub convention as everything else phase 7 touches; configure
them and the same `ObjectStore` interface talks to S3 or MinIO instead.

Nothing in the current pipeline calls `put()` yet — ingestion (phase 4) reads
platform media through `MediaLoader` and OCRs it in memory, it doesn't retain
a copy. Wiring "OCR this AND keep the original" is real product behavior
(what gets retained, for how long, is exactly phase 7's own retention-policy
question) that belongs with whichever later phase first needs to show a
human the original screenshot — most likely phase 11 (honeypot isolation) or
phase 12 (reporting). This module exists now, tested and ready, so that wiring
is additive later rather than a rewrite.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from packages.shared.config.settings import get_settings


class ObjectStore(Protocol):
    async def put(self, key: str, data: bytes, *, content_type: str | None = None) -> None: ...
    async def get(self, key: str) -> bytes: ...
    async def delete(self, key: str) -> None: ...
    async def exists(self, key: str) -> bool: ...


class LocalFileObjectStore:
    """Dev/test fallback. Never used when S3/MinIO is configured."""

    def __init__(self, root: str = "data/objects"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        # Reject path traversal — a key is an opaque id, never a filesystem path.
        if ".." in key or key.startswith("/") or key.startswith("\\"):
            raise ValueError(f"invalid object key: {key!r}")
        return self.root / key

    async def put(self, key: str, data: bytes, *, content_type: str | None = None) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    async def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    async def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    async def exists(self, key: str) -> bool:
        return self._path(key).exists()


class S3ObjectStore:
    """S3-compatible (real S3 or MinIO), via aioboto3."""

    def __init__(self, *, endpoint_url: str | None, access_key: str, secret_key: str,
                 bucket: str, region: str):
        import aioboto3

        self._session = aioboto3.Session()
        self._endpoint_url = endpoint_url
        self._access_key = access_key
        self._secret_key = secret_key
        self._bucket = bucket
        self._region = region

    def _client(self):
        return self._session.client(
            "s3", endpoint_url=self._endpoint_url,
            aws_access_key_id=self._access_key, aws_secret_access_key=self._secret_key,
            region_name=self._region,
        )

    async def put(self, key: str, data: bytes, *, content_type: str | None = None) -> None:
        async with self._client() as s3:
            kwargs = {"ContentType": content_type} if content_type else {}
            await s3.put_object(Bucket=self._bucket, Key=key, Body=data, **kwargs)

    async def get(self, key: str) -> bytes:
        async with self._client() as s3:
            response = await s3.get_object(Bucket=self._bucket, Key=key)
            return await response["Body"].read()

    async def delete(self, key: str) -> None:
        async with self._client() as s3:
            await s3.delete_object(Bucket=self._bucket, Key=key)

    async def exists(self, key: str) -> bool:
        async with self._client() as s3:
            try:
                await s3.head_object(Bucket=self._bucket, Key=key)
                return True
            except s3.exceptions.ClientError:
                return False


_store: ObjectStore | None = None


def get_object_store() -> ObjectStore:
    global _store
    if _store is None:
        settings = get_settings()
        if settings.S3_ENDPOINT_URL or (settings.S3_ACCESS_KEY and settings.S3_SECRET_KEY):
            _store = S3ObjectStore(
                endpoint_url=settings.S3_ENDPOINT_URL,
                access_key=settings.S3_ACCESS_KEY or "",
                secret_key=settings.S3_SECRET_KEY or "",
                bucket=settings.S3_BUCKET,
                region=settings.S3_REGION,
            )
        else:
            _store = LocalFileObjectStore()
    return _store


def reset_object_store_cache() -> None:
    global _store
    _store = None
