# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Distributed object storage via Cloudflare R2 (S3-compatible).

All I/O is async via ``aioboto3``.  The module is designed to be
stateless: each call creates a fresh client so workers can be scaled
horizontally without connection pooling issues.

When ``r2_enabled`` is ``False`` (default), operations gracefully fall
back to local filesystem passthrough — this keeps unit tests fast and
lets developers run CrashWise without an R2 account.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path

import aioboto3

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# ── Client factory ───────────────────────────────────────────────────────────


def _get_session() -> aioboto3.Session:
    """Build a boto3 session from settings."""
    settings = get_settings()
    return aioboto3.Session(
        aws_access_key_id=settings.r2_access_key_id or "",
        aws_secret_access_key=settings.r2_secret_access_key.get_secret_value()
        if settings.r2_secret_access_key
        else "",
        region_name=settings.r2_region,
    )


def _get_endpoint() -> str | None:
    """Return the S3-compatible endpoint URL."""
    settings = get_settings()
    if settings.r2_endpoint_url:
        return settings.r2_endpoint_url
    if settings.r2_account_id:
        return f"https://{settings.r2_account_id}.r2.cloudflarestorage.com"
    return None


# ── Public API ───────────────────────────────────────────────────────────────


async def upload_file(
    local_path: Path,
    key: str,
    *,
    bucket: str | None = None,
) -> str:
    """Upload a local file to R2.

    Parameters
    ----------
    local_path:
        Filesystem path to the file.
    key:
        Object key in the bucket (e.g., ``corpus/openssl/seed-1.seed``).
    bucket:
        Override the default bucket from settings.

    Returns
    -------
    The object key that was uploaded.
    """
    settings = get_settings()
    if not settings.r2_enabled:
        log.debug("storage.r2_disabled", key=key, local=str(local_path))
        return key

    bucket = bucket or settings.r2_bucket
    session = _get_session()
    endpoint = _get_endpoint()

    log.info("storage.upload.start", key=key, bucket=bucket, local=str(local_path))

    async with session.client(
        "s3",
        endpoint_url=endpoint,
    ) as client:
        content_type, _ = mimetypes.guess_type(str(local_path))
        extra_args: dict[str, str] = {}
        if content_type:
            extra_args["ContentType"] = content_type

        with local_path.open("rb") as f:
            await client.put_object(
                Bucket=bucket,
                Key=key,
                Body=f,
                **extra_args,
            )

    log.info("storage.upload.complete", key=key, bucket=bucket)
    return key


async def download_file(
    key: str,
    local_path: Path,
    *,
    bucket: str | None = None,
) -> Path:
    """Download an object from R2 to the local filesystem.

    Parameters
    ----------
    key:
        Object key in the bucket.
    local_path:
        Where to write the file locally.
    bucket:
        Override the default bucket from settings.

    Returns
    -------
    The local filesystem path written.
    """
    settings = get_settings()
    if not settings.r2_enabled:
        log.debug("storage.r2_disabled", key=key, local=str(local_path))
        return local_path

    bucket = bucket or settings.r2_bucket
    session = _get_session()
    endpoint = _get_endpoint()

    log.info("storage.download.start", key=key, bucket=bucket, local=str(local_path))

    local_path.parent.mkdir(parents=True, exist_ok=True)
    async with session.client(
        "s3",
        endpoint_url=endpoint,
    ) as client:
        try:
            response = await client.get_object(Bucket=bucket, Key=key)
            async with response["Body"] as stream:
                local_path.write_bytes(await stream.read())
        except Exception as exc:
            log.warning("storage.download.failed", key=key, error=str(exc))
            raise

    log.info("storage.download.complete", key=key, local=str(local_path))
    return local_path


async def list_objects(
    prefix: str,
    *,
    bucket: str | None = None,
) -> list[str]:
    """List object keys under a prefix.

    Returns
    -------
    List of object keys (not full metadata).
    """
    settings = get_settings()
    if not settings.r2_enabled:
        return []

    bucket = bucket or settings.r2_bucket
    session = _get_session()
    endpoint = _get_endpoint()
    keys: list[str] = []

    async with session.client(
        "s3",
        endpoint_url=endpoint,
    ) as client:
        paginator = client.get_paginator("list_objects_v2")
        async for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"])

    return keys


async def sync_directory(
    local_dir: Path,
    remote_prefix: str,
    *,
    direction: str = "down",
    bucket: str | None = None,
) -> list[Path]:
    """Sync a local directory with an R2 prefix.

    Parameters
    ----------
    local_dir:
        Local filesystem directory.
    remote_prefix:
        R2 key prefix (e.g., ``campaigns/abc-123/corpus/``).
    direction:
        ``"down"`` downloads from R2 to local;
        ``"up"`` uploads from local to R2.
    bucket:
        Override the default bucket from settings.

    Returns
    -------
    List of local paths that were synced.
    """
    settings = get_settings()
    if not settings.r2_enabled:
        log.debug("storage.r2_disabled", direction=direction, prefix=remote_prefix)
        return []

    bucket = bucket or settings.r2_bucket
    synced: list[Path] = []

    if direction == "down":
        # Download all objects under prefix.
        keys = await list_objects(remote_prefix, bucket=bucket)
        for key in keys:
            relative = key[len(remote_prefix) :].lstrip("/")
            local_path = local_dir / relative
            await download_file(key, local_path, bucket=bucket)
            synced.append(local_path)

    elif direction == "up":
        # Upload all local files.
        if not local_dir.exists():
            log.warning("storage.local_dir_missing", path=str(local_dir))
            return []
        for path in local_dir.rglob("*"):
            if path.is_file():
                relative = path.relative_to(local_dir).as_posix()
                key = f"{remote_prefix}/{relative}".replace("//", "/")
                await upload_file(path, key, bucket=bucket)
                synced.append(path)

    else:
        raise ValueError(f"Invalid sync direction: {direction}")

    log.info(
        "storage.sync.complete",
        direction=direction,
        prefix=remote_prefix,
        synced=len(synced),
    )
    return synced


async def upload_bytes(
    data: bytes,
    key: str,
    *,
    bucket: str | None = None,
    content_type: str = "application/octet-stream",
) -> str:
    """Upload raw bytes to R2.

    Parameters
    ----------
    data:
        Raw bytes to upload.
    key:
        Object key in the bucket.
    bucket:
        Override the default bucket.
    content_type:
        MIME type of the object.

    Returns
    -------
    The object key that was uploaded.
    """
    settings = get_settings()
    if not settings.r2_enabled:
        log.debug("storage.r2_disabled", key=key)
        return key

    bucket = bucket or settings.r2_bucket
    session = _get_session()
    endpoint = _get_endpoint()

    log.info("storage.upload_bytes.start", key=key, bucket=bucket, size=len(data))

    async with session.client(
        "s3",
        endpoint_url=endpoint,
    ) as client:
        await client.put_object(
            Bucket=bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
        )

    log.info("storage.upload_bytes.complete", key=key, bucket=bucket)
    return key


__all__ = [
    "download_file",
    "list_objects",
    "sync_directory",
    "upload_bytes",
    "upload_file",
]
