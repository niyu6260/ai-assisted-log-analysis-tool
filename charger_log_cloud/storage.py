from __future__ import annotations

import shutil
from pathlib import Path, PurePosixPath
from typing import Protocol

from charger_log_cloud.config import CloudSettings


class ObjectStore(Protocol):
    def put_file(self, source: Path, key: str) -> str: ...

    def materialize(self, uri: str, destination: Path) -> Path: ...

    def read_bytes(self, uri: str) -> bytes: ...

    def delete(self, uri: str) -> None: ...


def _safe_key(key: str) -> str:
    path = PurePosixPath(key)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Unsafe object key: {key}")
    return str(path)


class LocalObjectStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        candidate = (self.root / _safe_key(key)).resolve()
        if self.root != candidate and self.root not in candidate.parents:
            raise ValueError(f"Object key escapes root: {key}")
        return candidate

    def put_file(self, source: Path, key: str) -> str:
        destination = self._path(key)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return f"local://{_safe_key(key)}"

    def materialize(self, uri: str, destination: Path) -> Path:
        if not uri.startswith("local://"):
            raise ValueError(f"Unsupported local object URI: {uri}")
        source = self._path(uri.removeprefix("local://"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return destination

    def read_bytes(self, uri: str) -> bytes:
        if not uri.startswith("local://"):
            raise ValueError(f"Unsupported local object URI: {uri}")
        return self._path(uri.removeprefix("local://")).read_bytes()

    def delete(self, uri: str) -> None:
        if not uri.startswith("local://"):
            raise ValueError(f"Unsupported local object URI: {uri}")
        self._path(uri.removeprefix("local://")).unlink(missing_ok=True)


class S3ObjectStore:
    def __init__(self, settings: CloudSettings):
        import boto3

        self.bucket = settings.s3_bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url,
            region_name=settings.s3_region,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
        )

    def put_file(self, source: Path, key: str) -> str:
        safe_key = _safe_key(key)
        self.client.upload_file(str(source), self.bucket, safe_key)
        return f"s3://{self.bucket}/{safe_key}"

    def _parts(self, uri: str) -> tuple[str, str]:
        if not uri.startswith("s3://"):
            raise ValueError(f"Unsupported S3 URI: {uri}")
        bucket, _, key = uri.removeprefix("s3://").partition("/")
        if not bucket or not key:
            raise ValueError(f"Invalid S3 URI: {uri}")
        return bucket, _safe_key(key)

    def materialize(self, uri: str, destination: Path) -> Path:
        bucket, key = self._parts(uri)
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.client.download_file(bucket, key, str(destination))
        return destination

    def read_bytes(self, uri: str) -> bytes:
        bucket, key = self._parts(uri)
        response = self.client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()

    def delete(self, uri: str) -> None:
        bucket, key = self._parts(uri)
        self.client.delete_object(Bucket=bucket, Key=key)


def create_object_store(settings: CloudSettings) -> ObjectStore:
    if settings.object_store == "local":
        return LocalObjectStore(settings.local_store_root)
    if settings.object_store == "s3":
        return S3ObjectStore(settings)
    raise ValueError(
        f"CHARGER_OBJECT_STORE must be local or s3, got {settings.object_store!r}"
    )
