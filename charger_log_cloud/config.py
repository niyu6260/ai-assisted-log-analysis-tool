from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.casefold() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class CloudSettings:
    database_url: str
    object_store: str
    local_store_root: Path
    work_root: Path
    rules_path: Path
    s3_bucket: str
    s3_endpoint_url: str | None
    s3_region: str
    s3_access_key: str | None
    s3_secret_key: str | None
    require_auth: bool
    max_upload_bytes: int
    retention_days: int
    worker_poll_seconds: float
    llm_endpoint: str | None
    llm_model: str
    llm_api_key: str | None

    @classmethod
    def from_env(cls) -> "CloudSettings":
        project_root = Path(__file__).resolve().parents[1]
        state_root = Path(
            os.getenv("CHARGER_CLOUD_STATE", project_root / ".cloud-state")
        ).resolve()
        database_url = os.getenv(
            "CHARGER_DATABASE_URL",
            f"sqlite:///{(state_root / 'charger-cloud.db').as_posix()}",
        )
        return cls(
            database_url=database_url,
            object_store=os.getenv("CHARGER_OBJECT_STORE", "local").casefold(),
            local_store_root=Path(
                os.getenv(
                    "CHARGER_LOCAL_STORE_ROOT",
                    state_root / "objects",
                )
            ).resolve(),
            work_root=Path(
                os.getenv("CHARGER_WORK_ROOT", state_root / "work")
            ).resolve(),
            rules_path=Path(
                os.getenv(
                    "CHARGER_RULES_PATH",
                    project_root / "rules" / "pack_v1.yaml",
                )
            ).resolve(),
            s3_bucket=os.getenv("CHARGER_S3_BUCKET", "charger-logs"),
            s3_endpoint_url=os.getenv("CHARGER_S3_ENDPOINT_URL"),
            s3_region=os.getenv("CHARGER_S3_REGION", "us-east-1"),
            s3_access_key=os.getenv("CHARGER_S3_ACCESS_KEY"),
            s3_secret_key=os.getenv("CHARGER_S3_SECRET_KEY"),
            require_auth=_bool_env("CHARGER_REQUIRE_AUTH", True),
            max_upload_bytes=int(
                os.getenv("CHARGER_MAX_UPLOAD_BYTES", str(2 * 1024**3))
            ),
            retention_days=int(os.getenv("CHARGER_RETENTION_DAYS", "90")),
            worker_poll_seconds=float(
                os.getenv("CHARGER_WORKER_POLL_SECONDS", "2")
            ),
            llm_endpoint=os.getenv("CHARGER_LLM_ENDPOINT"),
            llm_model=os.getenv("CHARGER_LLM_MODEL", "internal-diagnostic-model"),
            llm_api_key=os.getenv("CHARGER_LLM_API_KEY"),
        )
