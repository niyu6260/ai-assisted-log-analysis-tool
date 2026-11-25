from __future__ import annotations

import json
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

from ccu_log_diag.assistant import (
    KnowledgeIndex,
    OpenAICompatibleClient,
    SYSTEM_PROMPT,
    build_assistant_payload,
    validate_assistant_output,
)
from ccu_log_diag.generalization import build_automatic_triage
from ccu_log_diag.pipeline import analyze_logs
from charger_log_cloud.config import CloudSettings
from charger_log_cloud.repository import CloudRepository
from charger_log_cloud.storage import ObjectStore, create_object_store


RESULT_FILES = (
    "report.md",
    "findings.json",
    "meta.json",
    "timeline.json",
    "sessions.json",
    "triage.json",
    "assistant_context.json",
    "assistant.json",
)


def safe_filename(value: str) -> str:
    name = Path(value or "upload.zip").name
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return cleaned[:180] or "upload.zip"


class AnalysisService:
    def __init__(
        self,
        settings: CloudSettings,
        repository: CloudRepository,
        object_store: ObjectStore,
    ):
        self.settings = settings
        self.repository = repository
        self.object_store = object_store

    @classmethod
    def create(cls, settings: CloudSettings | None = None) -> "AnalysisService":
        settings = settings or CloudSettings.from_env()
        settings.local_store_root.mkdir(parents=True, exist_ok=True)
        settings.work_root.mkdir(parents=True, exist_ok=True)
        if settings.database_url.startswith("sqlite:///"):
            database_path = Path(
                settings.database_url.removeprefix("sqlite:///")
            )
            database_path.parent.mkdir(parents=True, exist_ok=True)
        repository = CloudRepository(settings.database_url)
        repository.initialize()
        return cls(settings, repository, create_object_store(settings))

    def submit(
        self,
        source: Path,
        *,
        original_name: str,
        user_id: str,
        request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        job_id = str(uuid.uuid4())
        filename = safe_filename(original_name)
        input_uri = self.object_store.put_file(
            source,
            f"uploads/{job_id}/{filename}",
        )
        return self.repository.create_job(
            job_id=job_id,
            user_id=user_id,
            original_name=filename,
            input_uri=input_uri,
            request=request or {},
        )

    def process_next_job(self) -> dict[str, Any] | None:
        job = self.repository.claim_next_job()
        if not job:
            return None
        job_id = job["id"]
        job_root = self.settings.work_root / "jobs" / job_id
        input_path = job_root / "input" / job["original_name"]
        output_root = job_root / "analysis"
        try:
            self.object_store.materialize(job["input_uri"], input_path)
            analysis = analyze_logs(
                input_path,
                output_root,
                self.settings.rules_path,
            )
            triage = build_automatic_triage(
                analysis.events,
                analysis.findings,
            )
            knowledge = KnowledgeIndex.load(
                Path(__file__).resolve().parents[1] / "knowledge"
            )
            assistant_payload = build_assistant_payload(
                triage,
                analysis.events,
                knowledge,
            )
            (analysis.run_dir / "assistant_context.json").write_text(
                json.dumps(
                    assistant_payload,
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            if self.settings.llm_endpoint:
                client = OpenAICompatibleClient(
                    self.settings.llm_endpoint,
                    self.settings.llm_model,
                    api_key=self.settings.llm_api_key,
                )
                assistant_output = client.complete_json(
                    SYSTEM_PROMPT,
                    assistant_payload,
                )
                validate_assistant_output(
                    assistant_output,
                    assistant_payload["allowed_event_ids"],
                )
                (analysis.run_dir / "assistant.json").write_text(
                    json.dumps(
                        assistant_output,
                        ensure_ascii=False,
                        indent=2,
                    ),
                    encoding="utf-8",
                )
            uris: dict[str, str] = {}
            for name in RESULT_FILES:
                source = analysis.run_dir / name
                if source.is_file():
                    uris[name] = self.object_store.put_file(
                        source,
                        f"results/{job_id}/{name}",
                    )
            result = {
                "run_id": analysis.run_dir.name,
                "artifacts": uris,
                "event_count": len(analysis.events),
                "session_count": len(analysis.sessions),
                "finding_count": len(analysis.findings),
                "durations_ms": analysis.durations_ms,
            }
            self.repository.complete_job(job_id, result)
            return self.repository.get_job(job_id)
        except Exception as exc:
            self.repository.fail_job(
                job_id,
                f"{type(exc).__name__}: {exc}",
            )
            return self.repository.get_job(job_id)
        finally:
            shutil.rmtree(job_root, ignore_errors=True)

    def read_result(self, job: dict[str, Any], name: str) -> bytes:
        uri = job.get("result", {}).get("artifacts", {}).get(name)
        if not uri:
            raise FileNotFoundError(name)
        return self.object_store.read_bytes(uri)

    def cleanup_expired(self) -> int:
        expired = self.repository.expired_jobs(self.settings.retention_days)
        for job in expired:
            self.object_store.delete(job["input_uri"])
            for uri in job.get("result", {}).get("artifacts", {}).values():
                self.object_store.delete(uri)
            self.repository.delete_job(job["id"])
        return len(expired)

    def result_json(self, job: dict[str, Any], name: str) -> Any:
        return json.loads(self.read_result(job, name).decode("utf-8"))
