from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

from fastapi.testclient import TestClient

from charger_log_cloud.app import create_app
from charger_log_cloud.config import CloudSettings
from charger_log_cloud.service import AnalysisService


ROOT = Path(__file__).resolve().parents[1]


def _settings(tmp_path: Path) -> CloudSettings:
    return CloudSettings(
        database_url=f"sqlite:///{(tmp_path / 'cloud.db').as_posix()}",
        object_store="local",
        local_store_root=tmp_path / "objects",
        work_root=tmp_path / "work",
        rules_path=ROOT / "rules" / "pack_v1.yaml",
        s3_bucket="unused",
        s3_endpoint_url=None,
        s3_region="us-east-1",
        s3_access_key=None,
        s3_secret_key=None,
        require_auth=True,
        max_upload_bytes=20 * 1024 * 1024,
        retention_days=90,
        worker_poll_seconds=0.01,
        llm_endpoint=None,
        llm_model="test-model",
        llm_api_key=None,
    )


def _archive(tmp_path: Path) -> Path:
    archive = tmp_path / "incident.zip"
    source = ROOT / "tests" / "fixtures" / "labeled" / "network_tls_failure" / "network.log"
    with ZipFile(archive, "w") as output:
        output.write(source, "network.log")
    return archive


def _headers(user: str, role: str) -> dict[str, str]:
    return {"X-User-Id": user, "X-User-Role": role}


def test_private_cloud_upload_worker_report_feedback_and_audit(
    tmp_path: Path,
) -> None:
    service = AnalysisService.create(_settings(tmp_path))
    client = TestClient(create_app(service))
    archive = _archive(tmp_path)

    assert client.get("/health").json()["status"] == "ok"
    with archive.open("rb") as handle:
        unauthorized = client.post(
            "/api/v1/jobs",
            files={"file": ("incident.zip", handle, "application/zip")},
        )
    assert unauthorized.status_code == 401

    with archive.open("rb") as handle:
        submitted = client.post(
            "/api/v1/jobs",
            headers=_headers("analyst-1", "user"),
            files={"file": ("incident.zip", handle, "application/zip")},
            data={"request_json": '{"customer_symptom":"backend offline"}'},
        )
    assert submitted.status_code == 202
    job_id = submitted.json()["id"]
    assert submitted.json()["status"] == "queued"

    hidden = client.get(
        f"/api/v1/jobs/{job_id}",
        headers=_headers("other-user", "user"),
    )
    assert hidden.status_code == 404

    completed = service.process_next_job()
    assert completed
    assert completed["status"] == "succeeded"

    job = client.get(
        f"/api/v1/jobs/{job_id}",
        headers=_headers("analyst-1", "user"),
    )
    assert job.json()["result"]["finding_count"] >= 1
    assert "assistant_context.json" in job.json()["result"]["artifacts"]
    assert client.get(
        f"/api/v1/jobs/{job_id}/report",
        headers=_headers("analyst-1", "user"),
    ).status_code == 200
    assert client.get(
        f"/api/v1/jobs/{job_id}/findings",
        headers=_headers("analyst-1", "user"),
    ).status_code == 200
    triage = client.get(
        f"/api/v1/jobs/{job_id}/triage",
        headers=_headers("analyst-1", "user"),
    )
    assert triage.status_code == 200
    assert "domain_ranking" in triage.json()

    denied_feedback = client.post(
        f"/api/v1/jobs/{job_id}/feedback",
        headers=_headers("analyst-1", "user"),
        json={"verdict": "incorrect"},
    )
    assert denied_feedback.status_code == 403

    accepted_feedback = client.post(
        f"/api/v1/jobs/{job_id}/feedback",
        headers=_headers("expert-1", "expert"),
        json={
            "verdict": "incorrect",
            "corrected_domains": ["network"],
            "corrected_root_cause_category": "external_network_or_backend_path",
            "corrected_summary": "TLS path failure",
            "evidence_event_ids": [],
        },
    )
    assert accepted_feedback.status_code == 200
    assert accepted_feedback.json()["review_status"] == "pending_review"

    audit = client.get(
        "/api/v1/audit",
        headers=_headers("admin-1", "admin"),
    )
    assert audit.status_code == 200
    assert {item["action"] for item in audit.json()} >= {
        "job.submit",
        "feedback.submit",
    }
