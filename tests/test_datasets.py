from __future__ import annotations

from pathlib import Path

import yaml

from ccu_log_diag.datasets import (
    redact_text,
    validate_case_data,
    validate_dataset,
    write_manifest,
)
from scripts.import_legacy_cases import import_cases


ROOT = Path(__file__).resolve().parents[1]


def test_twenty_case_pilot_import_validates_without_raw_log_copy(
    tmp_path: Path,
) -> None:
    output = tmp_path / "cases"
    written = import_cases(
        ROOT / "cases",
        output,
        blind_labels=ROOT / "blind_tests" / "batch_001" / "revealed_labels.yaml",
        limit=20,
    )

    assert len(written) == 20
    result = validate_dataset(output)
    assert result.passed
    assert result.valid == 20
    assert not result.leakage_groups
    assert all(path.name == "case.yaml" for path in written)
    assert all(not any(path.parent.glob("*.zip")) for path in written)

    manifest = tmp_path / "pilot20.yaml"
    write_manifest(written, manifest, name="pilot20")
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    assert len(data["cases"]) == 20
    assert all(len(item["sha256"]) == 64 for item in data["cases"])


def test_gold_case_requires_two_distinct_reviewers() -> None:
    data = {
        "schema_version": "1.0",
        "case_id": "gold-001",
        "title": "Example",
        "source": {
            "archive_uri": "s3://logs/example.zip",
            "raw_access": "restricted",
        },
        "charger": {"model": "480E", "serial_numbers": ["masked"]},
        "incident": {
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-01T00:10:00Z",
            "customer_symptom": "Cannot charge",
        },
        "labels": {
            "domains": ["ocpp"],
            "root_cause_category": "backend_authorization_policy",
            "root_cause_summary": "Backend rejected authorization.",
            "conclusion_status": "confirmed",
            "confidence": "high",
            "evidence": [],
        },
        "governance": {
            "label_status": "gold",
            "label_version": "1.0",
            "split": "blind",
            "reviewers": ["one-reviewer"],
        },
    }

    issues = validate_case_data(data)
    assert any(
        issue.path == "governance.reviewers"
        and "two distinct reviewers" in issue.message
        for issue in issues
    )


def test_split_leakage_is_detected(tmp_path: Path) -> None:
    base = {
        "schema_version": "1.0",
        "title": "Example",
        "source": {
            "archive_uri": "restricted://example.zip",
            "raw_access": "restricted",
        },
        "charger": {"model": "480E", "serial_numbers": ["masked"]},
        "incident": {
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-01T00:10:00Z",
            "customer_symptom": "Cannot charge",
        },
        "labels": {
            "domains": ["power"],
            "root_cause_category": "power_conversion_or_module",
            "root_cause_summary": "Module fault.",
            "conclusion_status": "confirmed",
            "confidence": "high",
            "evidence": [],
        },
        "governance": {
            "label_status": "reviewed",
            "label_version": "1.0",
            "reviewers": ["expert"],
            "group_keys": ["site:same-site"],
        },
    }
    for case_id, split in (("train-case", "train"), ("blind-case", "blind")):
        document = {
            **base,
            "case_id": case_id,
            "governance": {**base["governance"], "split": split},
        }
        path = tmp_path / case_id / "case.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(
            yaml.safe_dump(document, sort_keys=False),
            encoding="utf-8",
        )

    result = validate_dataset(tmp_path)
    assert not result.passed
    assert result.leakage_groups["site:same-site"] == [
        "blind-case",
        "train-case",
    ]


def test_redaction_is_stable_and_preserves_field_labels() -> None:
    text = (
        "ICCID 8944501234567890123 VIN WDB9630201L123456 "
        "ip 192.168.10.2 idTag=FD18845A"
    )
    first, counts = redact_text(text, secret="test-secret")
    second, _ = redact_text(text, secret="test-secret")

    assert first == second
    assert "192.168.10.2" not in first
    assert "FD18845A" not in first
    assert "idTag=<id_tag:" in first
    assert counts["ipv4"] == 1
    assert counts["id_tag"] == 1
