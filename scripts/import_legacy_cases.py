from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ccu_log_diag.datasets import SCHEMA_VERSION, validate_case_data, write_manifest


DETECTOR_LABELS: dict[str, tuple[list[str], str]] = {
    "network_manager_ownership_conflict": (
        ["network", "system"],
        "charger_configuration",
    ),
    "ev_estop_at_max_current": (
        ["iso15118", "power"],
        "vehicle_request_or_bms_behavior",
    ),
    "s20_state_lifecycle": (["system", "ocpp"], "firmware_regression"),
    "maintenance_backend_disconnect": (
        ["network", "ocpp"],
        "external_network_or_backend_path",
    ),
    "fognode_operation_path_failure": (
        ["network", "ocpp"],
        "external_network_or_backend_path",
    ),
    "ev_invalid_target_voltage": (
        ["iso15118"],
        "vehicle_request_or_bms_behavior",
    ),
    "bmw_i3_module_switch_dip": (
        ["power", "iso15118"],
        "power_conversion_or_module",
    ),
    "lem2_internal_ethernet_fault": (
        ["network", "power"],
        "internal_network_or_endpoint",
    ),
    "lem2_http_service_hang": (
        ["network", "power"],
        "process_or_service_failure",
    ),
    "dual_terminal_l20_recovery": (
        ["power", "network"],
        "metering_or_measurement",
    ),
    "plug_and_play_idtag_rejected": (
        ["ocpp"],
        "backend_authorization_policy",
    ),
    "precharge_residual_voltage": (
        ["iso15118", "power"],
        "protocol_state_machine",
    ),
    "current_demand_overvoltage_unresolved": (
        ["power", "iso15118"],
        "unresolved",
    ),
    "ems_low_power_taper": (
        ["power", "iso15118"],
        "vehicle_request_or_bms_behavior",
    ),
    "s25_dynamic_ramp_tracking": (
        ["power", "iso15118"],
        "power_conversion_or_module",
    ),
    "initial_precharge_zero_voltage": (
        ["iso15118", "power"],
        "protocol_state_machine",
    ),
    "c36_cp_state_e_lifecycle": (
        ["cp"],
        "cp_physical_or_sensing_path",
    ),
    "single_pm_fan_fault": (
        ["power"],
        "power_conversion_or_module",
    ),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _legacy_case(
    path: Path,
    *,
    hash_inputs: bool,
    split: str,
) -> dict[str, Any]:
    source = yaml.safe_load(path.read_text(encoding="utf-8"))
    detector = str(source.get("detector", source["id"]))
    domains, category = DETECTOR_LABELS.get(
        detector,
        (["unknown"], "unresolved"),
    )
    selection = source["source_selection"]
    truth = source["ground_truth"]
    metadata = source.get("metadata", {})
    input_path = Path(source["input"])
    serials = [
        selection["serial_number"],
        *selection.get("related_serial_numbers", []),
    ]
    source_data: dict[str, Any] = {
        "archive_uri": str(input_path),
        "raw_access": "restricted",
        "anonymization_status": "not_reviewed",
        "legacy_case_path": str(path.as_posix()),
    }
    if hash_inputs and input_path.is_file():
        source_data["sha256"] = _sha256(input_path)

    group_keys = [f"archive:{input_path.name.casefold()}"]
    if metadata.get("site"):
        group_keys.append(f"site:{str(metadata['site']).casefold()}")

    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": source["id"],
        "title": source.get("title", source["id"]),
        "source": source_data,
        "charger": {
            "model": str(metadata.get("charger_model", "unknown")),
            "serial_numbers": serials,
            "firmware_versions": [],
        },
        "incident": {
            "start": source["incident"]["start"],
            "end": source["incident"]["end"],
            "timezone": "UTC",
            "customer_symptom": truth["symptom"],
        },
        "labels": {
            "domains": domains,
            "root_cause_category": category,
            "root_cause_summary": truth["root_cause"],
            "conclusion_status": truth.get("confirmation_status", "probable"),
            "confidence": truth.get("confidence", "medium"),
            "trigger_hypothesis": truth.get("trigger_hypothesis", ""),
            "expected_findings": source.get("expected", {}).get("findings", []),
            "forbidden_findings": source.get("expected", {}).get(
                "forbidden_findings", []
            ),
            "evidence": [],
            "missing_evidence": truth.get("missing_proof", []),
            "recommended_actions": [],
        },
        "governance": {
            "label_status": "reviewed",
            "label_version": "1.0",
            "split": split,
            "reviewers": ["legacy-expert"],
            "group_keys": group_keys,
            "imported_at": datetime.now(timezone.utc).isoformat(),
        },
        "legacy": {
            "detector": detector,
            "customer_context_needed": truth.get("customer_context_needed", []),
            "metadata": metadata,
        },
    }


def _blind_cases(path: Path, *, split: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    source = yaml.safe_load(path.read_text(encoding="utf-8"))
    imported: list[dict[str, Any]] = []
    for case_id, label in source.get("cases", {}).items():
        if label.get("status") != "revealed":
            continue
        categories = label.get("root_cause_categories")
        category = (
            categories[0]
            if isinstance(categories, list) and categories
            else label.get("root_cause_category", "unresolved")
        )
        imported.append(
            {
                "schema_version": SCHEMA_VERSION,
                "case_id": case_id,
                "title": f"Blind benchmark {case_id}",
                "source": {
                    "archive_uri": f"blind_tests/{source['batch_id']}/{case_id}",
                    "raw_access": "restricted",
                    "anonymization_status": "not_reviewed",
                    "legacy_case_path": str(path.as_posix()),
                },
                "charger": {
                    "model": "unknown",
                    "serial_numbers": ["unknown"],
                    "firmware_versions": [],
                },
                "incident": {
                    "start": "1970-01-01T00:00:00Z",
                    "end": "1970-01-01T00:00:00Z",
                    "timezone": "UTC",
                    "customer_symptom": "See frozen blind-test intake and expert label.",
                },
                "labels": {
                    "domains": label.get("affected_domains", ["unknown"]),
                    "root_cause_category": category,
                    "root_cause_summary": label["root_cause"],
                    "conclusion_status": label.get(
                        "confirmation_status", "confirmed"
                    ),
                    "confidence": "high",
                    "expected_findings": label.get("expected_findings", []),
                    "forbidden_findings": [],
                    "evidence": [
                        {
                            "role": "support",
                            "description": item,
                        }
                        for item in label.get("key_timeline", [])
                    ],
                    "missing_evidence": [],
                    "recommended_actions": [],
                },
                "governance": {
                    "label_status": "reviewed",
                    "label_version": "1.0",
                    "split": split,
                    "reviewers": ["blind-test-expert"],
                    "group_keys": [f"blind:{source['batch_id']}:{case_id}"],
                    "imported_at": datetime.now(timezone.utc).isoformat(),
                },
                "legacy": {
                    "blind_batch": source["batch_id"],
                    "root_cause_categories": categories or [category],
                },
            }
        )
    return imported


def import_cases(
    source_dir: Path,
    output_dir: Path,
    *,
    blind_labels: Path | None = None,
    split: str = "unassigned",
    limit: int | None = None,
    overwrite: bool = False,
    hash_inputs: bool = False,
) -> list[Path]:
    documents = [
        _legacy_case(path, hash_inputs=hash_inputs, split=split)
        for path in sorted(source_dir.rglob("case.yaml"))
    ]
    if blind_labels:
        documents.extend(_blind_cases(blind_labels, split="blind"))
    if limit is not None:
        documents = documents[:limit]

    written: list[Path] = []
    for document in documents:
        issues = validate_case_data(document)
        if issues:
            details = "; ".join(
                f"{issue.path}: {issue.message}" for issue in issues
            )
            raise ValueError(f"Generated invalid case {document['case_id']}: {details}")
        destination = output_dir / document["case_id"] / "case.yaml"
        if destination.exists() and not overwrite:
            raise FileExistsError(
                f"{destination} exists; pass --overwrite to replace it"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            yaml.safe_dump(
                document,
                sort_keys=False,
                allow_unicode=True,
                width=100,
            ),
            encoding="utf-8",
        )
        written.append(destination)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description="Import legacy analyzed cases")
    parser.add_argument("--source", type=Path, default=Path("cases"))
    parser.add_argument("--out", type=Path, default=Path("datasets/cases"))
    parser.add_argument("--blind-labels", type=Path)
    parser.add_argument("--split", default="unassigned")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--hash-inputs", action="store_true")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("datasets/manifests/all.yaml"),
    )
    args = parser.parse_args()
    written = import_cases(
        args.source,
        args.out,
        blind_labels=args.blind_labels,
        split=args.split,
        limit=args.limit,
        overwrite=args.overwrite,
        hash_inputs=args.hash_inputs,
    )
    write_manifest(written, args.manifest, name="all-imported-cases")
    print(f"Imported {len(written)} cases")
    print(f"Manifest: {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
