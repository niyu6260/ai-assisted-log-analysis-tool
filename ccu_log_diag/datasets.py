from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


SCHEMA_VERSION = "1.0"
DOMAINS = {
    "cp",
    "plc_slac",
    "iso15118",
    "power",
    "ocpp",
    "network",
    "system",
    "unknown",
}
CONCLUSION_STATUSES = {"confirmed", "probable", "inconclusive"}
CONFIDENCE_LEVELS = {"high", "medium", "low"}
LABEL_STATUSES = {"draft", "reviewed", "gold"}
SPLITS = {"train", "validation", "blind", "unassigned"}
EVIDENCE_ROLES = {"support", "counter", "context"}


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    message: str
    severity: str = "error"


@dataclass
class DatasetValidationResult:
    files: int = 0
    valid: int = 0
    issues: list[ValidationIssue] = field(default_factory=list)
    leakage_groups: dict[str, list[str]] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "valid": self.valid,
            "passed": self.passed,
            "issues": [asdict(issue) for issue in self.issues],
            "leakage_groups": self.leakage_groups,
        }


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _require(
    mapping: dict[str, Any],
    key: str,
    path: str,
    issues: list[ValidationIssue],
) -> Any:
    value = mapping.get(key)
    if value is None or value == "" or value == []:
        issues.append(ValidationIssue(f"{path}.{key}", "required value is missing"))
    return value


def validate_case_data(data: Any, *, source: str = "<memory>") -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(data, dict):
        return [ValidationIssue(source, "case document must be a mapping")]

    if data.get("schema_version") != SCHEMA_VERSION:
        issues.append(
            ValidationIssue(
                "schema_version",
                f"must equal {SCHEMA_VERSION!r}",
            )
        )
    _require(data, "case_id", "case", issues)
    _require(data, "title", "case", issues)

    source_data = data.get("source")
    if not isinstance(source_data, dict):
        issues.append(ValidationIssue("source", "must be a mapping"))
    else:
        _require(source_data, "archive_uri", "source", issues)
        if source_data.get("raw_access") not in {
            "restricted",
            "internal",
            "anonymized",
        }:
            issues.append(
                ValidationIssue(
                    "source.raw_access",
                    "must be restricted, internal, or anonymized",
                )
            )

    charger = data.get("charger")
    if not isinstance(charger, dict):
        issues.append(ValidationIssue("charger", "must be a mapping"))
    else:
        _require(charger, "model", "charger", issues)
        _require(charger, "serial_numbers", "charger", issues)

    incident = data.get("incident")
    if not isinstance(incident, dict):
        issues.append(ValidationIssue("incident", "must be a mapping"))
    else:
        _require(incident, "customer_symptom", "incident", issues)
        start = _parse_timestamp(_require(incident, "start", "incident", issues))
        end = _parse_timestamp(_require(incident, "end", "incident", issues))
        if start and end and start > end:
            issues.append(
                ValidationIssue("incident", "start must not be after end")
            )

    labels = data.get("labels")
    if not isinstance(labels, dict):
        issues.append(ValidationIssue("labels", "must be a mapping"))
    else:
        domains = labels.get("domains")
        if not isinstance(domains, list) or not domains:
            issues.append(ValidationIssue("labels.domains", "must be a non-empty list"))
        elif invalid := sorted(set(domains) - DOMAINS):
            issues.append(
                ValidationIssue(
                    "labels.domains",
                    f"unknown domains: {', '.join(invalid)}",
                )
            )
        _require(labels, "root_cause_category", "labels", issues)
        _require(labels, "root_cause_summary", "labels", issues)
        if labels.get("conclusion_status") not in CONCLUSION_STATUSES:
            issues.append(
                ValidationIssue(
                    "labels.conclusion_status",
                    "must be confirmed, probable, or inconclusive",
                )
            )
        if labels.get("confidence") not in CONFIDENCE_LEVELS:
            issues.append(
                ValidationIssue(
                    "labels.confidence",
                    "must be high, medium, or low",
                )
            )
        evidence = labels.get("evidence", [])
        if not isinstance(evidence, list):
            issues.append(ValidationIssue("labels.evidence", "must be a list"))
        else:
            for index, item in enumerate(evidence):
                if not isinstance(item, dict):
                    issues.append(
                        ValidationIssue(
                            f"labels.evidence[{index}]",
                            "must be a mapping",
                        )
                    )
                    continue
                if item.get("role", "support") not in EVIDENCE_ROLES:
                    issues.append(
                        ValidationIssue(
                            f"labels.evidence[{index}].role",
                            f"must be one of {sorted(EVIDENCE_ROLES)}",
                        )
                    )
                if not any(
                    item.get(key)
                    for key in ("event_id", "source_file", "description")
                ):
                    issues.append(
                        ValidationIssue(
                            f"labels.evidence[{index}]",
                            "requires event_id, source_file, or description",
                        )
                    )

    governance = data.get("governance")
    if not isinstance(governance, dict):
        issues.append(ValidationIssue("governance", "must be a mapping"))
    else:
        status = governance.get("label_status")
        if status not in LABEL_STATUSES:
            issues.append(
                ValidationIssue(
                    "governance.label_status",
                    f"must be one of {sorted(LABEL_STATUSES)}",
                )
            )
        split = governance.get("split", "unassigned")
        if split not in SPLITS:
            issues.append(
                ValidationIssue(
                    "governance.split",
                    f"must be one of {sorted(SPLITS)}",
                )
            )
        reviewers = governance.get("reviewers", [])
        if not isinstance(reviewers, list):
            issues.append(ValidationIssue("governance.reviewers", "must be a list"))
        elif status == "gold" and len(set(reviewers)) < 2:
            issues.append(
                ValidationIssue(
                    "governance.reviewers",
                    "gold labels require two distinct reviewers",
                )
            )
        _require(governance, "label_version", "governance", issues)
    return issues


def load_case(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    issues = validate_case_data(data, source=str(path))
    errors = [issue for issue in issues if issue.severity == "error"]
    if errors:
        summary = "; ".join(f"{issue.path}: {issue.message}" for issue in errors)
        raise ValueError(f"Invalid golden case {path}: {summary}")
    return data


def validate_dataset(root: Path) -> DatasetValidationResult:
    files = sorted(root.rglob("case.yaml"))
    result = DatasetValidationResult(files=len(files))
    split_groups: dict[str, dict[str, set[str]]] = {}
    for path in files:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            result.issues.append(ValidationIssue(str(path), str(exc)))
            continue
        issues = validate_case_data(data, source=str(path))
        if not issues:
            result.valid += 1
        result.issues.extend(
            ValidationIssue(
                f"{path}:{issue.path}",
                issue.message,
                issue.severity,
            )
            for issue in issues
        )
        if not isinstance(data, dict):
            continue
        governance = data.get("governance", {})
        split = governance.get("split", "unassigned")
        for group in governance.get("group_keys", []):
            split_groups.setdefault(str(group), {}).setdefault(split, set()).add(
                str(data.get("case_id", path.parent.name))
            )

    for group, by_split in sorted(split_groups.items()):
        active_splits = {
            split: cases
            for split, cases in by_split.items()
            if split != "unassigned" and cases
        }
        if len(active_splits) > 1:
            case_ids = sorted(
                case_id
                for cases in active_splits.values()
                for case_id in cases
            )
            result.leakage_groups[group] = case_ids
            result.issues.append(
                ValidationIssue(
                    f"group_keys.{group}",
                    "group appears in multiple dataset splits: "
                    + ", ".join(sorted(active_splits)),
                )
            )
    return result


SENSITIVE_PATTERNS = {
    "iccid": re.compile(r"\b89\d{16,20}\b"),
    "vin": re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
    "ipv4": re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)"
        r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
    ),
    "id_tag": re.compile(
        r"(?i)(?P<prefix>\b(?:idTag|VID|RFID|card)\s*[:=]\s*)"
        r"(?P<value>[A-Z0-9_-]{6,64})"
    ),
}


def pseudonymize(value: str, secret: str, *, prefix: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:12]
    return f"<{prefix}:{digest}>"


def redact_text(text: str, *, secret: str) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    output = text
    for name in ("iccid", "vin", "ipv4"):
        pattern = SENSITIVE_PATTERNS[name]

        def replace(match: re.Match[str], label: str = name) -> str:
            counts[label] = counts.get(label, 0) + 1
            return pseudonymize(match.group(0), secret, prefix=label)

        output = pattern.sub(replace, output)

    def replace_tag(match: re.Match[str]) -> str:
        counts["id_tag"] = counts.get("id_tag", 0) + 1
        return match.group("prefix") + pseudonymize(
            match.group("value"),
            secret,
            prefix="id_tag",
        )

    output = SENSITIVE_PATTERNS["id_tag"].sub(replace_tag, output)
    return output, counts


def write_manifest(
    case_paths: Iterable[Path],
    output: Path,
    *,
    name: str,
) -> None:
    entries = []
    for path in sorted(case_paths):
        data = load_case(path)
        entries.append(
            {
                "case_id": data["case_id"],
                "path": str(path.as_posix()),
                "split": data["governance"].get("split", "unassigned"),
                "label_version": data["governance"]["label_version"],
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        yaml.safe_dump(
            {
                "manifest_version": "1.0",
                "name": name,
                "cases": entries,
            },
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
