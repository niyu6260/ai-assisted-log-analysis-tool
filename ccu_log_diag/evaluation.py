from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from ccu_log_diag.pipeline import analyze_logs


@dataclass
class CaseOutcome:
    case_id: str
    passed: bool
    expected_findings: list[str]
    actual_findings: list[str]
    unexpected_findings: list[str]
    parse_rate: float
    duration_ms: int
    run_dir: str


@dataclass
class EvaluationResult:
    total: int
    passed: int
    top1_accuracy: float
    false_positive_rate: float
    inconclusive_rate: float
    average_parse_rate: float
    total_duration_ms: int
    cases: list[CaseOutcome]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_manifest(manifest_path: Path, rules_path: Path, out_dir: Path) -> EvaluationResult:
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    definitions = data.get("cases", []) if isinstance(data, dict) else []
    outcomes: list[CaseOutcome] = []
    top1_hits = 0
    false_positives = 0
    inconclusive = 0
    parse_rates: list[float] = []
    total_duration = 0

    for definition in definitions:
        input_path = (manifest_path.parent / definition["input"]).resolve()
        result = analyze_logs(input_path, out_dir, rules_path)
        actual = [finding.rule_id for finding in result.findings]
        expected = list(definition.get("expected_findings", []))
        allowed = set(expected) | set(definition.get("allowed_findings", []))
        unexpected = [
            rule_id
            for rule_id in actual
            if rule_id not in allowed and rule_id != "inconclusive" and not rule_id.startswith("case:")
        ]
        confirmed = [rule_id for rule_id in actual if rule_id != "inconclusive"]
        if confirmed and confirmed[0] in expected:
            top1_hits += 1
        if "inconclusive" in actual:
            inconclusive += 1
        false_positives += len(unexpected)
        parsed = sum(artifact.parse_status == "parsed" for artifact in result.artifacts)
        parse_rate = parsed / len(result.artifacts) if result.artifacts else 0.0
        parse_rates.append(parse_rate)
        duration = sum(result.durations_ms.values())
        total_duration += duration
        outcomes.append(
            CaseOutcome(
                case_id=definition["id"],
                passed=all(item in actual for item in expected) and not unexpected,
                expected_findings=expected,
                actual_findings=actual,
                unexpected_findings=unexpected,
                parse_rate=parse_rate,
                duration_ms=duration,
                run_dir=str(result.run_dir),
            )
        )

    total = len(outcomes)
    return EvaluationResult(
        total=total,
        passed=sum(outcome.passed for outcome in outcomes),
        top1_accuracy=top1_hits / total if total else 0.0,
        false_positive_rate=false_positives / total if total else 0.0,
        inconclusive_rate=inconclusive / total if total else 0.0,
        average_parse_rate=sum(parse_rates) / total if total else 0.0,
        total_duration_ms=total_duration,
        cases=outcomes,
    )
