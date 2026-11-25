from __future__ import annotations

import math
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median
from typing import Any

from ccu_log_diag.incident_pipeline import analyze_incident_case
from ccu_log_diag.model.incidents import IncidentCase


@dataclass
class IncidentCaseOutcome:
    case_id: str
    passed: bool
    expected_findings: list[str]
    actual_findings: list[str]
    matched_findings: list[str]
    missing_findings: list[str]
    unexpected_findings: list[str]
    forbidden_hits: list[str]
    finding_statuses: dict[str, str]
    event_domains: list[str]
    selected_artifacts: int
    parsed_artifacts: int
    artifacts_with_events: int
    parse_success_rate: float
    event_source_coverage: float
    evidence_backed_findings: int
    total_findings: int
    evidence_references: int
    invalid_evidence_references: list[str]
    duration_ms: int
    stage_durations_ms: dict[str, int]
    run_dir: str


@dataclass
class IncidentEvaluationResult:
    evaluation_mode: str
    total: int
    passed: int
    case_pass_rate: float
    expected_finding_recall: float
    false_positive_case_rate: float
    forbidden_hit_count: int
    inconclusive_case_rate: float
    average_parse_success_rate: float
    average_event_source_coverage: float
    evidence_backed_finding_rate: float
    evidence_reference_validity: float
    total_duration_ms: int
    median_case_duration_ms: int
    p95_case_duration_ms: int
    finding_status_counts: dict[str, int]
    domain_case_counts: dict[str, int]
    cases: list[IncidentCaseOutcome]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _percentile(values: list[int], percentile: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def incident_evaluation_markdown(result: IncidentEvaluationResult) -> str:
    lines = [
        "# Incident Analysis Quality Baseline",
        "",
        f"- Evaluation mode: **{result.evaluation_mode}**",
        "- Interpretation: this measures regression stability after each labeled "
        "case selects its registered detector. It is not blind-test accuracy.",
        f"- Cases passed: **{result.passed}/{result.total}** "
        f"({result.case_pass_rate:.1%})",
        f"- Expected-finding recall: **{result.expected_finding_recall:.1%}**",
        f"- Cases with forbidden findings: "
        f"**{result.false_positive_case_rate:.1%}** "
        f"({result.forbidden_hit_count} forbidden hits)",
        f"- Cases containing an inconclusive finding: "
        f"**{result.inconclusive_case_rate:.1%}**",
        f"- Selected-file parse success: "
        f"**{result.average_parse_success_rate:.1%}**",
        f"- Selected sources producing evidence events: "
        f"**{result.average_event_source_coverage:.1%}**",
        f"- Findings backed by event evidence: "
        f"**{result.evidence_backed_finding_rate:.1%}**",
        f"- Evidence-reference validity: "
        f"**{result.evidence_reference_validity:.1%}**",
        f"- Runtime: **{result.total_duration_ms / 1000:.1f}s total**, "
        f"median **{result.median_case_duration_ms / 1000:.1f}s**, "
        f"P95 **{result.p95_case_duration_ms / 1000:.1f}s**",
        "",
        "## Diagnostic coverage",
        "",
    ]
    lines.extend(
        f"- `{domain}`: {count} case(s)"
        for domain, count in sorted(result.domain_case_counts.items())
    )
    lines.extend(["", "## Case outcomes", ""])
    for case in result.cases:
        label = "PASS" if case.passed else "FAIL"
        lines.extend(
            [
                f"### {case.case_id} — {label}",
                "",
                f"- Expected findings matched: "
                f"{len(case.matched_findings)}/{len(case.expected_findings)}",
                f"- Parse success: {case.parsed_artifacts}/"
                f"{case.selected_artifacts} ({case.parse_success_rate:.1%})",
                f"- Evidence-producing sources: {case.artifacts_with_events}/"
                f"{case.parsed_artifacts} ({case.event_source_coverage:.1%})",
                f"- Runtime: {case.duration_ms / 1000:.2f}s",
            ]
        )
        if case.missing_findings:
            lines.append(
                "- Missing expected findings: "
                + ", ".join(f"`{item}`" for item in case.missing_findings)
            )
        if case.forbidden_hits:
            lines.append(
                "- Forbidden findings: "
                + ", ".join(f"`{item}`" for item in case.forbidden_hits)
            )
        if case.unexpected_findings:
            lines.append(
                "- Unlabelled additional findings: "
                + ", ".join(f"`{item}`" for item in case.unexpected_findings)
            )
        if case.invalid_evidence_references:
            lines.append(
                "- Invalid evidence references: "
                + ", ".join(
                    f"`{item}`" for item in case.invalid_evidence_references
                )
            )
        lines.append("")
    return "\n".join(lines)


def _latest_complete_run(root: Path, case_id: str) -> Path:
    candidates = [
        path
        for path in (root / case_id).iterdir()
        if path.is_dir()
        and all(
            (path / name).is_file()
            for name in ("meta.json", "timeline.json", "findings.json")
        )
    ] if (root / case_id).is_dir() else []
    if not candidates:
        raise FileNotFoundError(
            f"No complete cached analysis found for case '{case_id}' in {root}"
        )
    return max(candidates, key=lambda path: path.name)


def evaluate_incident_cases(
    cases_dir: Path,
    out_dir: Path,
    *,
    reuse_from: Path | None = None,
) -> IncidentEvaluationResult:
    case_files = sorted(cases_dir.rglob("case.yaml"))
    if not case_files:
        case_files = sorted(cases_dir.glob("*.yaml"))
    outcomes: list[IncidentCaseOutcome] = []
    for case_file in case_files:
        case = IncidentCase.load(case_file)
        if reuse_from is None:
            result = analyze_incident_case(case_file, out_dir)
            run_dir = result.run_dir
            artifacts = [
                artifact.to_dict() for artifact in result.artifacts
            ]
            event_records = [event.to_dict() for event in result.events]
            finding_records = [
                finding.to_dict() for finding in result.findings
            ]
            stage_durations = dict(result.durations_ms)
        else:
            run_dir = _latest_complete_run(reuse_from, case.id)
            meta = json.loads(
                (run_dir / "meta.json").read_text(encoding="utf-8")
            )
            artifacts = list(meta.get("artifacts", []))
            event_records = json.loads(
                (run_dir / "timeline.json").read_text(encoding="utf-8")
            )
            finding_records = json.loads(
                (run_dir / "findings.json").read_text(encoding="utf-8")
            )
            stage_durations = dict(meta.get("durations_ms", {}))
        actual = [str(finding["rule_id"]) for finding in finding_records]
        expected = list(case.expected_findings)
        matched = [rule_id for rule_id in expected if rule_id in actual]
        missing = [rule_id for rule_id in expected if rule_id not in actual]
        unexpected = [
            rule_id
            for rule_id in actual
            if rule_id not in expected
            and rule_id not in case.forbidden_findings
        ]
        forbidden = [
            rule_id
            for rule_id in actual
            if rule_id in case.forbidden_findings
        ]
        selected = [
            artifact
            for artifact in artifacts
            if artifact.get("parse_status") != "excluded"
        ]
        parsed = [
            artifact
            for artifact in selected
            if artifact.get("parse_status") == "parsed"
        ]
        with_events = [
            artifact
            for artifact in parsed
            if int(artifact.get("event_count", 0)) > 0
        ]
        event_ids = {str(event["id"]) for event in event_records}
        evidence_references = [
            str(event_id)
            for finding in finding_records
            for event_id in [
                *finding.get("evidence_event_ids", []),
                *finding.get("counter_evidence_event_ids", []),
            ]
        ]
        invalid_references = sorted(
            {
                event_id
                for event_id in evidence_references
                if event_id not in event_ids
            }
        )
        domains = sorted(
            {
                str(event.get("domain", "unknown"))
                for event in event_records
                if event.get("domain", "unknown") != "unknown"
            }
        )
        duration = sum(int(value) for value in stage_durations.values())
        outcomes.append(
            IncidentCaseOutcome(
                case_id=case.id,
                passed=not missing and not forbidden and not invalid_references,
                expected_findings=expected,
                actual_findings=actual,
                matched_findings=matched,
                missing_findings=missing,
                unexpected_findings=unexpected,
                forbidden_hits=forbidden,
                finding_statuses={
                    str(finding["rule_id"]): str(finding.get("status", ""))
                    for finding in finding_records
                },
                event_domains=domains,
                selected_artifacts=len(selected),
                parsed_artifacts=len(parsed),
                artifacts_with_events=len(with_events),
                parse_success_rate=(
                    len(parsed) / len(selected) if selected else 0.0
                ),
                event_source_coverage=(
                    len(with_events) / len(parsed) if parsed else 0.0
                ),
                evidence_backed_findings=sum(
                    bool(
                        finding.get("evidence_event_ids")
                        or finding.get("counter_evidence_event_ids")
                    )
                    for finding in finding_records
                ),
                total_findings=len(finding_records),
                evidence_references=len(evidence_references),
                invalid_evidence_references=invalid_references,
                duration_ms=duration,
                stage_durations_ms=stage_durations,
                run_dir=str(run_dir),
            )
        )
    total = len(outcomes)
    total_expected = sum(len(outcome.expected_findings) for outcome in outcomes)
    total_matched = sum(len(outcome.matched_findings) for outcome in outcomes)
    total_findings = sum(outcome.total_findings for outcome in outcomes)
    backed_findings = sum(
        outcome.evidence_backed_findings for outcome in outcomes
    )
    evidence_references = sum(
        outcome.evidence_references for outcome in outcomes
    )
    invalid_references = sum(
        len(outcome.invalid_evidence_references) for outcome in outcomes
    )
    durations = [outcome.duration_ms for outcome in outcomes]
    status_counts = Counter(
        status
        for outcome in outcomes
        for status in outcome.finding_statuses.values()
    )
    domain_counts = Counter(
        domain
        for outcome in outcomes
        for domain in outcome.event_domains
    )
    passed = sum(outcome.passed for outcome in outcomes)
    return IncidentEvaluationResult(
        evaluation_mode=(
            "routed_case_regression"
            if reuse_from is None
            else "cached_routed_case_baseline"
        ),
        total=total,
        passed=passed,
        case_pass_rate=passed / total if total else 0.0,
        expected_finding_recall=(
            total_matched / total_expected if total_expected else 0.0
        ),
        false_positive_case_rate=(
            sum(bool(outcome.forbidden_hits) for outcome in outcomes) / total
            if total
            else 0.0
        ),
        forbidden_hit_count=sum(
            len(outcome.forbidden_hits) for outcome in outcomes
        ),
        inconclusive_case_rate=(
            sum(
                "inconclusive" in outcome.finding_statuses.values()
                for outcome in outcomes
            )
            / total
            if total
            else 0.0
        ),
        average_parse_success_rate=(
            sum(outcome.parse_success_rate for outcome in outcomes) / total
            if total
            else 0.0
        ),
        average_event_source_coverage=(
            sum(outcome.event_source_coverage for outcome in outcomes) / total
            if total
            else 0.0
        ),
        evidence_backed_finding_rate=(
            backed_findings / total_findings if total_findings else 0.0
        ),
        evidence_reference_validity=(
            (evidence_references - invalid_references) / evidence_references
            if evidence_references
            else 0.0
        ),
        total_duration_ms=sum(durations),
        median_case_duration_ms=(
            int(median(durations)) if durations else 0
        ),
        p95_case_duration_ms=_percentile(durations, 0.95),
        finding_status_counts=dict(sorted(status_counts.items())),
        domain_case_counts=dict(sorted(domain_counts.items())),
        cases=outcomes,
    )
