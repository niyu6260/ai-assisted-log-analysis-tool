from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from ccu_log_diag.model.events import Domain, Event, EventType, Finding


ANOMALY_TYPES = {
    EventType.ALARM,
    EventType.EMERGENCY_STOP,
    EventType.ERROR_CODE,
    EventType.CONNECTIVITY_LOST,
    EventType.PROTOCOL_ERROR,
    EventType.AUTHORIZATION,
    EventType.MODULE_STATE,
}
TYPE_WEIGHTS = {
    EventType.EMERGENCY_STOP: 6,
    EventType.ALARM: 5,
    EventType.ERROR_CODE: 5,
    EventType.CONNECTIVITY_LOST: 4,
    EventType.PROTOCOL_ERROR: 4,
    EventType.AUTHORIZATION: 3,
    EventType.MODULE_STATE: 2,
}
SEVERITY_WEIGHTS = {"critical": 8, "high": 6, "medium": 4, "low": 2, "info": 1}
STATUS_WEIGHTS = {"confirmed": 4, "probable": 2, "case_match": 2, "inconclusive": 0}


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class IncidentCandidate:
    start: str
    end: str
    score: int
    event_count: int
    domains: list[str]
    event_types: dict[str, int]
    evidence_event_ids: list[str]


@dataclass
class FindingCandidate:
    rule_id: str
    root_cause_category: str
    affected_domain: str
    score: int
    occurrences: int
    status: str
    confidence: str
    first_seen: str
    last_seen: str
    evidence_event_ids: list[str]


@dataclass
class AutomaticTriage:
    incident_windows: list[IncidentCandidate]
    domain_ranking: list[dict[str, Any]]
    root_cause_ranking: list[FindingCandidate]
    consolidated_inconclusive_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_incident_windows(
    events: Iterable[Event],
    *,
    gap_seconds: int = 300,
    limit: int = 10,
) -> list[IncidentCandidate]:
    anomalies = [
        event
        for event in events
        if event.type in ANOMALY_TYPES and _parse_ts(event.ts_utc) is not None
    ]
    anomalies.sort(key=lambda event: (_parse_ts(event.ts_utc), event.id))
    clusters: list[list[Event]] = []
    for event in anomalies:
        if not clusters:
            clusters.append([event])
            continue
        previous = _parse_ts(clusters[-1][-1].ts_utc)
        current = _parse_ts(event.ts_utc)
        if previous and current and (current - previous).total_seconds() <= gap_seconds:
            clusters[-1].append(event)
        else:
            clusters.append([event])

    candidates: list[IncidentCandidate] = []
    for cluster in clusters:
        domains = sorted(
            {
                event.domain.value
                for event in cluster
                if event.domain != Domain.UNKNOWN
            }
        )
        type_counts = Counter(event.type.value for event in cluster)
        score = sum(TYPE_WEIGHTS.get(event.type, 1) for event in cluster)
        score += max(0, len(domains) - 1) * 3
        candidates.append(
            IncidentCandidate(
                start=cluster[0].ts_utc,
                end=cluster[-1].ts_utc,
                score=score,
                event_count=len(cluster),
                domains=domains,
                event_types=dict(sorted(type_counts.items())),
                evidence_event_ids=[event.id for event in cluster[:50]],
            )
        )
    return sorted(
        candidates,
        key=lambda item: (item.score, item.event_count, item.start),
        reverse=True,
    )[:limit]


def rank_findings(
    findings: Iterable[Finding],
    events: Iterable[Event],
    *,
    limit: int = 10,
) -> tuple[list[FindingCandidate], int]:
    event_by_id = {event.id: event for event in events}
    grouped: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
    inconclusive = 0
    for finding in findings:
        if finding.status == "inconclusive" or finding.rule_id == "inconclusive":
            inconclusive += 1
            continue
        key = (
            finding.rule_id,
            finding.root_cause_category or "unknown",
            finding.affected_domain.value,
        )
        grouped[key].append(finding)

    candidates: list[FindingCandidate] = []
    for (rule_id, category, domain), items in grouped.items():
        evidence_ids = list(
            dict.fromkeys(
                event_id
                for item in items
                for event_id in (
                    item.evidence_event_ids + item.counter_evidence_event_ids
                )
            )
        )
        timestamps = sorted(
            event_by_id[event_id].ts_utc
            for event_id in evidence_ids
            if event_id in event_by_id and event_by_id[event_id].ts_utc
        )
        score = max(
            SEVERITY_WEIGHTS.get(item.severity, 1)
            + STATUS_WEIGHTS.get(item.status, 0)
            + min(len(item.evidence_event_ids), 5)
            for item in items
        )
        score += min(len(items) - 1, 5)
        best = max(
            items,
            key=lambda item: (
                STATUS_WEIGHTS.get(item.status, 0),
                SEVERITY_WEIGHTS.get(item.severity, 1),
                len(item.evidence_event_ids),
            ),
        )
        candidates.append(
            FindingCandidate(
                rule_id=rule_id,
                root_cause_category=category,
                affected_domain=domain,
                score=score,
                occurrences=len(items),
                status=best.status,
                confidence=best.confidence,
                first_seen=timestamps[0] if timestamps else "",
                last_seen=timestamps[-1] if timestamps else "",
                evidence_event_ids=evidence_ids[:50],
            )
        )
    return (
        sorted(
            candidates,
            key=lambda item: (item.score, item.occurrences, item.rule_id),
            reverse=True,
        )[:limit],
        inconclusive,
    )


def build_automatic_triage(
    events: list[Event],
    findings: list[Finding],
) -> AutomaticTriage:
    windows = detect_incident_windows(events)
    root_causes, inconclusive = rank_findings(findings, events)
    domain_scores: Counter[str] = Counter()
    for candidate in root_causes:
        if candidate.affected_domain != Domain.UNKNOWN.value:
            domain_scores[candidate.affected_domain] += candidate.score
    if not domain_scores:
        for window in windows:
            for domain in window.domains:
                domain_scores[domain] += window.score
    ranking = [
        {"domain": domain, "score": score}
        for domain, score in domain_scores.most_common()
    ]
    return AutomaticTriage(
        incident_windows=windows,
        domain_ranking=ranking,
        root_cause_ranking=root_causes,
        consolidated_inconclusive_count=inconclusive,
    )


def load_analysis_run(run_dir: Path) -> tuple[list[Event], list[Finding]]:
    event_data = json.loads((run_dir / "timeline.json").read_text(encoding="utf-8"))
    finding_data = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    events = [
        Event(
            id=item["id"],
            ts_utc=item.get("ts_utc", ""),
            source=item.get("source", ""),
            type=EventType(item["type"]),
            summary=item.get("summary", ""),
            raw=item.get("raw", ""),
            connector_id=item.get("connector_id"),
            gun_id=item.get("gun_id"),
            txn_id=item.get("txn_id"),
            attrs=item.get("attrs", {}),
            domain=Domain(item.get("domain", "unknown")),
            component=item.get("component", ""),
            original_timestamp=item.get("original_timestamp", ""),
            charger_id=item.get("charger_id"),
            terminal_id=item.get("terminal_id"),
            session_id=item.get("session_id"),
            correlation_ids=item.get("correlation_ids", {}),
        )
        for item in event_data
    ]
    findings = [
        Finding(
            rule_id=item["rule_id"],
            severity=item.get("severity", "info"),
            title=item.get("title", ""),
            explanation=item.get("explanation", ""),
            evidence_event_ids=item.get("evidence_event_ids", []),
            suggested_customer_reply=item.get("suggested_customer_reply", ""),
            session_key=item.get("session_key"),
            confidence=item.get("confidence", "low"),
            status=item.get("status", "inconclusive"),
            root_cause_category=item.get("root_cause_category", ""),
            affected_domain=Domain(item.get("affected_domain", "unknown")),
            counter_evidence_event_ids=item.get(
                "counter_evidence_event_ids", []
            ),
            missing_evidence=item.get("missing_evidence", []),
            recommended_actions=item.get("recommended_actions", []),
        )
        for item in finding_data
    ]
    return events, findings


def evaluate_frozen_blind_batch(
    frozen_path: Path,
    labels_path: Path,
) -> dict[str, Any]:
    frozen = yaml.safe_load(frozen_path.read_text(encoding="utf-8"))
    labels = yaml.safe_load(labels_path.read_text(encoding="utf-8"))
    labels_by_id = labels.get("cases", {})
    outcomes: list[dict[str, Any]] = []
    for frozen_case in frozen.get("cases", []):
        case_id = frozen_case["id"]
        label = labels_by_id.get(case_id, {})
        if label.get("status") != "revealed":
            continue
        events, findings = load_analysis_run(Path(frozen_case["run"]))
        triage = build_automatic_triage(events, findings)
        expected_domains = set(label.get("affected_domains", []))
        expected_categories = set(
            label.get("root_cause_categories")
            or [label.get("root_cause_category", "unresolved")]
        )
        expected_findings = set(label.get("expected_findings", []))
        predicted_domains = [
            item["domain"] for item in triage.domain_ranking[:3]
        ]
        predicted_categories = [
            item.root_cause_category
            for item in triage.root_cause_ranking[:3]
        ]
        predicted_rules = {
            item.rule_id for item in triage.root_cause_ranking
        }
        outcomes.append(
            {
                "case_id": case_id,
                "domain_top1_match": bool(
                    predicted_domains
                    and predicted_domains[0] in expected_domains
                ),
                "domain_top3_match": bool(
                    expected_domains.intersection(predicted_domains)
                ),
                "root_cause_top3_match": bool(
                    expected_categories.intersection(predicted_categories)
                ),
                "expected_findings_matched": len(
                    expected_findings.intersection(predicted_rules)
                ),
                "expected_findings_total": len(expected_findings),
                "predicted_domains": predicted_domains,
                "predicted_root_cause_categories": predicted_categories,
                "inconclusive_count": (
                    triage.consolidated_inconclusive_count
                ),
            }
        )
    total = len(outcomes)
    finding_total = sum(
        item["expected_findings_total"] for item in outcomes
    )
    finding_matched = sum(
        item["expected_findings_matched"] for item in outcomes
    )
    return {
        "batch_id": frozen.get("batch_id"),
        "revealed_cases": total,
        "total_cases": len(frozen.get("cases", [])),
        "domain_top1_accuracy": (
            sum(item["domain_top1_match"] for item in outcomes) / total
            if total
            else 0.0
        ),
        "domain_top3_accuracy": (
            sum(item["domain_top3_match"] for item in outcomes) / total
            if total
            else 0.0
        ),
        "root_cause_top3_accuracy": (
            sum(item["root_cause_top3_match"] for item in outcomes) / total
            if total
            else 0.0
        ),
        "expected_finding_recall": (
            finding_matched / finding_total if finding_total else 0.0
        ),
        "cases": outcomes,
    }


def blind_evaluation_markdown(result: dict[str, Any]) -> str:
    lines = [
        f"# Blind Generalization Baseline: {result.get('batch_id', 'unknown')}",
        "",
        f"- Revealed labels: {result['revealed_cases']}/{result['total_cases']}",
        f"- Domain Top-1 accuracy: {result['domain_top1_accuracy']:.1%}",
        f"- Domain Top-3 accuracy: {result['domain_top3_accuracy']:.1%}",
        f"- Root-cause Top-3 accuracy: {result['root_cause_top3_accuracy']:.1%}",
        f"- Expected-finding recall: {result['expected_finding_recall']:.1%}",
        "",
        "## Cases",
        "",
    ]
    for item in result["cases"]:
        lines.extend(
            [
                f"### {item['case_id']}",
                "",
                f"- Domain Top-1 match: {item['domain_top1_match']}",
                f"- Domain Top-3 match: {item['domain_top3_match']}",
                f"- Root-cause Top-3 match: {item['root_cause_top3_match']}",
                "- Predicted domains: "
                + (", ".join(item["predicted_domains"]) or "none"),
                "- Predicted root-cause categories: "
                + (
                    ", ".join(item["predicted_root_cause_categories"])
                    or "none"
                ),
                f"- Consolidated inconclusive sessions: "
                f"{item['inconclusive_count']}",
                "",
            ]
        )
    return "\n".join(lines)
