from __future__ import annotations

import json
from pathlib import Path

import yaml

from ccu_log_diag.generalization import (
    build_automatic_triage,
    evaluate_frozen_blind_batch,
)
from ccu_log_diag.model.events import Domain, Event, EventType, Finding


def _event(
    event_id: str,
    timestamp: str,
    event_type: EventType,
    domain: Domain,
) -> Event:
    return Event(
        id=event_id,
        ts_utc=timestamp,
        source="fixture",
        type=event_type,
        summary=event_type.value,
        domain=domain,
    )


def test_automatic_triage_clusters_windows_and_consolidates_findings() -> None:
    events = [
        _event("e1", "2026-01-01T10:00:00Z", EventType.CONNECTIVITY_LOST, Domain.NETWORK),
        _event("e2", "2026-01-01T10:00:20Z", EventType.PROTOCOL_ERROR, Domain.OCPP),
        _event("e3", "2026-01-01T11:00:00Z", EventType.ALARM, Domain.POWER),
    ]
    findings = [
        Finding(
            rule_id="backend_path_failure",
            severity="high",
            title="Backend path failed",
            explanation="",
            evidence_event_ids=["e1", "e2"],
            confidence="high",
            status="confirmed",
            root_cause_category="external_network_or_backend_path",
            affected_domain=Domain.NETWORK,
        ),
        Finding(
            rule_id="backend_path_failure",
            severity="high",
            title="Backend path failed again",
            explanation="",
            evidence_event_ids=["e2"],
            confidence="high",
            status="confirmed",
            root_cause_category="external_network_or_backend_path",
            affected_domain=Domain.NETWORK,
        ),
        Finding(
            rule_id="inconclusive",
            severity="info",
            title="Unknown",
            explanation="",
            status="inconclusive",
        ),
    ]

    triage = build_automatic_triage(events, findings)

    assert len(triage.incident_windows) == 2
    assert triage.incident_windows[0].domains == ["network", "ocpp"]
    assert triage.domain_ranking[0]["domain"] == "network"
    assert triage.root_cause_ranking[0].occurrences == 2
    assert triage.consolidated_inconclusive_count == 1


def test_frozen_blind_evaluation_scores_top_k_without_case_detector(
    tmp_path: Path,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    event = _event(
        "auth-1",
        "2026-01-01T10:00:00Z",
        EventType.AUTHORIZATION,
        Domain.OCPP,
    )
    finding = Finding(
        rule_id="backend_blocked_vid",
        severity="high",
        title="VID blocked",
        explanation="",
        evidence_event_ids=[event.id],
        confidence="high",
        status="confirmed",
        root_cause_category="backend_authorization_policy",
        affected_domain=Domain.OCPP,
    )
    (run / "timeline.json").write_text(
        json.dumps([event.to_dict()]),
        encoding="utf-8",
    )
    (run / "findings.json").write_text(
        json.dumps([finding.to_dict()]),
        encoding="utf-8",
    )
    frozen = tmp_path / "frozen.yaml"
    frozen.write_text(
        yaml.safe_dump(
            {
                "batch_id": "batch",
                "cases": [{"id": "blind-001", "run": str(run)}],
            }
        ),
        encoding="utf-8",
    )
    labels = tmp_path / "labels.yaml"
    labels.write_text(
        yaml.safe_dump(
            {
                "cases": {
                    "blind-001": {
                        "status": "revealed",
                        "affected_domains": ["ocpp"],
                        "root_cause_category": "backend_authorization_policy",
                        "expected_findings": ["backend_blocked_vid"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = evaluate_frozen_blind_batch(frozen, labels)

    assert result["domain_top1_accuracy"] == 1.0
    assert result["root_cause_top3_accuracy"] == 1.0
    assert result["expected_finding_recall"] == 1.0
