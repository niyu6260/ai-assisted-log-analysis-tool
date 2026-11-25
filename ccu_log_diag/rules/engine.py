from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ccu_log_diag.model.events import Domain, Event, Finding, Session
from ccu_log_diag.rules.detectors import DETECTORS, DetectorContext


def load_rules(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = data.get("rules", []) if isinstance(data, dict) else []
    if not isinstance(rules, list):
        raise ValueError("Rules file must contain a 'rules' list")
    return rules


def _events_by_id(events: list[Event]) -> dict[str, Event]:
    return {e.id: e for e in events}


def _session_events(session: Session, by_id: dict[str, Event]) -> list[Event]:
    return [by_id[i] for i in session.event_ids if i in by_id]


def run_rules(events: list[Event], sessions: list[Session], rules_path: Path) -> list[Finding]:
    rules = load_rules(rules_path)
    by_id = _events_by_id(events)
    findings: list[Finding] = []
    targets: list[tuple[Session | None, list[Event]]]
    if sessions:
        targets = [(session, _session_events(session, by_id)) for session in sessions]
    else:
        targets = [(None, events)]

    for session, scoped_events in targets:
        scoped_findings: list[Finding] = []
        context = DetectorContext(scoped_events, session)
        for rule in rules:
            rule_id = rule.get("id")
            detect = DETECTORS.get(rule_id)
            if detect is None or rule.get("enabled", True) is False:
                continue
            detection = detect(context, rule)
            if not detection.hit:
                continue
            scoped_findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=rule.get("severity", "info"),
                    title=rule.get("title", rule_id),
                    explanation=rule.get("explanation", ""),
                    evidence_event_ids=detection.evidence,
                    counter_evidence_event_ids=detection.counter_evidence,
                    suggested_customer_reply=rule.get("suggested_customer_reply", ""),
                    session_key=session.key if session else None,
                    confidence=rule.get("confidence", "medium"),
                    status=rule.get("status", "confirmed"),
                    root_cause_category=detection.root_cause_category,
                    affected_domain=detection.affected_domain,
                    missing_evidence=detection.missing_evidence,
                    recommended_actions=detection.recommended_actions,
                )
            )
        if not scoped_findings:
            present_domains = {event.domain for event in scoped_events if event.domain != Domain.UNKNOWN}
            missing = [
                domain.value
                for domain in (
                    Domain.CP,
                    Domain.PLC_SLAC,
                    Domain.ISO15118,
                    Domain.POWER,
                    Domain.OCPP,
                    Domain.NETWORK,
                )
                if domain not in present_domains
            ]
            anomaly = session.first_anomaly_event_id if session else None
            scoped_findings.append(
                Finding(
                    rule_id="inconclusive",
                    severity="info",
                    title="No confirmed root cause",
                    explanation="The available evidence does not match a confirmed diagnostic rule.",
                    evidence_event_ids=[anomaly] if anomaly else [],
                    session_key=session.key if session else None,
                    confidence="low",
                    status="inconclusive",
                    root_cause_category="unknown",
                    affected_domain=Domain.UNKNOWN,
                    missing_evidence=missing,
                    recommended_actions=["Collect the missing domain logs and review the first abnormal transition."],
                )
            )
        findings.extend(scoped_findings)
    return findings
