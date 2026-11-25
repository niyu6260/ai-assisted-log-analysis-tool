from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ccu_log_diag.model.events import Domain, Event, Finding, Session


def load_cases(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    cases = data.get("cases", []) if isinstance(data, dict) else []
    return cases if isinstance(cases, list) else []


def match_cases(
    events: list[Event],
    sessions: list[Session],
    path: Path,
) -> list[Finding]:
    """Match confirmed cases by structured event features, never raw similarity alone."""

    by_id = {event.id: event for event in events}
    targets = sessions or [Session(key="global", event_ids=list(by_id))]
    findings: list[Finding] = []
    for session in targets:
        scoped = [by_id[event_id] for event_id in session.event_ids if event_id in by_id]
        event_types = {event.type.value for event in scoped}
        domains = {event.domain.value for event in scoped}
        text = "\n".join(f"{event.summary}\n{event.raw}" for event in scoped).lower()
        for case in load_cases(path):
            signature = case.get("signature", {})
            required_types = set(signature.get("event_types", []))
            required_domains = set(signature.get("domains", []))
            required_text = [str(token).lower() for token in signature.get("text_any", [])]
            if required_types and not required_types.issubset(event_types):
                continue
            if required_domains and not required_domains.issubset(domains):
                continue
            if required_text and not any(token in text for token in required_text):
                continue
            evidence = [
                event.id
                for event in scoped
                if event.type.value in required_types
                or any(token in (event.summary + event.raw).lower() for token in required_text)
            ][:8]
            try:
                affected_domain = Domain(case.get("affected_domain", "unknown"))
            except ValueError:
                affected_domain = Domain.UNKNOWN
            findings.append(
                Finding(
                    rule_id=f"case:{case.get('id', 'unknown')}",
                    severity=case.get("severity", "info"),
                    title=f"Known case match: {case.get('title', case.get('id', 'unknown'))}",
                    explanation=case.get("root_cause", ""),
                    evidence_event_ids=evidence,
                    suggested_customer_reply=case.get("suggested_customer_reply", ""),
                    session_key=None if session.key == "global" else session.key,
                    confidence=case.get("confidence", "medium"),
                    status="case_match",
                    root_cause_category=case.get("category", "known_case"),
                    affected_domain=affected_domain,
                    recommended_actions=case.get("recommended_actions", []),
                )
            )
    return findings
