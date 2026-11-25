from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ccu_log_diag.ingest import LogArtifact
from ccu_log_diag.model.events import Event, Finding
from ccu_log_diag.model.incidents import IncidentCase


def write_incident_report_md(
    out_path: Path,
    case: IncidentCase,
    artifacts: list[LogArtifact],
    events: list[Event],
    findings: list[Finding],
) -> None:
    by_id = {event.id: event for event in events}
    lines = [
        f"# Incident Analysis: {case.title}",
        "",
        f"- Case: `{case.id}`",
        f"- Scope: `{case.scope}`",
        f"- Serial number: `{case.source_selection.serial_number}`",
        f"- Window: `{case.window.start.isoformat()}` to `{case.window.end.isoformat()}`",
        f"- Generated: `{datetime.now(timezone.utc).isoformat()}`",
        f"- Selected files: {len(artifacts)}",
        f"- Events: {len(events)}",
        "",
        "## Analyzer findings",
        "",
    ]
    for finding in findings:
        lines.extend(
            [
                f"### [{finding.severity.upper()}] {finding.title}",
                "",
                f"- Rule: `{finding.rule_id}`",
                f"- Status: `{finding.status}`",
                f"- Confidence: `{finding.confidence}`",
                f"- Category: `{finding.root_cause_category or 'unknown'}`",
                "",
                finding.explanation,
                "",
                "Evidence:",
            ]
        )
        for event_id in finding.evidence_event_ids:
            event = by_id.get(event_id)
            if event:
                location = event.source_location
                source = f"{location.path}:{location.line}" if location else event.source
                lines.append(f"- `{event.ts_utc}` {event.summary} (`{source}`)")
        if finding.counter_evidence_event_ids:
            lines.extend(["", "Counter-evidence:"])
            for event_id in finding.counter_evidence_event_ids:
                event = by_id.get(event_id)
                if event:
                    lines.append(f"- `{event.ts_utc}` {event.summary}")
        if finding.missing_evidence:
            lines.extend(["", "Missing proof:"])
            lines.extend(f"- {item}" for item in finding.missing_evidence)
        if finding.recommended_actions:
            lines.extend(["", "Recommended actions:"])
            lines.extend(f"- {item}" for item in finding.recommended_actions)
        lines.append("")

    lines.extend(["## Incident timeline (selected)", ""])
    referenced = {
        event_id
        for finding in findings
        for event_id in finding.evidence_event_ids + finding.counter_evidence_event_ids
    }
    noisy_types = {"NETWORK_STATE", "DNS_RECOVERED"}
    selected_events = [
        event for event in events if event.id in referenced or event.type.value not in noisy_types
    ]
    for event in selected_events:
        location = event.source_location
        source = f"{location.path}:{location.line}" if location else event.source
        lines.append(f"- `{event.ts_utc}` [{event.type.value}] {event.summary} (`{source}`)")
    if len(selected_events) < len(events):
        lines.append("")
        lines.append(
            f"_Suppressed {len(events) - len(selected_events)} repetitive health checks. "
            "See timeline.json for all events._"
        )

    lines.extend(
        [
            "",
            "## Expert ground truth",
            "",
            f"- Symptom: {case.ground_truth.symptom}",
            f"- Assessment: {case.ground_truth.root_cause}",
            f"- Confirmation status: `{case.ground_truth.confirmation_status}`",
            f"- Confidence: `{case.ground_truth.confidence}`",
        ]
    )
    if case.ground_truth.trigger_hypothesis:
        lines.extend(["", "### Trigger hypothesis", "", case.ground_truth.trigger_hypothesis])
    if case.ground_truth.customer_context_needed:
        lines.extend(["", "### Customer context needed", ""])
        lines.extend(f"- {item}" for item in case.ground_truth.customer_context_needed)
    attachments = case.metadata.get("attachments", [])
    if attachments:
        lines.extend(["", "## Attachments", ""])
        for index, attachment in enumerate(attachments, 1):
            lines.append(f"![Case evidence {index}]({attachment})")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
