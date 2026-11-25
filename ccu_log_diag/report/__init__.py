from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ccu_log_diag.ingest import LogArtifact
from ccu_log_diag.model.events import Event, Finding, Session


def write_report_md(
    out_path: Path,
    input_name: str,
    sessions: list[Session],
    events: list[Event],
    findings: list[Finding],
    artifacts: list[LogArtifact] | None = None,
) -> None:
    by_id = {e.id: e for e in events}
    lines: list[str] = []
    lines.append(f"# Log Diagnosis Report")
    lines.append("")
    lines.append(f"- Input: `{input_name}`")
    lines.append(f"- Generated (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append(f"- Sessions: {len(sessions)}")
    lines.append(f"- Events: {len(events)}")
    lines.append(f"- Findings: {len(findings)}")
    lines.append(f"- Domains: {', '.join(sorted({e.domain.value for e in events})) or 'none'}")
    lines.append("")

    if artifacts is not None:
        unknown = [artifact for artifact in artifacts if artifact.parse_status != "parsed"]
        lines.append("## Log coverage")
        lines.append("")
        lines.append(f"- Files discovered: {len(artifacts)}")
        lines.append(f"- Files parsed: {len(artifacts) - len(unknown)}")
        lines.append(f"- Unknown or failed files: {len(unknown)}")
        for artifact in unknown[:20]:
            detail = f" ({artifact.error})" if artifact.error else ""
            lines.append(f"  - `{artifact.relative_path}`: {artifact.parse_status}{detail}")
        lines.append("")

    lines.append("## Findings summary")
    lines.append("")
    if not findings:
        lines.append("_No rule hits. Timeline is still available below for manual review._")
    else:
        for f in findings:
            lines.append(f"### [{f.severity.upper()}] {f.title}")
            lines.append("")
            lines.append(f"- Rule: `{f.rule_id}`")
            lines.append(f"- Session: `{f.session_key or 'n/a'}`")
            lines.append(f"- Confidence: {f.confidence}")
            lines.append(f"- Status: {f.status}")
            lines.append(f"- Affected layer: {f.affected_domain.value}")
            lines.append(f"- Root-cause category: `{f.root_cause_category or 'n/a'}`")
            lines.append("")
            lines.append(f.explanation.strip())
            lines.append("")
            if f.suggested_customer_reply:
                lines.append("**Suggested service reply**")
                lines.append("")
                lines.append(f.suggested_customer_reply.strip())
                lines.append("")
            if f.evidence_event_ids:
                lines.append("Evidence:")
                for eid in f.evidence_event_ids:
                    e = by_id.get(eid)
                    if e:
                        location = ""
                        if e.source_location:
                            location = f" ({e.source_location.path}:{e.source_location.line or '?'})"
                        lines.append(f"- `{e.ts_utc}` [{e.type.value}] {e.summary}{location}")
                lines.append("")
            if f.counter_evidence_event_ids:
                lines.append(f"- Counter-evidence: {', '.join(f.counter_evidence_event_ids)}")
            if f.missing_evidence:
                lines.append(f"- Missing evidence: {', '.join(f.missing_evidence)}")
            if f.recommended_actions:
                lines.append("- Recommended actions:")
                for action in f.recommended_actions:
                    lines.append(f"  - {action}")
            lines.append("")

    lines.append("## Sessions")
    lines.append("")
    for s in sessions:
        lines.append(f"### {s.key}")
        lines.append(f"- Connector: {s.connector_id}")
        lines.append(f"- Start: {s.start_ts}")
        lines.append(f"- Stop: {s.stop_ts} (reason={s.stop_reason})")
        lines.append(f"- Linked events: {len(s.event_ids)}")
        lines.append(f"- Association confidence: {s.association_confidence}")
        lines.append(f"- Association evidence: {', '.join(s.association_evidence) or 'none'}")
        lines.append(f"- First anomaly: `{s.first_anomaly_event_id or 'none'}`")
        if s.stages:
            lines.append("- Layer/stage status:")
            for stage, status in s.stages.items():
                lines.append(f"  - {stage}: {status}")
        lines.append("")

    lines.append("## Timeline (selected)")
    lines.append("")
    # keep report readable
    important = {
        "SESSION_START",
        "SESSION_STOP",
        "CABLECHECK_FINISHED",
        "PRECHARGE",
        "CHARGING_COMPLETE",
        "NORMAL_STOP",
        "EMERGENCY_STOP",
        "ALARM",
        "CP_STATE_CHANGE",
        "ISOLATION_STATUS",
        "POWER_REQUEST",
        "PROTOCOL_ERROR",
        "SLAC_STATE",
        "ISO15118_STATE",
        "NETWORK_STATE",
        "MODULE_STATE",
    }
    shown = 0
    for e in events:
        if e.type.value not in important and e.type.value != "METER_VALUES":
            continue
        if e.type.value == "METER_VALUES":
            # sparse meters: every event is ok if few; skip if too many
            continue
        lines.append(f"- `{e.ts_utc}` [{e.source}/{e.type.value}] {e.summary}")
        shown += 1
        if shown >= 200:
            lines.append("")
            lines.append("_Timeline truncated at 200 important events. See timeline.json for full data._")
            break

    # add a few meter snapshots per session
    lines.append("")
    lines.append("## Meter snapshots")
    lines.append("")
    meters = [e for e in events if e.type.value == "METER_VALUES"]
    if not meters:
        lines.append("_No OCPP MeterValues parsed._")
    else:
        step = max(1, len(meters) // 12)
        for e in meters[::step][:15]:
            lines.append(f"- `{e.ts_utc}` txn={e.txn_id} {e.summary}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
