from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from ccu_log_diag.cases import match_cases
from ccu_log_diag.generalization import build_automatic_triage
from ccu_log_diag.ingest import LogArtifact, discover_log_artifacts, prepare_workspace
from ccu_log_diag.model.events import Event, Finding, Session
from ccu_log_diag.parsers import ParserRegistry
from ccu_log_diag.report import write_report_md
from ccu_log_diag.rules import run_rules
from ccu_log_diag.timeline import build_sessions, build_timeline


@dataclass
class AnalysisResult:
    run_dir: Path
    artifacts: list[LogArtifact]
    events: list[Event]
    sessions: list[Session]
    findings: list[Finding]
    durations_ms: dict[str, int]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def analyze_logs(
    input_path: Path,
    out_dir: Path,
    rules_path: Path,
    *,
    registry: ParserRegistry | None = None,
    cases_path: Path | None = None,
    keep_work: bool = False,
) -> AnalysisResult:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir = out_dir / run_id
    work_dir = run_dir / "_work"
    run_dir.mkdir(parents=True, exist_ok=False)
    durations: dict[str, int] = {}

    started = perf_counter()
    root = prepare_workspace(input_path, work_dir)
    artifacts = discover_log_artifacts(root)
    durations["ingest"] = int((perf_counter() - started) * 1000)

    parser_registry = registry or ParserRegistry.default()
    events: list[Event] = []
    started = perf_counter()
    for artifact in artifacts:
        try:
            selection = parser_registry.select(artifact.path)
            artifact.detection_confidence = selection.confidence
            if selection.parser is None:
                artifact.parse_status = "unknown"
                continue
            artifact.detected_parser = selection.parser.name
            artifact.detected_domain = selection.parser.domain.value
            parsed = selection.parser.parse(artifact.path)
            artifact.event_count = len(parsed)
            artifact.parse_status = "parsed"
            events.extend(parsed)
        except (OSError, UnicodeError, ValueError) as exc:
            artifact.parse_status = "error"
            artifact.error = str(exc)
    durations["parse"] = int((perf_counter() - started) * 1000)

    started = perf_counter()
    timeline = build_timeline(events)
    durations["normalize"] = int((perf_counter() - started) * 1000)

    started = perf_counter()
    sessions = build_sessions(timeline)
    durations["correlate"] = int((perf_counter() - started) * 1000)

    started = perf_counter()
    findings = run_rules(timeline, sessions, rules_path)
    case_findings = match_cases(
        timeline,
        sessions,
        cases_path or Path(__file__).resolve().parents[1] / "knowledge" / "cases.yaml",
    )
    matched_sessions = {finding.session_key for finding in case_findings}
    findings = [
        finding
        for finding in findings
        if not (finding.status == "inconclusive" and finding.session_key in matched_sessions)
    ]
    findings.extend(case_findings)
    durations["diagnose"] = int((perf_counter() - started) * 1000)
    triage = build_automatic_triage(timeline, findings)

    _write_json(run_dir / "timeline.json", [event.to_dict() for event in timeline])
    _write_json(run_dir / "sessions.json", [session.to_dict() for session in sessions])
    _write_json(run_dir / "findings.json", [finding.to_dict() for finding in findings])
    _write_json(run_dir / "triage.json", triage.to_dict())
    _write_json(
        run_dir / "meta.json",
        {
            "input": str(input_path),
            "run_id": run_id,
            "artifacts": [artifact.to_dict() for artifact in artifacts],
            "event_count": len(timeline),
            "session_count": len(sessions),
            "finding_count": len(findings),
            "domains": sorted({event.domain.value for event in timeline}),
            "durations_ms": durations,
        },
    )
    write_report_md(
        run_dir / "report.md",
        str(input_path),
        sessions,
        timeline,
        findings,
        artifacts=artifacts,
    )

    if work_dir.exists() and not keep_work:
        shutil.rmtree(work_dir, ignore_errors=True)
    return AnalysisResult(run_dir, artifacts, timeline, sessions, findings, durations)
