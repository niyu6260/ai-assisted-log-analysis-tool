from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from ccu_log_diag.ingest import LogArtifact, discover_log_artifacts, prepare_workspace
from ccu_log_diag.model.events import Event, Finding
from ccu_log_diag.model.incidents import IncidentCase
from ccu_log_diag.parsers.incident_parser import parse_incident_file
from ccu_log_diag.report.incident_report import write_incident_report_md
from ccu_log_diag.rules.incident_detectors import detect_incident
from ccu_log_diag.timeline import build_timeline


@dataclass
class IncidentAnalysisResult:
    run_dir: Path
    case: IncidentCase
    artifacts: list[LogArtifact]
    events: list[Event]
    findings: list[Finding]
    durations_ms: dict[str, int]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def analyze_incident_case(
    case_path: Path,
    out_dir: Path,
    *,
    keep_work: bool = False,
) -> IncidentAnalysisResult:
    case = IncidentCase.load(case_path)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir = out_dir / case.id / run_id
    work_dir = run_dir / "_work"
    run_dir.mkdir(parents=True, exist_ok=False)
    durations: dict[str, int] = {}

    started = perf_counter()
    root = prepare_workspace(case.input_path, work_dir)
    artifacts = discover_log_artifacts(root)
    selected = [artifact for artifact in artifacts if case.source_selection.accepts(artifact.path)]
    for artifact in artifacts:
        if artifact not in selected:
            artifact.parse_status = "excluded"
    durations["ingest"] = int((perf_counter() - started) * 1000)

    started = perf_counter()
    events: list[Event] = []
    for artifact in selected:
        try:
            parsed = parse_incident_file(
                artifact.path,
                year=case.window.start.year,
                charger_id=case.source_selection.serial_number,
                utc_offset_hours=case.source_selection.utc_offset_hours(
                    artifact.path
                ),
                start_utc=case.window.start,
                end_utc=case.window.end,
            )
            in_window = [event for event in parsed if case.window.contains(event.ts_utc)]
            artifact.detected_parser = "sungrow_incident"
            lower_name = artifact.path.name.lower()
            artifact.detected_domain = (
                "ocpp"
                if "ocpp" in lower_name
                else "system"
                if "mainprocess" in lower_name
                else "iso15118"
                if any(token in lower_name for token in ("ccu_ethernet", "fault_state", "charging"))
                else "network"
            )
            artifact.detection_confidence = 1.0
            artifact.parse_status = "parsed"
            artifact.event_count = len(in_window)
            events.extend(in_window)
        except (OSError, UnicodeError, ValueError) as exc:
            artifact.parse_status = "error"
            artifact.error = str(exc)
    timeline = build_timeline(events)
    durations["parse"] = int((perf_counter() - started) * 1000)

    started = perf_counter()
    findings = detect_incident(case, timeline)
    durations["diagnose"] = int((perf_counter() - started) * 1000)

    _write_json(
        run_dir / "incident.json",
        {
            "id": case.id,
            "title": case.title,
            "scope": case.scope,
            "start": case.window.start.isoformat(),
            "end": case.window.end.isoformat(),
            "serial_number": case.source_selection.serial_number,
            "ground_truth_status": case.ground_truth.confirmation_status,
        },
    )
    _write_json(run_dir / "timeline.json", [event.to_dict() for event in timeline])
    _write_json(run_dir / "findings.json", [finding.to_dict() for finding in findings])
    _write_json(
        run_dir / "meta.json",
        {
            "case": case.id,
            "input": str(case.input_path),
            "selected_files": [artifact.relative_path for artifact in selected],
            "artifacts": [artifact.to_dict() for artifact in artifacts],
            "event_count": len(timeline),
            "finding_count": len(findings),
            "durations_ms": durations,
        },
    )
    write_incident_report_md(run_dir / "report.md", case, selected, timeline, findings)

    if work_dir.exists() and not keep_work:
        shutil.rmtree(work_dir, ignore_errors=True)
    return IncidentAnalysisResult(run_dir, case, artifacts, timeline, findings, durations)
