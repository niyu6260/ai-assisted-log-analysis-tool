from __future__ import annotations

from pathlib import Path

import pytest

from ccu_log_diag.cases import match_cases
from ccu_log_diag.evaluation import evaluate_manifest
from ccu_log_diag.model.events import Domain, Event, EventType
from ccu_log_diag.parsers import ParserRegistry
from ccu_log_diag.pipeline import analyze_logs
from ccu_log_diag.rules import run_rules
from ccu_log_diag.timeline import build_sessions, build_timeline


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "pack_v1.yaml"


@pytest.mark.parametrize(
    ("filename", "line", "domain", "event_type"),
    [
        ("cp.log", "[2026-01-01T10:00:00Z] CP signal fault connectorId=1", Domain.CP, EventType.PROTOCOL_ERROR),
        ("slac.log", "[2026-01-01T10:00:01Z] SLAC match failed PEV_MAC=00:11:22:33:44:55", Domain.PLC_SLAC, EventType.PROTOCOL_ERROR),
        ("iso15118.log", "[2026-01-01T10:00:02Z] V2G TLS handshake fail", Domain.ISO15118, EventType.PROTOCOL_ERROR),
        ("pcu_1.log", "[2026-01-01T10:00:03Z] PCU overvoltage alarm gun=1", Domain.POWER, EventType.ALARM),
        ("network.log", "[2026-01-01T10:00:04Z] DNS resolve timeout", Domain.NETWORK, EventType.PROTOCOL_ERROR),
    ],
)
def test_registry_detects_and_parses_domain(
    tmp_path: Path,
    filename: str,
    line: str,
    domain: Domain,
    event_type: EventType,
) -> None:
    path = tmp_path / filename
    path.write_text(line + "\n", encoding="utf-8")

    selection = ParserRegistry.default().select(path)

    assert selection.parser is not None
    assert selection.parser.domain == domain
    events = selection.parser.parse(path)
    assert events[0].type == event_type
    assert events[0].source_location is not None
    assert events[0].source_location.line == 1


def test_cross_domain_events_are_correlated_by_connector_and_time() -> None:
    events = build_timeline(
        [
            Event(
                id="start",
                ts_utc="2026-01-01T10:00:00Z",
                source="ocpp",
                type=EventType.SESSION_START,
                summary="start",
                connector_id=1,
                txn_id=42,
                domain=Domain.OCPP,
            ),
            Event(
                id="slac",
                ts_utc="2026-01-01T10:00:01Z",
                source="plc_slac",
                type=EventType.SLAC_STATE,
                summary="matched",
                connector_id=1,
                domain=Domain.PLC_SLAC,
            ),
            Event(
                id="network",
                ts_utc="2026-01-01T10:00:02Z",
                source="network",
                type=EventType.PROTOCOL_ERROR,
                summary="DNS failure",
                connector_id=1,
                domain=Domain.NETWORK,
            ),
        ]
    )

    sessions = build_sessions(events)

    assert len(sessions) == 1
    assert set(sessions[0].event_ids) == {"start", "slac", "network"}
    assert sessions[0].stages["plc_slac"] == "observed"
    assert sessions[0].stages["network"] == "failed"
    assert sessions[0].first_anomaly_event_id == "network"
    assert sessions[0].association_confidence == "high"


def test_domain_detector_emits_evidence_based_finding() -> None:
    event = Event(
        id="dns",
        ts_utc="2026-01-01T10:00:00Z",
        source="network",
        type=EventType.PROTOCOL_ERROR,
        summary="DNS failure",
        domain=Domain.NETWORK,
    )
    timeline = build_timeline([event])
    sessions = build_sessions(timeline)

    findings = run_rules(timeline, sessions, RULES)

    finding = next(item for item in findings if item.rule_id == "network_connectivity_failure")
    assert finding.affected_domain == Domain.NETWORK
    assert finding.evidence_event_ids == ["dns"]
    assert finding.root_cause_category == "network_connectivity"


def test_sessions_split_concurrent_guns_without_ocpp_transaction() -> None:
    events = build_timeline(
        [
            Event("g1", "2026-01-01T10:00:00Z", "cp", EventType.CP_STATE_CHANGE, "CP B", gun_id=1, domain=Domain.CP),
            Event("g2", "2026-01-01T10:00:01Z", "cp", EventType.CP_STATE_CHANGE, "CP B", gun_id=2, domain=Domain.CP),
            Event("g1-slac", "2026-01-01T10:00:02Z", "plc_slac", EventType.SLAC_STATE, "matched", gun_id=1, domain=Domain.PLC_SLAC),
        ]
    )

    sessions = build_sessions(events)

    assert len(sessions) == 2
    assert {session.gun_id for session in sessions} == {1, 2}
    gun_one = next(session for session in sessions if session.gun_id == 1)
    assert set(gun_one.event_ids) == {"g1", "g1-slac"}


def test_pipeline_records_unknown_files_and_outputs_report(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "network.log").write_text(
        "[2026-01-01T10:00:00Z] TLS handshake error certificate expired\n",
        encoding="utf-8",
    )
    (logs / "mystery.log").write_text("unrecognized subsystem output\n", encoding="utf-8")

    result = analyze_logs(logs, tmp_path / "reports", RULES)

    assert (result.run_dir / "report.md").exists()
    assert (result.run_dir / "timeline.json").exists()
    assert any(item.rule_id == "network_connectivity_failure" for item in result.findings)
    assert any(item.parse_status == "unknown" for item in result.artifacts)
    report = (result.run_dir / "report.md").read_text(encoding="utf-8")
    assert "Log coverage" in report
    assert "Network connectivity failure" in report


def test_labeled_case_signature_matches_confirmed_root_cause() -> None:
    events = build_timeline(
        [
            Event("pre", "2026-01-01T10:00:00Z", "vccu", EventType.PRECHARGE, "PreCharge", domain=Domain.ISO15118),
            Event("alarm", "2026-01-01T10:00:01Z", "vccu", EventType.ALARM, "Voltage difference alarm", domain=Domain.ISO15118),
            Event("stop", "2026-01-01T10:00:02Z", "vccu", EventType.EMERGENCY_STOP, "Emergency stop", domain=Domain.ISO15118),
        ]
    )
    sessions = build_sessions(events)

    findings = match_cases(events, sessions, ROOT / "knowledge" / "cases.yaml")

    assert findings[0].rule_id == "case:precharge_voltage_difference"
    assert findings[0].status == "case_match"


def test_labeled_manifest_reports_coverage_metrics(tmp_path: Path) -> None:
    result = evaluate_manifest(
        ROOT / "tests" / "fixtures" / "labeled" / "manifest.yaml",
        RULES,
        tmp_path / "evaluation",
    )

    assert result.passed == result.total == 2
    assert result.top1_accuracy == 1.0
    assert result.false_positive_rate == 0.0
    assert result.average_parse_rate == 1.0
