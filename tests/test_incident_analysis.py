from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

from ccu_log_diag.error_catalog import load_error_catalog
from ccu_log_diag.ingest import prepare_workspace
from ccu_log_diag.incident_evaluation import (
    evaluate_incident_cases,
    incident_evaluation_markdown,
)
from ccu_log_diag.incident_pipeline import analyze_incident_case
from ccu_log_diag.model.events import EventType
from ccu_log_diag.model.incidents import IncidentCase


ROOT = Path(__file__).resolve().parents[1]
CASE_FILE = ROOT / "tests" / "fixtures" / "incidents" / "solaredge_conflict.yaml"
S3_CASE_FILE = ROOT / "tests" / "fixtures" / "incidents" / "s3_estop.yaml"
S20_CASE_FILE = ROOT / "tests" / "fixtures" / "incidents" / "s20_timeout.yaml"
MAINTENANCE_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "maintenance_backend.yaml"
)
MERCEDES_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "mercedes_invalid_voltage.yaml"
)
BMW_I3_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "bmw_i3.yaml"
)
FAULT_MODE_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "fault_mode_lem2.yaml"
)
LEM_HTTP_HANG_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "lem_http_hang.yaml"
)
DUAL_TERMINAL_L20_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "dual_terminal_l20.yaml"
)
PLUG_AND_PLAY_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "plug_and_play_idtag.yaml"
)
TESLA_PRECHARGE_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "tesla_precharge.yaml"
)
CURRENT_DEMAND_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "current_demand_overvoltage.yaml"
)
EMS_LOW_POWER_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "ems_low_power.yaml"
)
S25_RAMP_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "s25_ramp.yaml"
)
ORA_ZERO_TARGET_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "ora_zero_target.yaml"
)
C36_ESTOP_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "c36_estop.yaml"
)
C36_SPONTANEOUS_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "c36_spontaneous.yaml"
)
PM1_FAULT_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "pm1_fault.yaml"
)
SIM_CARD_PATH_CASE_FILE = (
    ROOT / "tests" / "fixtures" / "incidents" / "sim_card_path.yaml"
)


def test_source_selection_uses_sn_v_and_explicit_global_exception() -> None:
    case = IncidentCase.load(CASE_FILE)
    selection = case.source_selection

    assert selection.accepts(Path("A24C0215369Vrouter_network.log"))
    assert selection.accepts(Path("A24C0215369Vrouter_network_0.log"))
    assert selection.accepts(Path("dlm-network.log"))
    assert not selection.accepts(Path("Vrouter_network.log"))
    assert not selection.accepts(Path("A24C0215369router_network.log"))


def test_non_charging_incident_produces_probable_conflict_finding(tmp_path: Path) -> None:
    result = analyze_incident_case(CASE_FILE, tmp_path / "reports")

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "eth1_network_manager_conflict_probable"
    assert finding.status == "probable"
    assert finding.confidence == "medium"
    assert finding.counter_evidence_event_ids
    assert EventType.NETWORK_MANAGER_START in {event.type for event in result.events}
    assert EventType.NETWORK_MANAGER_RELEASE in {event.type for event in result.events}
    assert EventType.WEBSOCKET_CONNECTED in {event.type for event in result.events}
    assert EventType.OCPP_BOOT_ACCEPTED in {event.type for event in result.events}
    assert (result.run_dir / "incident.json").exists()
    report = (result.run_dir / "report.md").read_text(encoding="utf-8")
    assert "Probable eth1 network-manager ownership conflict" in report
    assert "Vehicle-side emergency stop" not in report


def test_incident_cases_can_be_evaluated_in_batch(tmp_path: Path) -> None:
    result = evaluate_incident_cases(CASE_FILE.parent, tmp_path / "batch")

    assert result.total == 19
    assert result.passed == 19
    assert result.case_pass_rate == 1.0
    assert result.expected_finding_recall == 1.0
    assert result.false_positive_case_rate == 0.0
    assert result.forbidden_hit_count == 0
    assert result.average_parse_success_rate == 1.0
    assert result.evidence_backed_finding_rate == 1.0
    assert result.evidence_reference_validity == 1.0
    assert result.total_duration_ms >= 0
    assert result.domain_case_counts["network"] >= 1
    assert all(case.forbidden_hits == [] for case in result.cases)
    assert all(case.missing_findings == [] for case in result.cases)
    assert all(case.invalid_evidence_references == [] for case in result.cases)

    report = incident_evaluation_markdown(result)
    assert "# Incident Analysis Quality Baseline" in report
    assert "Expected-finding recall: **100.0%**" in report
    assert "solaredge_4g_eth1_manager_conflict — PASS" in report

    cached = evaluate_incident_cases(
        CASE_FILE.parent,
        tmp_path / "unused",
        reuse_from=tmp_path / "batch",
    )
    assert cached.evaluation_mode == "cached_routed_case_baseline"
    assert cached.passed == 19
    assert cached.expected_finding_recall == 1.0


def test_s3_case_separates_confirmed_stop_from_trigger_hypothesis(tmp_path: Path) -> None:
    result = analyze_incident_case(S3_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    assert findings["s3_vehicle_emergency_stop"].status == "confirmed"
    hypothesis = findings["ev_estop_at_max_current_possible_fluctuation"]
    assert hypothesis.status == "probable"
    assert hypothesis.confidence == "low"
    assert "295.5 A" in hypothesis.explanation
    assert hypothesis.missing_evidence
    assert EventType.OCPP_STOP_ACCEPTED in {event.type for event in result.events}
    assert any("Fault_State1" in artifact.relative_path for artifact in result.artifacts if artifact.parse_status == "parsed")


def test_sungrow_error_catalog_maps_s3_as_symptom_not_root_cause() -> None:
    catalog = load_error_catalog(ROOT / "knowledge" / "error_codes" / "sungrow.yaml")

    assert catalog["S3"].meaning == "EV_E_Stop"
    assert catalog["S3"].origin == "vehicle"
    assert catalog["S3"].diagnostic_role == "symptom"


def test_s20_case_distinguishes_timeout_from_probable_state_regression(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(S20_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    assert findings["s20_frame_communication_timeout_observed"].status == "confirmed"
    lifecycle = findings["s20_state_lifecycle_inconsistency_probable"]
    assert lifecycle.status == "probable"
    assert lifecycle.counter_evidence_event_ids
    assert "permanently stuck" in lifecycle.explanation
    assert any(
        event.attrs.get("status") == "Available"
        and event.attrs.get("ocpp_error") == "NoError"
        and event.attrs.get("code") == "S20"
        for event in result.events
    )


def test_maintenance_backend_case_isolates_destination_specific_failure(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(MAINTENANCE_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    outage = findings["maintenance_backend_prolonged_disconnection_confirmed"]
    assert outage.status == "confirmed"
    assert "customer OCPP" in outage.title
    unresolved = findings["maintenance_backend_network_path_unresolved"]
    assert unresolved.status == "inconclusive"
    assert unresolved.counter_evidence_event_ids
    assert "manual IP configuration change" in unresolved.explanation


def test_sim_card_case_isolates_customer_path_without_claiming_dead_sim(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(SIM_CARD_PATH_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    startup = findings["fognode_and_operation_initial_connection_confirmed"]
    assert startup.status == "confirmed"
    assert "HTTP 101" in startup.explanation
    assert "Accepted BootNotification" in startup.explanation

    outage = findings["operation_pong_timeout_and_reconnect_failure_confirmed"]
    assert outage.status == "confirmed"
    assert "code 1006" in outage.explanation
    assert "Maintenance Heartbeat still received a reply" in outage.explanation
    assert "180-second Ping interval only delayed failure detection" in outage.explanation

    path = findings["customer_sim_to_operation_port_path_probable"]
    assert path.status == "probable"
    assert path.confidence == "medium"
    assert "Customer SIM/APN to Operation platform port" in path.title
    assert "RSRP -86 to -84 dBm" in path.explanation
    assert "does not support physical SIM-card failure" in path.explanation
    assert any("nc -vz" in action for action in path.recommended_actions)
    router_events = [
        event
        for event in result.events
        if event.component == "router_syslog"
    ]
    assert router_events
    assert min(event.ts_utc for event in router_events) == "2026-09-07T06:06:29Z"
    assert next(
        artifact
        for artifact in result.artifacts
        if artifact.path.name == "Vnetwork.log"
    ).parse_status == "excluded"
    assert next(
        artifact
        for artifact in result.artifacts
        if artifact.path.name == "VPowerCabinetFogNode.log"
    ).parse_status == "parsed"


def test_mercedes_case_correlates_related_terminal_serial_numbers(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(MERCEDES_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    immediate = findings["ev_invalid_target_voltage_precharge_stop_confirmed"]
    assert immediate.status == "confirmed"
    assert "2 CCU log source(s)" in immediate.explanation
    root_cause = findings["mercedes_vehicle_software_root_cause_confirmed"]
    assert root_cause.status == "confirmed"
    assert root_cause.affected_domain.value == "iso15118"
    assert {event.charger_id for event in result.events} == {"A2551405827"}


def test_nested_zip_logs_are_extracted_safely(tmp_path: Path) -> None:
    inner = tmp_path / "terminal.zip"
    with ZipFile(inner, "w") as archive:
        archive.writestr("A2551405831VCCU_Ethernet1.log", "example")
    outer = tmp_path / "charger.zip"
    with ZipFile(outer, "w") as archive:
        archive.write(inner, "terminal.zip")

    root = prepare_workspace(outer, tmp_path / "work")

    assert (
        root / "terminal" / "A2551405831VCCU_Ethernet1.log"
    ).read_text() == "example"


def test_bmw_i3_case_links_current_dip_to_c_to_b_stop(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(BMW_I3_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    ramp = findings["bmw_i3_stepwise_target_current_ramp_confirmed"]
    assert ramp.status == "confirmed"
    root_cause = findings["bmw_i3_module_switch_current_dip_root_cause"]
    assert root_cause.status == "confirmed"
    assert "107.0 A" in root_cause.explanation
    assert "79.5 A" in root_cause.explanation
    assert "30 kW" in root_cause.explanation
    assert "does not independently prove an S3" in root_cause.explanation


def test_fault_mode_case_links_lem2_fault_cascade_to_internal_network(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(FAULT_MODE_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    communication = findings["connector2_lem_communication_loss_confirmed"]
    assert communication.status == "confirmed"
    assert "L20" in communication.explanation
    assert "communication-loss cascade" in communication.explanation

    path_fault = findings["connector2_internal_ethernet_path_fault_probable"]
    assert path_fault.status == "probable"
    assert path_fault.confidence == "medium"
    assert "77 seconds" in path_fault.explanation
    assert "53 seconds" in path_fault.explanation
    assert "192.168.10.2" in path_fault.explanation
    assert path_fault.counter_evidence_event_ids
    assert any("curl -v" in action for action in path_fault.recommended_actions)


def test_lem_http_hang_case_separates_network_reachability_from_service(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(LEM_HTTP_HANG_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    timeout = findings["connector2_meter_http_timeout_persistent_confirmed"]
    assert timeout.status == "confirmed"
    assert "Connector 1" in timeout.explanation
    assert "completed none" in timeout.explanation

    service_hang = findings["connector2_lem_http_service_hang_probable"]
    assert service_hang.status == "probable"
    assert "answered ICMP ping" in service_hang.explanation
    assert "cable continuity passed" in service_hang.explanation
    assert "July 1" in service_hang.explanation
    assert any("packet trace" in action for action in service_hang.recommended_actions)


def test_dual_terminal_l20_case_confirms_trigger_and_automatic_clear(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(DUAL_TERMINAL_L20_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    lifecycle = findings["dual_terminal_l20_trigger_clear_mechanism_confirmed"]
    assert lifecycle.status == "confirmed"
    assert "Terminal1" in lifecycle.explanation
    assert "Terminal2" in lifecycle.explanation
    assert "No stuck L20" in lifecycle.explanation

    trigger = findings["dual_terminal_meter_communication_interruption_probable"]
    assert trigger.status == "probable"
    assert trigger.confidence == "low"
    assert trigger.counter_evidence_event_ids
    assert "persistent meter hardware failure" in trigger.explanation


def test_plug_and_play_case_attributes_stop_to_customer_idtag_rejection(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(PLUG_AND_PLAY_CASE_FILE, tmp_path / "reports")

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "plug_and_play_charger_idtag_rejected_confirmed"
    assert finding.status == "confirmed"
    assert "A2581906891" in finding.explanation
    assert "transactionId=0" in finding.explanation
    assert "DeAuthorized" in finding.explanation
    assert "no energy was delivered" in finding.explanation
    assert any("Register" in action for action in finding.recommended_actions)


def test_tesla_precharge_case_links_residual_voltage_to_safety_stop(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(TESLA_PRECHARGE_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    protection = findings["precharge_output_over_ev_voltage_protection_confirmed"]
    assert protection.status == "confirmed"
    assert "262-263 V" in protection.explanation
    assert "18.7-39.0 V" in protection.explanation
    assert "12 V protection threshold" in protection.explanation

    timing = findings["post_cablecheck_residual_voltage_timing_probable"]
    assert timing.status == "probable"
    assert "523-545 ms" in timing.explanation
    assert "280.7-302.0 V" in timing.explanation
    assert any(
        "protection enabled" in action for action in timing.recommended_actions
    )
    assert not any(
        "disable" in action.lower() for action in timing.recommended_actions
    )


def test_current_demand_case_keeps_true_overvoltage_and_bad_sample_unresolved(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(CURRENT_DEMAND_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    protection = findings["current_demand_output_overvoltage_protection_confirmed"]
    assert protection.status == "confirmed"
    assert "25.03 V" in protection.explanation
    assert "408 V" in protection.explanation
    assert "433.0 V" in protection.explanation

    unresolved = findings["current_demand_true_overvoltage_vs_sample_unresolved"]
    assert unresolved.status == "inconclusive"
    assert "367 V" in unresolved.explanation
    assert "485 seconds old" in unresolved.explanation
    assert "pcu_20260728050417.log" in unresolved.explanation
    assert "No root cause should be declared" in unresolved.explanation

    retry = findings["replug_started_new_successful_transaction_confirmed"]
    assert retry.status == "confirmed"
    assert "389920417" in retry.explanation
    assert "389922350" in retry.explanation
    assert "separate session" in retry.explanation


def test_ems_low_power_case_identifies_ev_request_as_binding_limit(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(EMS_LOW_POWER_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    taper = findings["ev_high_soc_current_taper_confirmed"]
    assert taper.status == "confirmed"
    assert "78% and 82% SoC" in taper.explanation
    assert "113.5 A to 0.9 A" in taper.explanation
    assert "minimum request of 0.8 A" in taper.explanation

    ems = findings["ems_low_allocation_not_primary_limiter_probable"]
    assert ems.status == "probable"
    assert "49.5 kW" in ems.explanation
    assert "2.4 kW floor" in ems.explanation
    assert "allowed 3.0 kW" in ems.explanation
    assert "requested only about 0.3 kW" in ems.explanation
    assert "not the binding constraint" in ems.explanation


def test_s25_case_identifies_dynamic_down_ramp_tracking_failure(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(S25_RAMP_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    profile = findings["smart_profile_abrupt_step_down_confirmed"]
    assert profile.status == "confirmed"
    assert "15.0 kW" in profile.explanation
    assert "18.9 A" in profile.explanation
    assert "246.3 kW" in profile.explanation

    tracking = findings["s25_dynamic_current_tracking_lag_confirmed"]
    assert tracking.status == "confirmed"
    assert "311 A to 85 A" in tracking.explanation
    assert "99 A" in tracking.explanation
    assert "14 A above" in tracking.explanation
    assert "S25/OverCurrentFailure" in tracking.explanation

    vehicle = findings["ev_slow_compliance_with_new_limit_contributed"]
    assert vehicle.status == "confirmed"
    assert "18.9 A" in vehicle.explanation
    assert "85 A" in vehicle.explanation


def test_ora_case_identifies_initial_zero_target_compatibility_defect(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(
        ORA_ZERO_TARGET_CASE_FILE, tmp_path / "reports"
    )

    findings = {finding.rule_id: finding for finding in result.findings}
    repeated = findings["repeated_initial_precharge_zero_voltage_confirmed"]
    assert repeated.status == "confirmed"
    assert "2 attempts" in repeated.explanation
    assert "target voltage 0 V" in repeated.explanation

    collapse = findings["zero_target_output_collapse_confirmed"]
    assert collapse.status == "confirmed"
    assert "201 V" in collapse.explanation
    assert "374.2 V" in collapse.explanation
    assert "fell to 10 V" in collapse.explanation
    assert "280 V" in collapse.explanation

    compatibility = findings[
        "ora_precharge_compatibility_software_change_required"
    ]
    assert compatibility.status == "confirmed"
    assert "7.1 s" in compatibility.explanation
    assert "0 charger alarm/error-code events" in compatibility.explanation
    assert "software compatibility defect" in compatibility.explanation


def test_c36_case_proves_alarm_is_independent_from_emergency_button(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(C36_ESTOP_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    mapping = findings["c36_cp_state_e_mapping_confirmed"]
    assert mapping.status == "confirmed"
    assert "alarm ID 80" in mapping.explanation
    assert "non-forced" in mapping.explanation

    before_estop = findings["c36_preceded_estop_independent_confirmed"]
    assert "70 s before C2" in before_estop.explanation
    assert "421.5-423.6 V" in before_estop.explanation

    persisted = findings["c36_persisted_after_estop_release_confirmed"]
    assert "returned to C36 alone" in persisted.explanation
    assert "independent lifecycles" in persisted.explanation


def test_c36_case_identifies_spontaneous_cp_state_lifecycle(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(
        C36_SPONTANEOUS_CASE_FILE, tmp_path / "reports"
    )

    findings = {finding.rule_id: finding for finding in result.findings}
    lifecycle = findings["c36_spontaneous_cp_state_lifecycle_confirmed"]
    assert lifecycle.status == "confirmed"
    assert "2 long clear→reappear cycles" in lifecycle.explanation
    assert "5.5 h, 5.7 h" in lifecycle.explanation
    assert "no C2 event" in lifecycle.explanation

    path = findings["connector1_cp_signal_path_fault_probable"]
    assert path.status == "probable"
    assert "physical CP/PE path or the CCU sampling path" in path.explanation


def test_pm1_case_separates_fan_fault_from_power_limit_and_vehicle(
    tmp_path: Path,
) -> None:
    result = analyze_incident_case(PM1_FAULT_CASE_FILE, tmp_path / "reports")

    findings = {finding.rule_id: finding for finding in result.findings}
    update = findings["sdsp_update_success_pm_fault_persisted_confirmed"]
    assert update.status == "confirmed"
    assert "04.0E3.003.001.03" in update.explanation
    assert "04.0E3.003.001.05" in update.explanation

    limit = findings["charger_25kw_limit_operated_correctly_confirmed"]
    assert "25.0 kW EVSE limit" in limit.explanation
    assert "24.9 kW" in limit.explanation
    assert "8 kW" in limit.explanation
    assert "vehicle's startup ramp" in limit.explanation

    module = findings["pm1_fault_removed_only_power_module_confirmed"]
    assert module.status == "confirmed"
    assert "25 kW to 0 kW" in module.explanation
    assert "ValidMdNum then became 0" in module.explanation
    assert "39 s later" in module.explanation

    fan = findings["pm1_fan6_or_feedback_path_fault_probable"]
    assert fan.status == "probable"
    assert "Fan6Speedabnormal" in fan.explanation
    assert "HARD_PFC_FAULT" in fan.explanation
