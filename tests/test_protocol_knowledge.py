from __future__ import annotations

from pathlib import Path

import pytest

from ccu_log_diag.protocol_knowledge import (
    CpState,
    CpVariant,
    load_protocol_knowledge,
)


ROOT = Path(__file__).resolve().parents[1]
CP_PATH = ROOT / "knowledge" / "protocols" / "iec_61851_cp.yaml"


def test_iec_61851_cp_knowledge_loads_and_validates_state_references() -> None:
    knowledge = load_protocol_knowledge(CP_PATH)

    assert knowledge.knowledge_id == "iec_61851_dc_cp_guidance"
    assert set(knowledge.states) == {"A", "B", "C", "D", "E", "F"}
    assert len(knowledge.transitions) == 14
    assert len(knowledge.diagnostic_rules) == 5


def test_cp_base_states_and_pwm_variants_remain_distinct() -> None:
    knowledge = load_protocol_knowledge(CP_PATH)

    state_b = knowledge.state_or_variant("B")
    state_b2 = knowledge.state_or_variant("B2")
    state_e = knowledge.state_or_variant("E")

    assert isinstance(state_b, CpState)
    assert state_b.nominal_positive_voltage_v == 9
    assert isinstance(state_b2, CpVariant)
    assert state_b2.base_state == "B"
    assert state_b2.pwm is True
    assert isinstance(state_e, CpState)
    assert state_e.category == "fault"
    assert state_e.nominal_positive_voltage_v == 0


def test_cp_transition_graph_contains_normal_and_fault_paths() -> None:
    knowledge = load_protocol_knowledge(CP_PATH)

    from_c2 = {item.id: item for item in knowledge.transitions_from("C2")}

    assert from_c2["charging_loop"].target == "C2"
    assert from_c2["ev_not_ready_with_pwm"].target == "B2"
    assert from_c2["cp_open_during_charge"].target == "A2"
    assert from_c2["cp_open_during_charge"].direction == "fault"


def test_cp_states_align_with_high_level_charging_phases() -> None:
    knowledge = load_protocol_knowledge(CP_PATH)

    assert knowledge.message_phase_alignment["state_B_PWM"][:2] == (
        "SupportedAppProtocol",
        "SessionSetup",
    )
    assert knowledge.message_phase_alignment["state_C_or_D_PWM"] == (
        "CableCheck",
        "PreCharge",
        "CurrentDemand",
    )
    assert knowledge.message_phase_alignment["state_B_or_B_PWM"] == (
        "SessionStop",
    )


def test_cp_knowledge_preserves_start_and_stop_cross_layer_sequences() -> None:
    knowledge = load_protocol_knowledge(CP_PATH)

    start = knowledge.raw["dc_start_sequence"]["ordered_phases"]
    stop = knowledge.raw["dc_stop_sequence"]["ordered_phases"]

    assert start[0] == "connector insertion changes CP from A to B"
    assert "CurrentDemand controls energy transfer" == start[-1]
    assert "CP changes from C or D back to B" in stop
    assert stop[-1] == "physical disconnect changes CP from B to A"


def test_unknown_cp_state_is_rejected() -> None:
    knowledge = load_protocol_knowledge(CP_PATH)

    with pytest.raises(KeyError, match="StateZ"):
        knowledge.transitions_from("StateZ")
