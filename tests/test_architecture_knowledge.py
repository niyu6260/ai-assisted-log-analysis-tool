from __future__ import annotations

from pathlib import Path

import pytest

from ccu_log_diag.architecture_knowledge import load_architecture_knowledge


ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE_PATH = (
    ROOT / "knowledge" / "architecture" / "tcu_ccu_diagnostic.yaml"
)


def test_tcu_ccu_architecture_loads_with_valid_component_references() -> None:
    knowledge = load_architecture_knowledge(ARCHITECTURE_PATH)

    assert knowledge.knowledge_id == "sungrow_tcu_ccu_diagnostic_architecture"
    assert knowledge.status == "partial"
    assert "tcu_back_logic" in knowledge.components
    assert "ccu_charging_controller" in knowledge.components
    assert "pcu_controller" in knowledge.components
    assert len(knowledge.communication_paths) == 8
    assert len(knowledge.runtime_mechanisms) == 5
    assert len(knowledge.evidence_boundaries) >= 8


def test_architecture_exposes_cross_component_diagnostic_paths() -> None:
    knowledge = load_architecture_knowledge(ARCHITECTURE_PATH)

    ccu_paths = {path.id: path for path in knowledge.paths_for("ccu_charging_controller")}

    assert "tcu_to_ccu" in ccu_paths
    assert "ccu_to_ev_high_level" in ccu_paths
    assert "ccu_to_pcu" in ccu_paths
    assert ccu_paths["ccu_to_pcu"].confidence == "confirmed"
    assert ccu_paths["ccu_to_ev_high_level"].application_protocols == (
        "DIN 70121",
        "ISO 15118",
    )


def test_architecture_routes_power_faults_to_primary_evidence_sources() -> None:
    knowledge = load_architecture_knowledge(ARCHITECTURE_PATH)

    route = next(
        item
        for item in knowledge.diagnostic_routes
        if "module switching" in item.symptom
    )

    assert route.inspect_first[:2] == ("pcu_controller", "power_modules")


def test_unknown_component_path_lookup_is_rejected() -> None:
    knowledge = load_architecture_knowledge(ARCHITECTURE_PATH)

    with pytest.raises(KeyError, match="unknown_component"):
        knowledge.paths_for("unknown_component")


def test_log_rotation_is_modeled_as_one_cross_file_timeline() -> None:
    knowledge = load_architecture_knowledge(ARCHITECTURE_PATH)

    rotation = knowledge.mechanism("log_rolling")

    assert rotation.owner == "tcu_back_logic"
    assert rotation.details["flush_sequence"][-2:] == [
        "Rename the current file as the old file.",
        "Start a new empty current file.",
    ]
    assert any(
        "one chronological stream" in implication
        for implication in rotation.diagnostic_implications
    )


def test_hierarchical_state_machine_keeps_request_and_completed_entry_distinct() -> None:
    knowledge = load_architecture_knowledge(ARCHITECTURE_PATH)

    state_machine = knowledge.mechanism("hierarchical_state_machine")
    business = knowledge.mechanism("backend_business_state_machine")

    assert state_machine.details["switching_sequence"][:3] == [
        "Receive a state-switch request with a trigger value.",
        "Search the current state and child hierarchy for a matching trigger.",
        "Exit the previous state.",
    ]
    assert "EnergyTransfer" in business.details["top_level_states"]
    assert business.details["confirmed_substates"]["EnergyTransfer"] == [
        "Preparing",
        "Charging",
        "Unplugged",
    ]


def test_unknown_runtime_mechanism_is_rejected() -> None:
    knowledge = load_architecture_knowledge(ARCHITECTURE_PATH)

    with pytest.raises(KeyError, match="missing_mechanism"):
        knowledge.mechanism("missing_mechanism")
