from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class CpVariant:
    id: str
    base_state: str
    pwm: bool
    meaning: str


@dataclass(frozen=True)
class CpState:
    id: str
    nominal_positive_voltage_v: float
    meaning: str
    category: str
    variants: dict[str, CpVariant]
    implementation_note: str = ""


@dataclass(frozen=True)
class CpTransition:
    id: str
    source: str
    target: str
    trigger: str
    direction: str


@dataclass(frozen=True)
class ProtocolKnowledge:
    knowledge_id: str
    title: str
    status: str
    states: dict[str, CpState]
    transitions: tuple[CpTransition, ...]
    message_phase_alignment: dict[str, tuple[str, ...]]
    diagnostic_rules: tuple[dict[str, Any], ...]
    open_questions: tuple[str, ...]
    raw: dict[str, Any]

    def state_or_variant(self, state_id: str) -> CpState | CpVariant:
        if state_id in self.states:
            return self.states[state_id]
        for state in self.states.values():
            if state_id in state.variants:
                return state.variants[state_id]
        raise KeyError(f"Unknown CP state or variant: {state_id}")

    def transitions_from(self, state_id: str) -> tuple[CpTransition, ...]:
        self.state_or_variant(state_id)
        return tuple(item for item in self.transitions if item.source == state_id)


def _strings(value: object, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError(f"{field} must be a list of strings")
    return tuple(value)


def load_protocol_knowledge(path: Path) -> ProtocolKnowledge:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Protocol knowledge must be a YAML mapping")
    if data.get("schema_version") != 1:
        raise ValueError(
            f"Unsupported protocol schema version: {data.get('schema_version')!r}"
        )

    raw_states = data.get("states")
    if not isinstance(raw_states, dict) or not raw_states:
        raise ValueError("Protocol knowledge must define states")

    states: dict[str, CpState] = {}
    all_state_ids: set[str] = set()
    for state_id, raw in raw_states.items():
        if not isinstance(state_id, str) or not isinstance(raw, dict):
            raise ValueError("Each CP state must be a mapping")
        raw_variants = raw.get("variants", {})
        if not isinstance(raw_variants, dict):
            raise ValueError(f"Variants for CP state {state_id!r} must be a mapping")
        variants: dict[str, CpVariant] = {}
        for variant_id, variant in raw_variants.items():
            if (
                not isinstance(variant_id, str)
                or not isinstance(variant, dict)
                or not isinstance(variant.get("pwm"), bool)
            ):
                raise ValueError(
                    f"CP variant {variant_id!r} must define a boolean pwm value"
                )
            if variant_id in all_state_ids:
                raise ValueError(f"Duplicate CP state or variant: {variant_id!r}")
            variants[variant_id] = CpVariant(
                id=variant_id,
                base_state=state_id,
                pwm=variant["pwm"],
                meaning=str(variant.get("meaning", "")),
            )
            all_state_ids.add(variant_id)
        if state_id in all_state_ids:
            raise ValueError(f"Duplicate CP state or variant: {state_id!r}")
        voltage = raw.get("nominal_positive_voltage_V")
        if not isinstance(voltage, (int, float)):
            raise ValueError(f"CP state {state_id!r} must define nominal voltage")
        states[state_id] = CpState(
            id=state_id,
            nominal_positive_voltage_v=float(voltage),
            meaning=str(raw.get("meaning", "")),
            category=str(raw.get("category", "")),
            variants=variants,
            implementation_note=str(raw.get("implementation_note", "")),
        )
        all_state_ids.add(state_id)

    transitions: list[CpTransition] = []
    transition_ids: set[str] = set()
    raw_transitions = data.get("transitions", [])
    if not isinstance(raw_transitions, list):
        raise ValueError("transitions must be a list")
    for raw in raw_transitions:
        if not isinstance(raw, dict):
            raise ValueError("Each transition must be a mapping")
        transition_id = str(raw.get("id", ""))
        source = str(raw.get("from", ""))
        target = str(raw.get("to", ""))
        if not transition_id or transition_id in transition_ids:
            raise ValueError(f"Missing or duplicate transition id: {transition_id!r}")
        unknown = {source, target} - all_state_ids
        if unknown:
            raise ValueError(
                f"Transition {transition_id!r} references unknown states: "
                f"{', '.join(sorted(unknown))}"
            )
        transition_ids.add(transition_id)
        transitions.append(
            CpTransition(
                id=transition_id,
                source=source,
                target=target,
                trigger=str(raw.get("trigger", "")),
                direction=str(raw.get("direction", "")),
            )
        )

    raw_alignment = data.get("message_phase_alignment", {})
    if not isinstance(raw_alignment, dict):
        raise ValueError("message_phase_alignment must be a mapping")
    message_phase_alignment = {
        phase: _strings(messages, f"message_phase_alignment.{phase}")
        for phase, messages in raw_alignment.items()
        if phase != "diagnostic_note"
    }

    diagnostic_rules = data.get("diagnostic_rules", [])
    if not isinstance(diagnostic_rules, list) or not all(
        isinstance(item, dict) for item in diagnostic_rules
    ):
        raise ValueError("diagnostic_rules must be a list of mappings")

    return ProtocolKnowledge(
        knowledge_id=str(data.get("knowledge_id", "")),
        title=str(data.get("title", "")),
        status=str(data.get("status", "")),
        states=states,
        transitions=tuple(transitions),
        message_phase_alignment=message_phase_alignment,
        diagnostic_rules=tuple(diagnostic_rules),
        open_questions=_strings(data.get("open_questions"), "open_questions"),
        raw=data,
    )
