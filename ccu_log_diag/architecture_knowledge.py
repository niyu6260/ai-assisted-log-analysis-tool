from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ArchitectureComponent:
    id: str
    label: str
    layer: str
    responsibilities: tuple[str, ...]
    diagnostic_relevance: tuple[str, ...]


@dataclass(frozen=True)
class CommunicationPath:
    id: str
    source: str
    target: str
    direction: str
    transport: tuple[str, ...]
    application_protocols: tuple[str, ...]
    purpose: tuple[str, ...]
    confidence: str
    note: str = ""


@dataclass(frozen=True)
class DiagnosticRoute:
    symptom: str
    inspect_first: tuple[str, ...]


@dataclass(frozen=True)
class RuntimeMechanism:
    id: str
    owner: str
    diagnostic_implications: tuple[str, ...]
    unknowns: tuple[str, ...]
    details: dict[str, Any]


@dataclass(frozen=True)
class ArchitectureKnowledge:
    knowledge_id: str
    title: str
    status: str
    components: dict[str, ArchitectureComponent]
    communication_paths: tuple[CommunicationPath, ...]
    diagnostic_routes: tuple[DiagnosticRoute, ...]
    runtime_mechanisms: dict[str, RuntimeMechanism]
    evidence_boundaries: tuple[dict[str, Any], ...]
    open_questions: tuple[str, ...]

    def paths_for(self, component_id: str) -> tuple[CommunicationPath, ...]:
        if component_id not in self.components:
            raise KeyError(f"Unknown architecture component: {component_id}")
        return tuple(
            path
            for path in self.communication_paths
            if component_id in {path.source, path.target}
        )

    def mechanism(self, mechanism_id: str) -> RuntimeMechanism:
        try:
            return self.runtime_mechanisms[mechanism_id]
        except KeyError:
            raise KeyError(f"Unknown runtime mechanism: {mechanism_id}") from None


def _strings(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError("Expected a list of strings")
    return tuple(value)


def load_architecture_knowledge(path: Path) -> ArchitectureKnowledge:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Architecture knowledge must be a YAML mapping")
    if data.get("schema_version") != 1:
        raise ValueError(
            f"Unsupported architecture schema version: {data.get('schema_version')!r}"
        )

    raw_components = data.get("components")
    if not isinstance(raw_components, dict) or not raw_components:
        raise ValueError("Architecture knowledge must define components")

    components: dict[str, ArchitectureComponent] = {}
    for component_id, raw in raw_components.items():
        if not isinstance(component_id, str) or not isinstance(raw, dict):
            raise ValueError("Each architecture component must be a mapping")
        components[component_id] = ArchitectureComponent(
            id=component_id,
            label=str(raw.get("label", "")),
            layer=str(raw.get("layer", "")),
            responsibilities=_strings(raw.get("responsibilities")),
            diagnostic_relevance=_strings(raw.get("diagnostic_relevance")),
        )

    paths: list[CommunicationPath] = []
    path_ids: set[str] = set()
    raw_paths = data.get("communication_paths", [])
    if not isinstance(raw_paths, list):
        raise ValueError("communication_paths must be a list")
    for raw in raw_paths:
        if not isinstance(raw, dict):
            raise ValueError("Each communication path must be a mapping")
        path_id = str(raw.get("id", ""))
        source = str(raw.get("from", ""))
        target = str(raw.get("to", ""))
        if not path_id or path_id in path_ids:
            raise ValueError(f"Missing or duplicate communication path id: {path_id!r}")
        unknown = {source, target} - components.keys()
        if unknown:
            raise ValueError(
                f"Communication path {path_id!r} references unknown components: "
                f"{', '.join(sorted(unknown))}"
            )
        path_ids.add(path_id)
        paths.append(
            CommunicationPath(
                id=path_id,
                source=source,
                target=target,
                direction=str(raw.get("direction", "")),
                transport=_strings(raw.get("transport")),
                application_protocols=_strings(raw.get("application_protocols")),
                purpose=_strings(raw.get("purpose")),
                confidence=str(raw.get("confidence", "")),
                note=str(raw.get("note", "")),
            )
        )

    routes: list[DiagnosticRoute] = []
    raw_routes = data.get("diagnostic_routing", [])
    if not isinstance(raw_routes, list):
        raise ValueError("diagnostic_routing must be a list")
    for raw in raw_routes:
        if not isinstance(raw, dict):
            raise ValueError("Each diagnostic route must be a mapping")
        inspect_first = _strings(raw.get("inspect_first"))
        unknown = set(inspect_first) - components.keys()
        if unknown:
            raise ValueError(
                "Diagnostic route references unknown components: "
                f"{', '.join(sorted(unknown))}"
            )
        routes.append(
            DiagnosticRoute(
                symptom=str(raw.get("symptom", "")),
                inspect_first=inspect_first,
            )
        )

    mechanisms: dict[str, RuntimeMechanism] = {}
    raw_mechanisms = data.get("runtime_mechanisms", {})
    if not isinstance(raw_mechanisms, dict):
        raise ValueError("runtime_mechanisms must be a mapping")
    for mechanism_id, raw in raw_mechanisms.items():
        if not isinstance(mechanism_id, str) or not isinstance(raw, dict):
            raise ValueError("Each runtime mechanism must be a mapping")
        owner = str(raw.get("owner", ""))
        if owner not in components:
            raise ValueError(
                f"Runtime mechanism {mechanism_id!r} references unknown owner: "
                f"{owner!r}"
            )
        mechanisms[mechanism_id] = RuntimeMechanism(
            id=mechanism_id,
            owner=owner,
            diagnostic_implications=_strings(raw.get("diagnostic_implications")),
            unknowns=_strings(raw.get("unknowns")),
            details=dict(raw),
        )

    evidence_boundaries = data.get("evidence_boundaries", [])
    if not isinstance(evidence_boundaries, list) or not all(
        isinstance(item, dict) for item in evidence_boundaries
    ):
        raise ValueError("evidence_boundaries must be a list of mappings")

    return ArchitectureKnowledge(
        knowledge_id=str(data.get("knowledge_id", "")),
        title=str(data.get("title", "")),
        status=str(data.get("status", "")),
        components=components,
        communication_paths=tuple(paths),
        diagnostic_routes=tuple(routes),
        runtime_mechanisms=mechanisms,
        evidence_boundaries=tuple(evidence_boundaries),
        open_questions=_strings(data.get("open_questions")),
    )
