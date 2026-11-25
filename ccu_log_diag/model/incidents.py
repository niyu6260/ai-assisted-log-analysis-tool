from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class IncidentWindow:
    start: datetime
    end: datetime

    def contains(self, timestamp: str) -> bool:
        if not timestamp:
            return False
        value = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return False
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return self.start <= parsed.astimezone(timezone.utc) <= self.end


@dataclass(frozen=True)
class SourceSelection:
    serial_number: str
    modules: tuple[str, ...]
    related_serial_numbers: tuple[str, ...] = ()
    include_files: tuple[str, ...] = ()
    include_rotated: bool = True
    utc_offset_hours_by_file: dict[str, float] = field(default_factory=dict)

    def accepts(self, path: Path) -> bool:
        name = path.name
        if name.lower() in {item.lower() for item in self.include_files}:
            return True
        rotation = r"(?:_\d+)?" if self.include_rotated else ""
        modules = "|".join(re.escape(module) for module in self.modules)
        serials = (self.serial_number, *self.related_serial_numbers)
        serial_pattern = "|".join(re.escape(serial) for serial in serials)
        pattern = rf"^(?:{serial_pattern})V(?:{modules}){rotation}\.log$"
        return re.fullmatch(pattern, name, re.IGNORECASE) is not None

    def utc_offset_hours(self, path: Path) -> float:
        offsets = {
            name.casefold(): offset
            for name, offset in self.utc_offset_hours_by_file.items()
        }
        return float(offsets.get(path.name.casefold(), 0.0))


@dataclass(frozen=True)
class GroundTruth:
    symptom: str
    root_cause: str
    confidence: str
    confirmation_status: str
    missing_proof: tuple[str, ...] = ()
    trigger_hypothesis: str = ""
    customer_context_needed: tuple[str, ...] = ()


@dataclass(frozen=True)
class IncidentCase:
    id: str
    title: str
    detector: str
    input_path: Path
    scope: str
    window: IncidentWindow
    source_selection: SourceSelection
    ground_truth: GroundTruth
    expected_findings: tuple[str, ...] = ()
    forbidden_findings: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "IncidentCase":
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Case file must contain a YAML mapping")
        incident = data["incident"]
        selection = data["source_selection"]
        truth = data["ground_truth"]
        input_path = Path(data["input"])
        if not input_path.is_absolute():
            input_path = (path.parent / input_path).resolve()
        return cls(
            id=data["id"],
            title=data.get("title", data["id"]),
            detector=data.get("detector", data["id"]),
            input_path=input_path,
            scope=data.get("scope", "incident_window"),
            window=IncidentWindow(_parse_utc(incident["start"]), _parse_utc(incident["end"])),
            source_selection=SourceSelection(
                serial_number=selection["serial_number"],
                modules=tuple(selection.get("modules", [])),
                related_serial_numbers=tuple(
                    selection.get("related_serial_numbers", [])
                ),
                include_files=tuple(selection.get("include_files", [])),
                include_rotated=selection.get("include_rotated", True),
                utc_offset_hours_by_file={
                    str(name): float(offset)
                    for name, offset in selection.get(
                        "utc_offset_hours_by_file", {}
                    ).items()
                },
            ),
            ground_truth=GroundTruth(
                symptom=truth["symptom"],
                root_cause=truth["root_cause"],
                confidence=truth.get("confidence", "medium"),
                confirmation_status=truth.get("confirmation_status", "probable"),
                missing_proof=tuple(truth.get("missing_proof", [])),
                trigger_hypothesis=truth.get("trigger_hypothesis", ""),
                customer_context_needed=tuple(truth.get("customer_context_needed", [])),
            ),
            expected_findings=tuple(data.get("expected", {}).get("findings", [])),
            forbidden_findings=tuple(data.get("expected", {}).get("forbidden_findings", [])),
            metadata=data.get("metadata", {}),
        )


def _parse_utc(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
