from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class ErrorCodeDefinition:
    code: str
    vendor: str
    canonical_event: str
    meaning: str
    origin: str
    description: str
    diagnostic_role: str
    confidence: str
    notes: tuple[str, ...]
    model: str = ""
    internal_code: str = ""
    vendor_error: str = ""
    source_sheet: str = ""
    source_row: int | None = None
    trigger: str = ""
    recovery: str = ""


def _curated_definition(
    code: str, vendor: str, definition: dict
) -> ErrorCodeDefinition:
    return ErrorCodeDefinition(
        code=code,
        vendor=vendor,
        canonical_event=definition.get("canonical_event", ""),
        meaning=definition.get("meaning", ""),
        origin=definition.get("origin", ""),
        description=definition.get("description", ""),
        diagnostic_role=definition.get("diagnostic_role", "symptom"),
        confidence=definition.get("confidence", "medium"),
        notes=tuple(definition.get("notes", [])),
    )


def _model_definition(
    code: str, vendor: str, model: str, entry: dict
) -> ErrorCodeDefinition:
    trigger = str(entry.get("trigger", ""))
    recovery = str(entry.get("recovery", ""))
    notes = tuple(
        note
        for note in (
            f"Trigger: {trigger}" if trigger else "",
            f"Recovery: {recovery}" if recovery else "",
            str(entry.get("notes", "")),
        )
        if note
    )
    return ErrorCodeDefinition(
        code=code,
        vendor=vendor,
        canonical_event=str(entry.get("display_field", "")),
        meaning=str(entry.get("name", "")),
        origin=str(entry.get("source_sheet", "")),
        description=trigger,
        diagnostic_role="symptom",
        confidence="high",
        notes=notes,
        model=model,
        internal_code=str(entry.get("internal_code", "")),
        vendor_error=str(entry.get("vendor_error", "")),
        source_sheet=str(entry.get("source_sheet", "")),
        source_row=entry.get("source_row"),
        trigger=trigger,
        recovery=recovery,
    )


def load_error_catalog(
    path: Path, model: str | None = None
) -> dict[str, ErrorCodeDefinition]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    vendor = data.get("vendor", "") if isinstance(data, dict) else ""
    codes = data.get("codes", {}) if isinstance(data, dict) else {}
    catalog = {
        code: _curated_definition(code, vendor, definition)
        for code, definition in codes.items()
    }
    if model is None:
        return catalog

    models = data.get("models", {}) if isinstance(data, dict) else {}
    requested_model = model.strip().casefold()
    canonical_model = next(
        (
            name
            for name, definition in models.items()
            if requested_model == name.casefold()
            or requested_model
            in {
                str(alias).strip().casefold()
                for alias in definition.get("applies_to", [])
            }
        ),
        None,
    )
    model_data = models.get(canonical_model) if canonical_model else None
    if not isinstance(model_data, dict):
        available = ", ".join(
            alias
            for name, definition in sorted(models.items())
            for alias in (name, *definition.get("applies_to", []))
        ) or "none"
        raise ValueError(f"Unknown model {model!r}; available models: {available}")

    for entry in model_data.get("entries", []):
        if not isinstance(entry, dict):
            continue
        aliases = {
            str(entry.get("internal_code", "")).strip(),
            str(entry.get("vendor_error", "")).strip(),
        }
        aliases.discard("")
        aliases.discard("/")
        for alias in aliases:
            catalog.setdefault(
                alias,
                _model_definition(
                    alias, vendor, str(canonical_model), entry
                ),
            )
    return catalog
