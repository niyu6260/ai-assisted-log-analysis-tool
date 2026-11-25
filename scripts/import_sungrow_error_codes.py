from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml
from openpyxl import load_workbook


HEADER_ALIASES = {
    "internal_code": ("编号", "TCU编码"),
    "vendor_error": ("OCPP vendorError", "OCPP \nvendorError"),
    "name": ("故障名称", "故障名", "中文名"),
    "display_field": ("工厂模式显示字段", "显示字段", "故障信息"),
    "fault_type": ("故障类型",),
    "fault_or_warning": ("故障1/告警0", "故障类型\n1：故障\n0：告警"),
    "trigger": ("故障触发条件", "触发条件", "触发阈值"),
    "recovery": ("故障恢复条件", "恢复条件", "恢复阈值"),
    "handling": ("处理方式", "客户排查"),
    "notes": ("备注",),
    "bit": ("bit",),
}

SKIP_SHEETS = {"ChangeLog"}
MODEL_ALIASES = {
    "IDC180": ["30E", "30R-1000", "180E"],
    "IDC480": ["480E", "480EC"],
}


def _text(value: Any) -> str | int | float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    text = str(value).strip()
    return text or None


def _normalized_header(value: Any) -> str:
    return " ".join(str(value or "").replace("\n", " ").split()).lower()


def _find_header(ws) -> tuple[int, dict[int, str]]:
    aliases = {
        _normalized_header(alias): field
        for field, values in HEADER_ALIASES.items()
        for alias in values
    }
    best_row = 0
    best_mapping: dict[int, str] = {}
    for row_index in range(1, min(ws.max_row, 8) + 1):
        mapping: dict[int, str] = {}
        for column, cell in enumerate(ws[row_index], 1):
            field = aliases.get(_normalized_header(cell.value))
            if field and field not in mapping.values():
                mapping[column] = field
        if len(mapping) > len(best_mapping):
            best_row, best_mapping = row_index, mapping
    return best_row, best_mapping


def _fallback_id(model: str, sheet: str, row_number: int, entry: dict[str, Any]) -> str:
    bit = entry.get("bit")
    if bit not in (None, ""):
        return f"{model}-{sheet}-bit-{bit}"
    return f"{model}-{sheet}-row-{row_number}"


def import_workbook(path: Path, model: str) -> dict[str, Any]:
    workbook = load_workbook(path, data_only=True, read_only=False)
    entries: list[dict[str, Any]] = []
    sheet_counts: dict[str, int] = {}
    try:
        for ws in workbook.worksheets:
            if ws.title in SKIP_SHEETS:
                continue
            header_row, columns = _find_header(ws)
            if not columns:
                continue
            count = 0
            for row_number in range(header_row + 1, ws.max_row + 1):
                entry = {
                    field: _text(ws.cell(row_number, column).value)
                    for column, field in columns.items()
                }
                if not any(value not in (None, "/") for value in entry.values()):
                    continue
                if not any(entry.get(field) for field in ("internal_code", "vendor_error", "name", "display_field", "bit")):
                    continue
                entry = {key: value for key, value in entry.items() if value is not None}
                entry["id"] = str(
                    entry.get("internal_code")
                    or entry.get("vendor_error")
                    or _fallback_id(model, ws.title, row_number, entry)
                )
                entry["source_sheet"] = ws.title
                entry["source_row"] = row_number
                entries.append(entry)
                count += 1
            sheet_counts[ws.title] = count
    finally:
        workbook.close()
    return {
        "applies_to": MODEL_ALIASES[model],
        "source": {
            "workbook": path.name,
            "sheet_counts": sheet_counts,
        },
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Sungrow fault workbooks into YAML")
    parser.add_argument("--idc180", type=Path, required=True)
    parser.add_argument("--idc480", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    existing = (
        yaml.safe_load(args.out.read_text(encoding="utf-8"))
        if args.out.exists()
        else {}
    )
    output = {
        "schema_version": 2,
        "vendor": "Sungrow",
        "protocol": "OCPP",
        "codes": (existing or {}).get("codes", {}),
        "models": {
            "IDC180": import_workbook(args.idc180, "IDC180"),
            "IDC480": import_workbook(args.idc480, "IDC480"),
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        yaml.safe_dump(output, allow_unicode=True, sort_keys=False, width=120),
        encoding="utf-8",
    )
    for model, catalog in output["models"].items():
        print(f"{model}: {len(catalog['entries'])} entries")
    print(f"Wrote: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
