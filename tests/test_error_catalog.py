from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ccu_log_diag.error_catalog import load_error_catalog


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "knowledge" / "error_codes" / "sungrow.yaml"


def test_sungrow_catalog_contains_both_imported_model_tables() -> None:
    data = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))

    assert data["schema_version"] == 2
    assert len(data["models"]["IDC180"]["entries"]) == 373
    assert len(data["models"]["IDC480"]["entries"]) == 340
    assert data["models"]["IDC180"]["applies_to"] == ["30E", "30R-1000", "180E"]
    assert data["models"]["IDC480"]["applies_to"] == ["480E", "480EC"]
    assert (
        data["models"]["IDC180"]["source"]["workbook"]
        == "IDC180故障总表-20250117(1).xlsx"
    )
    assert (
        data["models"]["IDC480"]["source"]["workbook"]
        == "IDC480故障总表-20241108(1).xlsx"
    )


def test_model_catalog_supports_internal_and_ocpp_code_lookup() -> None:
    idc180 = load_error_catalog(CATALOG_PATH, model="30R-1000")
    idc480 = load_error_catalog(CATALOG_PATH, model="480EC")

    assert idc180["S20"].canonical_event == "frame_communication_timeout"
    assert idc180["T2"].internal_code == "TCU-2"
    assert idc180["T2"].model == "IDC180"
    assert idc180["STOP-3"].vendor_error == "S3"
    assert idc180["S3"].canonical_event == "vehicle_emergency_stop"
    assert idc480["CCU-2"].meaning == "急停故障"
    assert idc480["CCU-2"].model == "IDC480"


def test_unknown_sungrow_model_is_rejected() -> None:
    with pytest.raises(ValueError, match="IDC180, 30E, 30R-1000, 180E"):
        load_error_catalog(CATALOG_PATH, model="IDC999")
