from __future__ import annotations

import re
from pathlib import Path
from uuid import uuid4

from ccu_log_diag.model.events import Domain, Event, EventType, SourceLocation

TS_RE = re.compile(r"^\[(?P<ts>\d{4}-\d{2}-\d{2}T[^\]]+)\]")


PATTERNS: list[tuple[re.Pattern[str], EventType, str]] = [
    (re.compile(r"Cable check timer finish|EVSEProcessing=Finished", re.I), EventType.CABLECHECK_FINISHED, "CableCheck finished"),
    (re.compile(r"CableCheck|Ca_CRes|IsolationMonitoringActive", re.I), EventType.CABLECHECK, "CableCheck activity"),
    (re.compile(r"EVSEIsolationStatus\s*=\s*(\w+)", re.I), EventType.ISOLATION_STATUS, "Isolation status"),
    (re.compile(r"PreCharge|P_CharReq|SendingVoltage_Precharge|Enter state: ChargingHighVoltNoAmpPrecharge", re.I), EventType.PRECHARGE, "PreCharge"),
    (re.compile(r"ChargingComplete\s*=\s*1", re.I), EventType.CHARGING_COMPLETE, "ChargingComplete=1"),
    (re.compile(r"EV_Normal_Stop_Trigger|EvNormalStop", re.I), EventType.NORMAL_STOP, "EV normal stop"),
    (re.compile(r"EvseEmergencyStop|EvEmergencyStop|C_To_B_Charging_Emergency_Stop", re.I), EventType.EMERGENCY_STOP, "Emergency stop"),
    (re.compile(r"State_CD_Switch_To_State_B|C_To_B_Charging", re.I), EventType.CP_STATE_CHANGE, "CP state change"),
    (re.compile(r"Output voltage over EV request voltage|Dc output voltage and EV request voltage difference", re.I), EventType.ALARM, "Voltage difference alarm"),
    (re.compile(r"current alarm error id:\s*(\d+)", re.I), EventType.ALARM, "Alarm error id"),
    (re.compile(r"PreCharge_Fault|EV_InvalidTargetVoltage_Stop_Charging", re.I), EventType.ALARM, "PreCharge fault"),
    (re.compile(r"Send_out_power_request_cache_changed:\s*v:(\d+),\s*c:(\d+)", re.I), EventType.POWER_REQUEST, "Power request cache"),
    (re.compile(r"Connector_Power_Info_Changed!\s*V:(\d+),\s*C:(\d+)", re.I), EventType.POWER_FEEDBACK, "Power feedback"),
    (re.compile(r"EVTargetCurrent\s*=\s*([0-9.-]+)\((-?\d+)\)A", re.I), EventType.CURRENT_DEMAND, "EVTargetCurrent"),
    (re.compile(r"EV_Target_V\s*=\s*([0-9.-]+)\((-?\d+)\)V", re.I), EventType.PRECHARGE, "EV target voltage"),
]


def _scale(value: float, exp: int) -> float:
    return value * (10 ** exp)


def _domain_for_event(event_type: EventType) -> Domain:
    if event_type == EventType.CP_STATE_CHANGE:
        return Domain.CP
    if event_type in {EventType.POWER_REQUEST, EventType.POWER_FEEDBACK, EventType.ALARM}:
        return Domain.POWER
    return Domain.ISO15118


def parse_vccu_file(path: Path, event_prefix: str = "vccu") -> list[Event]:
    events: list[Event] = []
    gun_hint = None
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            ts_m = TS_RE.search(line)
            if not ts_m:
                continue
            ts = ts_m.group("ts").replace("Z UTC", "Z").replace(" UTC", "").strip()
            if not ts.endswith("Z") and "T" in ts:
                # keep as-is; many logs already have Z
                pass

            for pat, etype, label in PATTERNS:
                m = pat.search(line)
                if not m:
                    continue
                attrs: dict = {}
                summary = label
                if etype == EventType.POWER_REQUEST and m.lastindex and m.lastindex >= 2:
                    attrs["v"] = int(m.group(1))
                    attrs["c"] = int(m.group(2))
                    attrs["current_A"] = int(m.group(2)) / 10.0
                    summary = f"Power request v={attrs['v']}V c={attrs['current_A']}A"
                elif etype == EventType.POWER_FEEDBACK and m.lastindex and m.lastindex >= 2:
                    attrs["V"] = int(m.group(1))
                    attrs["C"] = int(m.group(2))
                    attrs["current_A"] = int(m.group(2)) / 10.0
                    summary = f"Power feedback V={attrs['V']}V C={attrs['current_A']}A"
                elif etype == EventType.CURRENT_DEMAND and m.lastindex and m.lastindex >= 2:
                    try:
                        amps = _scale(float(m.group(1)), int(m.group(2)))
                        attrs["EVTargetCurrent_A"] = amps
                        summary = f"EVTargetCurrent={amps:.1f}A"
                    except ValueError:
                        pass
                elif etype == EventType.ISOLATION_STATUS:
                    attrs["EVSEIsolationStatus"] = m.group(1) if m.lastindex else None
                    summary = f"EVSEIsolationStatus={attrs.get('EVSEIsolationStatus')}"
                elif "IsolationMonitoringActive" in line:
                    attrs["EVSEStatusCode"] = "IsolationMonitoringActive"
                elif "difference" in line.lower() or "trigger, value" in line.lower():
                    vm = re.search(r"value:\s*([0-9.]+)", line, re.I)
                    if vm:
                        attrs["diff_V"] = float(vm.group(1))
                        summary = f"Voltage diff alarm value={attrs['diff_V']}"
                elif "error id" in line.lower():
                    em = re.search(r"error id:\s*(\d+)", line, re.I)
                    if em:
                        attrs["error_id"] = int(em.group(1))

                # Deduplicate noisy CableCheck / IsolationMonitoring spam: keep first of burst later in timeline
                events.append(
                    Event(
                        id=f"{event_prefix}-{path.stem}-{line_no}-{uuid4().hex[:6]}",
                        ts_utc=ts if "T" in ts else ts,
                        source="vccu",
                        type=etype,
                        summary=summary,
                        raw=line.strip()[:400],
                        gun_id=gun_hint,
                        attrs=attrs,
                        domain=_domain_for_event(etype),
                        component="vccu",
                        original_timestamp=ts,
                        source_location=SourceLocation(path=str(path), line=line_no),
                    )
                )
                break  # one event type per line
    return events
