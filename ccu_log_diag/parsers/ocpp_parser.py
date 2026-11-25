from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from ccu_log_diag.model.events import Domain, Event, EventType, SourceLocation

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T[^\s|]+)\s*\|\s*(?P<dir>[^|]+)\s*\|\s*action:(?P<action>[^|]*)\s*\|\s*messageId:[^|]*\s*\|\s*payload:(?P<payload>.*)$"
)


def _parse_payload(raw: str) -> dict:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def _meter_attrs(payload: dict) -> dict:
    attrs: dict = {}
    try:
        sampled = payload["meterValue"][0]["sampledValue"]
    except (KeyError, IndexError, TypeError):
        return attrs
    for sv in sampled:
        m = sv.get("measurand")
        v = sv.get("value")
        if not m:
            continue
        key = m.replace(".", "_").replace(" ", "_")
        try:
            attrs[key] = float(v)
        except (TypeError, ValueError):
            attrs[key] = v
    return attrs


def parse_ocpp_file(path: Path, event_prefix: str = "ocpp") -> list[Event]:
    events: list[Event] = []
    pending_starts: list[dict] = []  # wait for platform txn id

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.rstrip("\n")
            m = LINE_RE.match(line)
            if not m:
                continue
            direction = (m.group("dir") or "").strip()
            action = (m.group("action") or "").strip()
            payload = _parse_payload(m.group("payload"))
            ts = m.group("ts")
            connector = payload.get("connectorId")
            txn = payload.get("transactionId")
            eid = f"{event_prefix}-{line_no}-{uuid4().hex[:8]}"

            # Platform StartTransaction reply carries transactionId
            if direction == "PlatformCommand" and payload.get("actionID") == "StartTransaction":
                txn = payload.get("transactionId")
                if txn is not None and pending_starts:
                    start = pending_starts.pop(0)
                    events.append(
                        Event(
                            id=eid,
                            ts_utc=start.get("timestamp", ts),
                            source="ocpp",
                            type=EventType.SESSION_START,
                            summary=f"StartTransaction connector={start.get('connectorId')} txn={txn}",
                            raw=line[:500],
                            connector_id=start.get("connectorId"),
                            txn_id=txn,
                            attrs={"idTag": start.get("idTag"), "meterStart": start.get("meterStart")},
                        )
                    )
                continue

            if action not in {"StartTransaction", "StopTransaction", "MeterValues", "StatusNotification"}:
                continue

            if action == "StartTransaction":
                pending_starts.append(payload)
                # also emit provisional start without txn if reply never arrives
                continue
            elif action == "StopTransaction":
                events.append(
                    Event(
                        id=eid,
                        ts_utc=payload.get("timestamp", ts),
                        source="ocpp",
                        type=EventType.SESSION_STOP,
                        summary=f"StopTransaction reason={payload.get('reason')} txn={txn}",
                        raw=line[:500],
                        connector_id=connector,
                        txn_id=txn,
                        attrs={
                            "reason": payload.get("reason"),
                            "meterStop": payload.get("meterStop"),
                            "idTag": payload.get("idTag"),
                        },
                    )
                )
            elif action == "MeterValues":
                attrs = _meter_attrs(payload)
                power = attrs.get("Power_Active_Import")
                current = attrs.get("Current_Import")
                soc = attrs.get("SoC")
                meter_ts = ts
                try:
                    meter_ts = payload["meterValue"][0].get("timestamp", ts)
                except (KeyError, IndexError, TypeError):
                    pass
                events.append(
                    Event(
                        id=eid,
                        ts_utc=meter_ts,
                        source="ocpp",
                        type=EventType.METER_VALUES,
                        summary=f"MeterValues P={power}kW I={current}A SoC={soc}",
                        raw=line[:400],
                        connector_id=connector,
                        txn_id=txn,
                        attrs=attrs,
                    )
                )
            elif action == "StatusNotification":
                status = payload.get("status")
                err = payload.get("errorCode")
                vendor = payload.get("vendorErrorCode")
                if status in {"Charging", "Finishing", "Faulted"} or (err and err != "NoError") or vendor:
                    events.append(
                        Event(
                            id=eid,
                            ts_utc=payload.get("timestamp", ts),
                            source="ocpp",
                            type=EventType.OTHER,
                            summary=f"StatusNotification status={status} error={err} vendor={vendor}",
                            raw=line[:400],
                            connector_id=connector,
                            attrs={
                                "status": status,
                                "errorCode": err,
                                "vendorErrorCode": vendor,
                            },
                        )
                    )

    # orphan starts without platform reply
    for i, start in enumerate(pending_starts):
        events.append(
            Event(
                id=f"{event_prefix}-orphan-start-{i}-{uuid4().hex[:6]}",
                ts_utc=start.get("timestamp", ""),
                source="ocpp",
                type=EventType.SESSION_START,
                summary=f"StartTransaction connector={start.get('connectorId')} (no txn reply)",
                raw="",
                connector_id=start.get("connectorId"),
                txn_id=None,
                attrs={"idTag": start.get("idTag"), "meterStart": start.get("meterStart")},
            )
        )
    for event in events:
        event.domain = Domain.OCPP
        event.component = "ocpp"
        event.original_timestamp = event.ts_utc
        match = re.search(r"-(\d+)-[0-9a-f]+$", event.id)
        event.source_location = SourceLocation(
            path=str(path),
            line=int(match.group(1)) if match else None,
        )
        if event.connector_id is not None:
            event.correlation_ids["connector_id"] = str(event.connector_id)
        if event.txn_id is not None:
            event.correlation_ids["transaction_id"] = str(event.txn_id)
    return events
