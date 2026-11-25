from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ccu_log_diag.model.events import Domain, Event, EventType, Session


def _ts_key(ts: str) -> str:
    return ts or "9999"


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    value = ts.strip().replace(" UTC", "")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_timeline(events: list[Event]) -> list[Event]:
    """Sort and lightly de-duplicate noisy repeating events."""
    for event in events:
        parsed = _parse_ts(event.ts_utc)
        if parsed:
            event.ts_utc = parsed.isoformat().replace("+00:00", "Z")
        if not event.original_timestamp:
            event.original_timestamp = event.ts_utc
    events = sorted(events, key=lambda e: (_ts_key(e.ts_utc), e.source, e.type.value))
    filtered: list[Event] = []
    last_sig: Optional[tuple] = None
    for e in events:
        sig = (e.ts_utc[:19] if e.ts_utc else "", e.source, e.type.value, e.summary)
        if sig == last_sig:
            continue
        # collapse identical CableCheck spam within same second
        if (
            e.type in {EventType.CABLECHECK, EventType.ISOLATION_STATUS}
            and last_sig
            and last_sig[0] == sig[0]
            and last_sig[2] == sig[2]
        ):
            continue
        filtered.append(e)
        last_sig = sig
    return filtered


STAGE_BY_EVENT: dict[EventType, str] = {
    EventType.CP_STATE_CHANGE: "cp",
    EventType.SLAC_STATE: "plc_slac",
    EventType.ISO15118_STATE: "iso15118",
    EventType.AUTHORIZATION: "authorization",
    EventType.CABLECHECK: "cable_check",
    EventType.CABLECHECK_FINISHED: "cable_check",
    EventType.PRECHARGE: "precharge",
    EventType.CURRENT_DEMAND: "current_demand",
    EventType.POWER_REQUEST: "power_delivery",
    EventType.POWER_FEEDBACK: "power_delivery",
    EventType.METER_VALUES: "power_delivery",
    EventType.SESSION_STOP: "settlement",
}


def _new_session(event: Event, index: int) -> Session:
    key = f"txn-{event.txn_id}" if event.txn_id is not None else f"session-{index}"
    session = Session(
        key=key,
        connector_id=event.connector_id,
        gun_id=event.gun_id,
        txn_id=event.txn_id,
        start_ts=event.ts_utc or None,
        charger_id=event.charger_id,
        terminal_id=event.terminal_id,
        correlation_ids=dict(event.correlation_ids),
    )
    session.association_evidence.append("session boundary event")
    return session


def _event_matches_session(event: Event, session: Session) -> tuple[int, str]:
    if event.txn_id is not None and event.txn_id == session.txn_id:
        return 100, "transaction_id"
    event_ts = _parse_ts(event.ts_utc)
    start = _parse_ts(session.start_ts or "")
    inferred_end = _parse_ts(session.correlation_ids.get("_window_end", ""))
    if inferred_end and event_ts and start and not (start <= event_ts <= inferred_end):
        return 0, ""
    if event.connector_id is not None and event.connector_id == session.connector_id:
        return 80, "connector_id"
    if event.gun_id is not None and event.gun_id == session.gun_id:
        return 75, "gun_id"
    shared = set(event.correlation_ids.items()) & set(session.correlation_ids.items())
    if shared:
        return 70, "correlation_ids"
    stop = _parse_ts(session.stop_ts or "")
    if stop is None:
        stop = inferred_end
    if event_ts and start and event_ts >= start and (stop is None or event_ts <= stop):
        return 30, "time_window"
    return 0, ""


def _apply_stage(session: Session, event: Event) -> None:
    stage = STAGE_BY_EVENT.get(event.type)
    if not stage:
        stage = {
            Domain.CP: "cp",
            Domain.PLC_SLAC: "plc_slac",
            Domain.ISO15118: "iso15118",
            Domain.POWER: "power_delivery",
            Domain.OCPP: "ocpp",
            Domain.NETWORK: "network",
        }.get(event.domain)
    if stage:
        failed = event.type in {EventType.PROTOCOL_ERROR, EventType.ALARM, EventType.EMERGENCY_STOP}
        current = session.stages.get(stage)
        if failed or current is None:
            session.stages[stage] = "failed" if failed else "observed"
    if (
        session.first_anomaly_event_id is None
        and event.type in {EventType.PROTOCOL_ERROR, EventType.ALARM, EventType.EMERGENCY_STOP}
    ):
        session.first_anomaly_event_id = event.id


def build_sessions(events: list[Event]) -> list[Session]:
    sessions: dict[str, Session] = {}
    next_index = 1

    for e in events:
        if e.type == EventType.SESSION_START:
            candidate = _new_session(e, next_index)
            next_index += 1
            while candidate.key in sessions:
                candidate.key = f"session-{next_index}"
                next_index += 1
            candidate.event_ids.append(e.id)
            e.session_id = candidate.key
            sessions[candidate.key] = candidate
        elif e.type == EventType.SESSION_STOP and e.txn_id is not None:
            key = f"txn-{e.txn_id}"
            s = sessions.get(key) or _new_session(e, next_index)
            if key not in sessions:
                s.key = key
                next_index += 1
            s.stop_ts = e.ts_utc
            s.stop_reason = (e.attrs or {}).get("reason")
            if e.id not in s.event_ids:
                s.event_ids.append(e.id)
            e.session_id = s.key
            sessions[key] = s

    session_list = list(sessions.values())
    if not session_list and events:
        windows: dict[str, list[Session]] = {}
        for event in events:
            identity = (
                f"connector:{event.connector_id}"
                if event.connector_id is not None
                else f"gun:{event.gun_id}"
                if event.gun_id is not None
                else f"mac:{event.correlation_ids['mac']}"
                if "mac" in event.correlation_ids
                else "unidentified"
            )
            candidates = windows.setdefault(identity, [])
            event_ts = _parse_ts(event.ts_utc)
            previous = candidates[-1] if candidates else None
            previous_end = _parse_ts(previous.correlation_ids.get("_window_end", "")) if previous else None
            gap_seconds = (
                (event_ts - previous_end).total_seconds()
                if event_ts and previous_end
                else 0
            )
            if previous is None or gap_seconds > 1800:
                synthetic = _new_session(event, next_index)
                synthetic.key = f"window-{next_index}"
                next_index += 1
                synthetic.association_evidence = [
                    f"no explicit transaction; inferred from {identity} and 30-minute window"
                ]
                synthetic.association_confidence = "low"
                sessions[synthetic.key] = synthetic
                session_list.append(synthetic)
                candidates.append(synthetic)
                previous = synthetic
            if event.ts_utc:
                previous.correlation_ids["_window_end"] = event.ts_utc

    for e in events:
        if e.session_id and e.session_id in sessions:
            _apply_stage(sessions[e.session_id], e)
            continue
        best: Session | None = None
        best_score = 0
        best_reason = ""
        for s in session_list:
            score, reason = _event_matches_session(e, s)
            if score > best_score:
                best = s
                best_score = score
                best_reason = reason
        if best and e.id not in best.event_ids:
            best.event_ids.append(e.id)
            e.session_id = best.key
            if best_reason and best_reason not in best.association_evidence:
                best.association_evidence.append(best_reason)
            if best_score >= 70:
                best.association_confidence = "high"
            elif best_score < 50 and best.association_confidence != "high":
                best.association_confidence = "low"
            _apply_stage(best, e)

    return sorted(session_list, key=lambda s: s.start_ts or "")
