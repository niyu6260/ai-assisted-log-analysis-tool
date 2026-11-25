from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ccu_log_diag.model.events import Domain, Event, EventType, Session


@dataclass(frozen=True)
class Detection:
    hit: bool
    evidence: list[str]
    counter_evidence: list[str]
    affected_domain: Domain
    root_cause_category: str
    missing_evidence: list[str]
    recommended_actions: list[str]


@dataclass(frozen=True)
class DetectorContext:
    events: list[Event]
    session: Session | None

    @property
    def types(self) -> set[EventType]:
        return {event.type for event in self.events}


Detector = Callable[[DetectorContext, dict], Detection]
DETECTORS: dict[str, Detector] = {}


def detector(rule_id: str) -> Callable[[Detector], Detector]:
    def register(function: Detector) -> Detector:
        DETECTORS[rule_id] = function
        return function

    return register


def no_hit(domain: Domain = Domain.UNKNOWN) -> Detection:
    return Detection(False, [], [], domain, "", [], [])


def hit(
    events: list[Event],
    domain: Domain,
    category: str,
    *,
    counter: list[Event] | None = None,
    missing: list[str] | None = None,
    actions: list[str] | None = None,
) -> Detection:
    return Detection(
        True,
        [event.id for event in events],
        [event.id for event in counter or []],
        domain,
        category,
        missing or [],
        actions or [],
    )


@detector("normal_ev_stop")
def normal_ev_stop(context: DetectorContext, rule: dict) -> Detection:
    complete = [e for e in context.events if e.type == EventType.CHARGING_COMPLETE]
    stopped = [e for e in context.events if e.type == EventType.NORMAL_STOP]
    return hit((complete + stopped)[:5], Domain.ISO15118, "normal_stop") if complete and stopped else no_hit()


@detector("isolation_invalid_during_cablecheck")
def isolation_invalid(context: DetectorContext, rule: dict) -> Detection:
    invalid = [
        e
        for e in context.events
        if e.type == EventType.ISOLATION_STATUS
        and str(e.attrs.get("EVSEIsolationStatus", "")).lower() == "invalid"
    ]
    cable = [
        e
        for e in context.events
        if e.type in {EventType.CABLECHECK, EventType.CABLECHECK_FINISHED}
        or "IsolationMonitoringActive" in e.raw
    ]
    return hit((invalid[:1] + cable[:2]), Domain.ISO15118, "normal_transient") if invalid and cable else no_hit()


@detector("precharge_voltage_diff_trip")
def precharge_voltage_diff(context: DetectorContext, rule: dict) -> Detection:
    alarms = [
        e
        for e in context.events
        if e.type == EventType.ALARM
        and any(token in (e.summary + e.raw).lower() for token in ("voltage", "precharge", "diff"))
    ]
    precharge = [e for e in context.events if e.type == EventType.PRECHARGE]
    emergency = [e for e in context.events if e.type == EventType.EMERGENCY_STOP]
    if alarms and precharge and emergency:
        return hit(
            [precharge[0], alarms[0], emergency[0]],
            Domain.POWER,
            "precharge_voltage_mismatch",
            actions=["Check residual DC bus voltage and EV requested voltage."],
        )
    return no_hit()


@detector("vehicle_emergency_stop")
def vehicle_emergency(context: DetectorContext, rule: dict) -> Detection:
    emergency = [e for e in context.events if e.type == EventType.EMERGENCY_STOP]
    cp = [e for e in context.events if e.type == EventType.CP_STATE_CHANGE]
    complete = [e for e in context.events if e.type == EventType.CHARGING_COMPLETE]
    if emergency and not complete and any("C_To_B" in e.raw or "Emergency" in e.summary for e in context.events):
        return hit((emergency + cp)[:5], Domain.CP, "vehicle_initiated_stop", counter=complete)
    return no_hit()


@detector("ev_limited_stable_power")
def stable_ev_limited(context: DetectorContext, rule: dict) -> Detection:
    meters = [e for e in context.events if e.type == EventType.METER_VALUES]
    powers = [e.attrs.get("Power_Active_Import") for e in meters if e.attrs.get("Power_Active_Import") is not None]
    offered = [e.attrs.get("Current_Offered") for e in meters if e.attrs.get("Current_Offered") is not None]
    currents = [e.attrs.get("Current_Import") for e in meters if e.attrs.get("Current_Import") is not None]
    if (
        len(powers) >= 3
        and offered
        and currents
        and max(powers) - min(powers) <= float(rule.get("power_spread_max", 5))
        and max(offered) >= float(rule.get("offered_current_min", 200))
        and max(currents) < max(offered) * float(rule.get("import_ratio_max", 0.85))
    ):
        return hit([meters[0], meters[-1]], Domain.POWER, "vehicle_power_limit")
    return no_hit()


@detector("ev_target_current_stopped")
def target_current_stopped(context: DetectorContext, rule: dict) -> Detection:
    targets = [
        e for e in context.events if e.type == EventType.CURRENT_DEMAND and "EVTargetCurrent" in e.summary
    ]
    if not targets or len(targets) >= int(rule.get("max_target_updates", 30)):
        return no_hit()
    later = [
        e
        for e in context.events
        if e.ts_utc > targets[-1].ts_utc
        and e.type in {EventType.EMERGENCY_STOP, EventType.SESSION_STOP, EventType.CP_STATE_CHANGE}
    ]
    if later and any(e.type == EventType.EMERGENCY_STOP for e in later):
        return hit(
            [targets[-1], *later[:2]],
            Domain.ISO15118,
            "ev_target_updates_stopped",
            missing=["Continuous CurrentDemand messages after the final target update."],
        )
    return no_hit()


@detector("ocpp_local_stop_s3")
def ocpp_local_stop(context: DetectorContext, rule: dict) -> Detection:
    stops = [
        e
        for e in context.events
        if e.type == EventType.SESSION_STOP and e.attrs.get("reason") == "Local"
    ]
    s3 = [e for e in context.events if str(e.attrs.get("vendorErrorCode", "")) == "S3"]
    return hit([s3[0], stops[0]], Domain.OCPP, "local_stop") if stops and s3 else no_hit()


def _domain_protocol_error(domain: Domain, category: str, action: str) -> Detector:
    def detect(context: DetectorContext, rule: dict) -> Detection:
        errors = [
            event
            for event in context.events
            if event.domain == domain and event.type in {EventType.PROTOCOL_ERROR, EventType.ALARM}
        ]
        if not errors:
            return no_hit(domain)
        return hit(errors[:5], domain, category, actions=[action])

    return detect


def _power_module_error(context: DetectorContext, rule: dict) -> Detection:
    errors = [
        event
        for event in context.events
        if event.domain == Domain.POWER
        and event.type in {EventType.PROTOCOL_ERROR, EventType.ALARM}
        and (
            event.component == "power"
            or any(token in (event.summary + event.raw).lower() for token in ("pcu", "power module", "rectifier"))
        )
    ]
    if not errors:
        return no_hit(Domain.POWER)
    return hit(
        errors[:5],
        Domain.POWER,
        "power_module",
        actions=["Check PCU alarm code, availability and electrical limits."],
    )


DETECTORS.update(
    {
        "cp_signal_fault": _domain_protocol_error(Domain.CP, "cp_signal_fault", "Measure CP/PP voltage and inspect cable/connector."),
        "slac_negotiation_failure": _domain_protocol_error(Domain.PLC_SLAC, "slac_negotiation", "Compare PEV/EVSE MAC and SLAC timeout sequence."),
        "iso15118_protocol_failure": _domain_protocol_error(Domain.ISO15118, "iso15118_protocol", "Inspect the first failed V2G request/response pair."),
        "power_module_fault": _power_module_error,
        "ocpp_request_failure": _domain_protocol_error(Domain.OCPP, "ocpp_backend", "Check CALLERROR/rejection payload and backend response."),
        "network_connectivity_failure": _domain_protocol_error(Domain.NETWORK, "network_connectivity", "Check link, DNS, route, TCP and TLS in that order."),
    }
)
