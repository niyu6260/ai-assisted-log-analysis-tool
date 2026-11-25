from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from ccu_log_diag.model.events import (
    Domain,
    Event,
    EventType,
    ParseQuality,
    SourceLocation,
)


TS_PATTERNS = (
    re.compile(r"^\[(?P<ts>\d{4}-\d{2}-\d{2}[T ][^\]]+)\]"),
    re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+)"),
)


@dataclass(frozen=True)
class Pattern:
    regex: re.Pattern[str]
    event_type: EventType
    label: str
    severity_hint: str = ""


DOMAIN_PATTERNS: dict[Domain, tuple[Pattern, ...]] = {
    Domain.CP: (
        Pattern(re.compile(r"\bCP\b.*(?:state|status).*(?:A|B|C|D|E|F)\b", re.I), EventType.CP_STATE_CHANGE, "CP state change"),
        Pattern(re.compile(r"(?:control pilot|cp).*(?:fault|invalid|error|lost)", re.I), EventType.PROTOCOL_ERROR, "CP signal fault", "high"),
        Pattern(re.compile(r"(?:proximity|pp).*(?:fault|invalid|error)", re.I), EventType.PROTOCOL_ERROR, "PP signal fault", "high"),
    ),
    Domain.PLC_SLAC: (
        Pattern(re.compile(r"(?:CM_)?SLAC_(?:PARM|MATCH|ATTEN_CHAR|VALIDATE)", re.I), EventType.SLAC_STATE, "SLAC message"),
        Pattern(re.compile(r"(?:SLAC|PLC).*(?:matched|match complete|association complete)", re.I), EventType.SLAC_STATE, "SLAC matched"),
        Pattern(re.compile(r"(?:SLAC|PLC).*(?:timeout|timed out|no response|match failed|attenuation.*fail)", re.I), EventType.PROTOCOL_ERROR, "SLAC negotiation failed", "high"),
        Pattern(re.compile(r"(?:NMK|NID|PEV_MAC|EVSE_MAC)", re.I), EventType.SLAC_STATE, "SLAC identity"),
    ),
    Domain.ISO15118: (
        Pattern(re.compile(r"\b(?:SupportedAppProtocol|SessionSetup|ServiceDiscovery|PaymentServiceSelection|Authorization|ChargeParameterDiscovery|CableCheck|PreCharge|CurrentDemand|PowerDelivery|SessionStop)(?:Req|Res)?\b", re.I), EventType.ISO15118_STATE, "ISO 15118 message"),
        Pattern(re.compile(r"(?:ResponseCode|response code).*(?:FAILED|Failure|SequenceError|UnknownSession)", re.I), EventType.PROTOCOL_ERROR, "ISO 15118 response failure", "high"),
        Pattern(re.compile(r"(?:V2G|ISO.?15118).*(?:timeout|decode error|EXI error|session error|TLS.*fail)", re.I), EventType.PROTOCOL_ERROR, "ISO 15118 protocol failure", "high"),
    ),
    Domain.POWER: (
        Pattern(re.compile(r"(?:PCU|power module).*(?:online|offline|ready|derating)", re.I), EventType.MODULE_STATE, "Power module state"),
        Pattern(re.compile(r"(?:PCU|power module|rectifier).*(?:fault|alarm|trip|overvoltage|undervoltage|overcurrent|overtemperature)", re.I), EventType.ALARM, "Power module alarm", "high"),
        Pattern(re.compile(r"(?:requested|target).*(?:voltage|current)|(?:output).*(?:voltage|current)", re.I), EventType.POWER_FEEDBACK, "Power request or feedback"),
    ),
    Domain.OCPP: (
        Pattern(re.compile(r"\b(?:BootNotification|Authorize|StartTransaction|StopTransaction|StatusNotification|TransactionEvent)\b", re.I), EventType.OTHER, "OCPP message"),
        Pattern(re.compile(r"(?:CALLERROR|FormationViolation|PropertyConstraintViolation|NotSupported|SecurityError)", re.I), EventType.PROTOCOL_ERROR, "OCPP call error", "high"),
        Pattern(re.compile(r"(?:Authorize|StartTransaction|TransactionEvent).*(?:Rejected|Invalid|Blocked|Expired)", re.I), EventType.PROTOCOL_ERROR, "OCPP request rejected", "high"),
    ),
    Domain.NETWORK: (
        Pattern(re.compile(r"(?:link is|interface).*(?:up|down)|carrier (?:on|off)", re.I), EventType.NETWORK_STATE, "Network link state"),
        Pattern(re.compile(r"(?:DNS|resolve|name resolution).*(?:fail|timeout|error|NXDOMAIN)", re.I), EventType.PROTOCOL_ERROR, "DNS failure", "high"),
        Pattern(re.compile(r"(?:TCP|socket|connection).*(?:refused|reset|timeout|unreachable|broken pipe)", re.I), EventType.PROTOCOL_ERROR, "TCP connection failure", "high"),
        Pattern(re.compile(r"(?:TLS|SSL|certificate).*(?:fail|expired|unknown ca|handshake error|verify error)", re.I), EventType.PROTOCOL_ERROR, "TLS failure", "high"),
        Pattern(re.compile(r"(?:ping|packet).*(?:loss|unreachable)|no route to host", re.I), EventType.PROTOCOL_ERROR, "Network reachability failure", "high"),
    ),
}


def _timestamp(line: str) -> str:
    for pattern in TS_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group("ts").replace(" UTC", "").replace(" ", "T", 1)
    return ""


def _identifiers(line: str) -> tuple[int | None, int | None, dict[str, str]]:
    connector_match = re.search(r"(?:connector(?:Id)?|port)\s*[:=]\s*(\d+)", line, re.I)
    gun_match = re.search(r"(?:gun|terminal)\s*[:=#]?\s*(\d+)", line, re.I)
    mac_match = re.search(r"\b(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\b", line, re.I)
    connector = int(connector_match.group(1)) if connector_match else None
    gun = int(gun_match.group(1)) if gun_match else None
    ids: dict[str, str] = {}
    if connector is not None:
        ids["connector_id"] = str(connector)
    if gun is not None:
        ids["gun_id"] = str(gun)
    if mac_match:
        ids["mac"] = mac_match.group(0).lower()
    return connector, gun, ids


def parse_domain_file(path: Path, domain: Domain, event_prefix: str | None = None) -> list[Event]:
    """Parse useful facts from a domain log without assigning a root cause."""

    patterns = DOMAIN_PATTERNS.get(domain, ())
    events: list[Event] = []
    prefix = event_prefix or domain.value
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_no, line in enumerate(handle, 1):
            text = line.rstrip("\r\n")
            for item in patterns:
                match = item.regex.search(text)
                if not match:
                    continue
                connector, gun, correlation_ids = _identifiers(text)
                ts = _timestamp(text)
                attrs = {"pattern": item.label}
                if item.severity_hint:
                    attrs["severity_hint"] = item.severity_hint
                events.append(
                    Event(
                        id=f"{prefix}-{path.stem}-{line_no}-{uuid4().hex[:6]}",
                        ts_utc=ts,
                        source=domain.value,
                        type=item.event_type,
                        summary=item.label,
                        raw=text[:1000],
                        connector_id=connector,
                        gun_id=gun,
                        attrs=attrs,
                        domain=domain,
                        component=domain.value,
                        original_timestamp=ts,
                        correlation_ids=correlation_ids,
                        parse_quality=ParseQuality.INFERRED,
                        source_location=SourceLocation(path=str(path), line=line_no),
                    )
                )
                break
    return events
