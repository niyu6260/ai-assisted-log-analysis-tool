from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class Domain(str, Enum):
    """Diagnostic layers used across a complete charger."""

    CP = "cp"
    PLC_SLAC = "plc_slac"
    ISO15118 = "iso15118"
    POWER = "power"
    OCPP = "ocpp"
    NETWORK = "network"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class ParseQuality(str, Enum):
    EXACT = "exact"
    INFERRED = "inferred"
    PARTIAL = "partial"


class EventType(str, Enum):
    SESSION_START = "SESSION_START"
    SESSION_STOP = "SESSION_STOP"
    METER_VALUES = "METER_VALUES"
    CABLECHECK = "CABLECHECK"
    CABLECHECK_FINISHED = "CABLECHECK_FINISHED"
    PRECHARGE = "PRECHARGE"
    CURRENT_DEMAND = "CURRENT_DEMAND"
    EV_CURRENT_LIMIT = "EV_CURRENT_LIMIT"
    POWER_REQUEST = "POWER_REQUEST"
    POWER_FEEDBACK = "POWER_FEEDBACK"
    ALARM = "ALARM"
    EMERGENCY_STOP = "EMERGENCY_STOP"
    NORMAL_STOP = "NORMAL_STOP"
    CP_STATE_CHANGE = "CP_STATE_CHANGE"
    CHARGING_COMPLETE = "CHARGING_COMPLETE"
    ISOLATION_STATUS = "ISOLATION_STATUS"
    SLAC_STATE = "SLAC_STATE"
    ISO15118_STATE = "ISO15118_STATE"
    NETWORK_STATE = "NETWORK_STATE"
    NETWORK_MANAGER_START = "NETWORK_MANAGER_START"
    NETWORK_MANAGER_RELEASE = "NETWORK_MANAGER_RELEASE"
    NETWORK_MODE_CHANGE = "NETWORK_MODE_CHANGE"
    CONNECTIVITY_LOST = "CONNECTIVITY_LOST"
    PROCESS_CLEANUP = "PROCESS_CLEANUP"
    SERVICE_START = "SERVICE_START"
    DNS_RECOVERED = "DNS_RECOVERED"
    WEBSOCKET_CONNECTED = "WEBSOCKET_CONNECTED"
    OCPP_BOOT_ACCEPTED = "OCPP_BOOT_ACCEPTED"
    OCPP_STOP_ACCEPTED = "OCPP_STOP_ACCEPTED"
    ERROR_CODE = "ERROR_CODE"
    ERROR_CODE_CLEARED = "ERROR_CODE_CLEARED"
    CONNECTOR_STATUS = "CONNECTOR_STATUS"
    AUTHORIZATION = "AUTHORIZATION"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    MODULE_STATE = "MODULE_STATE"
    OTHER = "OTHER"


@dataclass
class SourceLocation:
    path: str
    line: Optional[int] = None
    offset: Optional[int] = None


@dataclass
class Event:
    id: str
    ts_utc: str
    source: str  # ocpp | vccu | pcu
    type: EventType
    summary: str
    raw: str = ""
    connector_id: Optional[int] = None
    gun_id: Optional[int] = None
    txn_id: Optional[int] = None
    attrs: dict[str, Any] = field(default_factory=dict)
    domain: Domain = Domain.UNKNOWN
    component: str = ""
    original_timestamp: str = ""
    charger_id: Optional[str] = None
    terminal_id: Optional[str] = None
    session_id: Optional[str] = None
    correlation_ids: dict[str, str] = field(default_factory=dict)
    parse_quality: ParseQuality = ParseQuality.EXACT
    source_location: Optional[SourceLocation] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        d["domain"] = self.domain.value
        d["parse_quality"] = self.parse_quality.value
        return d


@dataclass
class Session:
    key: str
    connector_id: Optional[int] = None
    txn_id: Optional[int] = None
    start_ts: Optional[str] = None
    stop_ts: Optional[str] = None
    stop_reason: Optional[str] = None
    event_ids: list[str] = field(default_factory=list)
    gun_id: Optional[int] = None
    charger_id: Optional[str] = None
    terminal_id: Optional[str] = None
    correlation_ids: dict[str, str] = field(default_factory=dict)
    stages: dict[str, str] = field(default_factory=dict)
    first_anomaly_event_id: Optional[str] = None
    association_confidence: str = "medium"
    association_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    explanation: str
    evidence_event_ids: list[str] = field(default_factory=list)
    suggested_customer_reply: str = ""
    session_key: Optional[str] = None
    confidence: str = "medium"
    status: str = "confirmed"
    root_cause_category: str = ""
    affected_domain: Domain = Domain.UNKNOWN
    counter_evidence_event_ids: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["affected_domain"] = self.affected_domain.value
        return d
