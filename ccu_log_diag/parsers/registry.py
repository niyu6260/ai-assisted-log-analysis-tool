from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from ccu_log_diag.model.events import Domain, Event
from ccu_log_diag.parsers.domain_parser import parse_domain_file
from ccu_log_diag.parsers.ocpp_parser import parse_ocpp_file
from ccu_log_diag.parsers.vccu_parser import parse_vccu_file


class ParserPlugin(Protocol):
    name: str
    domain: Domain

    def detect(self, path: Path, sample: str) -> float: ...

    def parse(self, path: Path) -> list[Event]: ...


@dataclass(frozen=True)
class FunctionalParser:
    name: str
    domain: Domain
    detector: Callable[[Path, str], float]
    parser: Callable[[Path], list[Event]]

    def detect(self, path: Path, sample: str) -> float:
        return self.detector(path, sample)

    def parse(self, path: Path) -> list[Event]:
        return self.parser(path)


@dataclass(frozen=True)
class ParserSelection:
    parser: ParserPlugin | None
    confidence: float
    candidates: tuple[tuple[str, float], ...]


def _score(path: Path, sample: str, names: tuple[str, ...], content: tuple[str, ...]) -> float:
    path_text = str(path).replace("\\", "/").lower()
    sample_lower = sample.lower()
    score = 0.0
    if any(token in path_text for token in names):
        score += 0.65
    hits = sum(1 for token in content if token.lower() in sample_lower)
    score += min(0.35, hits * 0.12)
    return min(score, 1.0)


def _specialized_ocpp(path: Path, sample: str) -> float:
    return _score(
        path,
        sample,
        ("operationocppmessage", "ocpp"),
        ("action:", "starttransaction", "stoptransaction", "metervalues"),
    )


def _specialized_vccu(path: Path, sample: str) -> float:
    return _score(
        path,
        sample,
        ("vccu_ethernet", "vccu"),
        ("evtargetcurrent", "cablecheck", "precharge", "evseisolationstatus"),
    )


DOMAIN_HINTS: dict[Domain, tuple[tuple[str, ...], tuple[str, ...]]] = {
    Domain.CP: (("cp_", "cp.", "control_pilot", "/cp/"), ("cp state", "cp signal", "control pilot", "proximity pilot")),
    Domain.PLC_SLAC: (("slac", "plc", "homeplug"), ("slac_parm", "slac_match", "atten_char", "nmk")),
    Domain.ISO15118: (("iso15118", "iso_15118", "v2g"), ("sessionsetup", "supportedappprotocol", "currentdemand", "exi")),
    Domain.POWER: (("pcu_", "/pcu/", "power_module", "rectifier"), ("pcu", "power module", "output voltage", "output current")),
    Domain.OCPP: (("ocpp",), ("bootnotification", "statusnotification", "callerror")),
    Domain.NETWORK: (("network", "net_", "modem", "ppp", "route", "ethernet"), ("dns", "socket", "connection refused", "tls handshake", "no route")),
}


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: list[ParserPlugin] = []

    def register(self, parser: ParserPlugin) -> None:
        self._parsers.append(parser)

    def select(self, path: Path, sample: str | None = None) -> ParserSelection:
        if sample is None:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                sample = handle.read(65536)
        scores = sorted(
            ((parser, parser.detect(path, sample)) for parser in self._parsers),
            key=lambda item: item[1],
            reverse=True,
        )
        candidates = tuple((parser.name, score) for parser, score in scores if score > 0)
        if not scores or scores[0][1] < 0.35:
            return ParserSelection(None, scores[0][1] if scores else 0.0, candidates)
        return ParserSelection(scores[0][0], scores[0][1], candidates)

    @classmethod
    def default(cls) -> "ParserRegistry":
        registry = cls()
        registry.register(
            FunctionalParser("ocpp_specialized", Domain.OCPP, _specialized_ocpp, parse_ocpp_file)
        )
        registry.register(
            FunctionalParser("vccu_specialized", Domain.ISO15118, _specialized_vccu, parse_vccu_file)
        )
        for domain, (names, content) in DOMAIN_HINTS.items():
            registry.register(
                FunctionalParser(
                    f"{domain.value}_generic",
                    domain,
                    lambda path, sample, n=names, c=content: _score(path, sample, n, c),
                    lambda path, d=domain: parse_domain_file(path, d),
                )
            )
        return registry
