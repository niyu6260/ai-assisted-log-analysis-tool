from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from ccu_log_diag.generalization import AutomaticTriage
from ccu_log_diag.model.events import Event


TOKEN = re.compile(r"[A-Za-z0-9_./:-]{2,}|[\u4e00-\u9fff]{2,}")


@dataclass(frozen=True)
class KnowledgeChunk:
    source: str
    section: str
    text: str


class KnowledgeIndex:
    def __init__(self, chunks: list[KnowledgeChunk]):
        self.chunks = chunks

    @classmethod
    def load(cls, root: Path) -> "KnowledgeIndex":
        chunks: list[KnowledgeChunk] = []
        for path in sorted(root.rglob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            for section, text in _flatten(data):
                if text.strip():
                    chunks.append(
                        KnowledgeChunk(
                            source=str(path.relative_to(root).as_posix()),
                            section=section,
                            text=text[:4000],
                        )
                    )
        return cls(chunks)

    def retrieve(self, query: str, *, limit: int = 8) -> list[KnowledgeChunk]:
        query_tokens = {token.casefold() for token in TOKEN.findall(query)}
        ranked: list[tuple[int, KnowledgeChunk]] = []
        for chunk in self.chunks:
            chunk_tokens = {
                token.casefold()
                for token in TOKEN.findall(
                    f"{chunk.section} {chunk.text}"
                )
            }
            score = len(query_tokens.intersection(chunk_tokens))
            if score:
                ranked.append((score, chunk))
        return [
            chunk
            for _, chunk in sorted(
                ranked,
                key=lambda item: (item[0], item[1].source, item[1].section),
                reverse=True,
            )[:limit]
        ]


def _flatten(value: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            section = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten(item, section)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _flatten(item, f"{prefix}[{index}]")
    elif value is not None:
        yield prefix, str(value)


class OpenAICompatibleClient:
    def __init__(
        self,
        endpoint: str,
        model: str,
        *,
        api_key: str | None = None,
        timeout_seconds: int = 90,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def complete_json(self, system: str, payload: dict[str, Any]) -> dict[str, Any]:
        request_body = json.dumps(
            {
                "model": self.model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {
                        "role": "user",
                        "content": json.dumps(payload, ensure_ascii=False),
                    },
                ],
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(
            f"{self.endpoint}/chat/completions",
            data=request_body,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(
            request,
            timeout=self.timeout_seconds,
        ) as response:
            data = json.loads(response.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        return json.loads(content)


SYSTEM_PROMPT = """You are an evidence-bound charger diagnostic assistant.
Return JSON only. You may rank or explain hypotheses, but every positive claim
must cite event IDs present in allowed_event_ids. Never invent protocol values,
timestamps, or evidence. Use conclusion_status confirmed only for a complete
causal chain, probable for narrowed but incomplete evidence, and inconclusive
when primary proof is missing. Return: conclusion_status, affected_domains,
root_cause_candidates (category, explanation, confidence, evidence_event_ids),
missing_evidence, recommended_actions."""


def build_assistant_payload(
    triage: AutomaticTriage,
    events: list[Event],
    knowledge: KnowledgeIndex,
) -> dict[str, Any]:
    event_by_id = {event.id: event for event in events}
    selected_ids = list(
        dict.fromkeys(
            event_id
            for candidate in triage.root_cause_ranking[:5]
            for event_id in candidate.evidence_event_ids
        )
    )[:100]
    if not selected_ids:
        selected_ids = list(
            dict.fromkeys(
                event_id
                for window in triage.incident_windows[:3]
                for event_id in window.evidence_event_ids
            )
        )[:100]
    selected_events = [
        {
            "event_id": event.id,
            "timestamp": event.ts_utc,
            "domain": event.domain.value,
            "type": event.type.value,
            "summary": event.summary,
            "attrs": event.attrs,
        }
        for event_id in selected_ids
        if (event := event_by_id.get(event_id)) is not None
    ]
    query = " ".join(
        [
            *(item["summary"] for item in selected_events),
            *(
                candidate.root_cause_category
                for candidate in triage.root_cause_ranking[:5]
            ),
        ]
    )
    chunks = knowledge.retrieve(query)
    return {
        "allowed_event_ids": [item["event_id"] for item in selected_events],
        "events": selected_events,
        "deterministic_triage": triage.to_dict(),
        "knowledge": [
            {
                "source": chunk.source,
                "section": chunk.section,
                "text": chunk.text,
            }
            for chunk in chunks
        ],
    }


def validate_assistant_output(
    output: dict[str, Any],
    allowed_event_ids: Iterable[str],
) -> dict[str, Any]:
    allowed = set(allowed_event_ids)
    status = output.get("conclusion_status")
    if status not in {"confirmed", "probable", "inconclusive"}:
        raise ValueError("Invalid conclusion_status")
    candidates = output.get("root_cause_candidates", [])
    if not isinstance(candidates, list):
        raise ValueError("root_cause_candidates must be a list")
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            raise ValueError(f"root_cause_candidates[{index}] must be an object")
        citations = candidate.get("evidence_event_ids", [])
        invalid = set(citations) - allowed
        if invalid:
            raise ValueError(
                "Assistant cited unknown event IDs: " + ", ".join(sorted(invalid))
            )
        if status != "inconclusive" and not citations:
            raise ValueError("Positive conclusions require event citations")
    return output
