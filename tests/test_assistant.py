from __future__ import annotations

import pytest

from ccu_log_diag.assistant import validate_assistant_output


def _output(event_id: str = "evt-1") -> dict[str, object]:
    return {
        "summary": "The network path failed.",
        "conclusions": [
            {
                "claim": "The backend connection timed out.",
                "status": "confirmed",
                "confidence": 0.9,
                "evidence_event_ids": [event_id],
            }
        ],
        "next_actions": ["Test the target TCP port."],
    }


def test_assistant_output_requires_known_event_citations() -> None:
    validate_assistant_output(_output(), {"evt-1"})
    with pytest.raises(ValueError, match="unknown event ids"):
        validate_assistant_output(_output("invented-event"), {"evt-1"})


def test_positive_assistant_conclusion_requires_evidence() -> None:
    output = _output()
    output["conclusions"][0]["evidence_event_ids"] = []  # type: ignore[index]
    with pytest.raises(ValueError, match="must cite evidence"):
        validate_assistant_output(output, {"evt-1"})
