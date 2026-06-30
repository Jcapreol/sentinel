"""
End-to-end flow tests for sentinel/web — Story 1.6.

These tests exercise the full request lifecycle through FastAPI's TestClient:
  - Complete demo path: POST /analyze/stream → all SSE events → final result
  - Complete live path: POST → run_in_executor bridge → mocked agents → result

They complement the unit-style tests in test_routes.py by verifying the
entire SSE sequence (ordering, completeness, schema) in a single coherent run.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from sentinel.verdict import AgentResult

if TYPE_CHECKING:
    pass


def _parse_sse(text: str) -> list[dict]:  # type: ignore[type-arg]
    events = []
    for line in text.split("\n"):
        if line.startswith("data: "):
            events.append(json.loads(line[6:]))
    return events


_VERDICT_SCHEMA_FIELDS = (
    "verdict",
    "confidence_tier",
    "methodology",
    "citations",
    "blind_spots",
    "source_independence_confirmed",
    "execution_time_seconds",
    "timestamp",
)


# ── Demo E2E: complete SSE sequence ──────────────────────────────────────────

def test_demo_e2e_complete_sse_sequence_tor_exit_node(web_client: TestClient) -> None:
    """End-to-end demo flow for tor-exit-node:
    POST /analyze/stream → 6 progress events (ordered, non-empty text)
    → 1 result event (last) → confidence_tier 3, verdict 'Confirmed'."""
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post(
            "/analyze/stream",
            json={"scenario_slug": "tor-exit-node"},
        )

    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]

    events = _parse_sse(response.text)
    progress_events = [e for e in events if e["type"] == "progress"]
    result_events = [e for e in events if e["type"] == "result"]
    error_events = [e for e in events if e["type"] == "error"]

    # Exactly 6 progress + 1 result, nothing else
    assert len(error_events) == 0
    assert len(progress_events) == 6
    assert len(result_events) == 1
    assert len(events) == 7

    # All progress events have non-empty step text and precede the result
    for i, pe in enumerate(progress_events):
        assert pe.get("step"), f"Progress event {i} has empty or missing step text"
    assert events[-1]["type"] == "result"

    # All VerdictSchema fields present
    data = result_events[0]["data"]
    for field in _VERDICT_SCHEMA_FIELDS:
        assert field in data, f"Missing VerdictSchema field: {field!r}"

    assert data["confidence_tier"] == 3
    assert data["verdict"] == "Confirmed"


@pytest.mark.parametrize(
    "slug, expected_tier, expected_verdict",
    [
        ("tor-exit-node", 3, "Confirmed"),
        ("lsass-credential-dumping", 2, "Probable"),
        ("urlhaus-malware-ip", 3, "Confirmed"),
        ("ssh-brute-force", 1, "Investigating"),
        ("google-benign", 0, "Benign"),
    ],
)
def test_demo_e2e_all_five_scenarios_correct_tier_and_verdict(
    web_client: TestClient,
    slug: str,
    expected_tier: int,
    expected_verdict: str,
) -> None:
    """All five demo scenarios produce the correct tier and verdict string
    when exercised end-to-end through the SSE stream."""
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post(
            "/analyze/stream",
            json={"scenario_slug": slug},
        )

    events = _parse_sse(response.text)
    result_event = next(e for e in events if e["type"] == "result")
    assert result_event["data"]["confidence_tier"] == expected_tier
    assert result_event["data"]["verdict"] == expected_verdict


# ── Live analysis E2E: mocked Watchman + Cipher agents ───────────────────────

def test_live_analysis_e2e_mocked_agents(web_client: TestClient) -> None:
    """Full live-analysis path exercised end-to-end:
    POST /analyze/stream → run_in_executor bridge → mocked WatchmanAgent.analyze
    + mocked CipherAgent.analyze → assemble_verdict() → result SSE event.

    Watchman returns Probable; Cipher returns malicious findings.
    Expected tier: CONFIRMED (3) — cipher malicious + watchman medium."""
    w_result = AgentResult(
        source_name="watchman",
        findings=["Lateral movement via LSASS memory access"],
        blind_spots=[],
        raw_confidence="Probable",
        error=None,
    )
    c_result = AgentResult(
        source_name="cipher",
        findings=[
            "VirusTotal: 185.220.101.45 flagged by 5 engines as malicious, 2 as suspicious",
            "AbuseIPDB: 185.220.101.45 abuse confidence 87% from 12 reports",
        ],
        blind_spots=[],
        raw_confidence=None,
        error=None,
    )

    with patch("sentinel.watchman.WatchmanAgent.analyze", return_value=w_result):
        with patch("sentinel.cipher.CipherAgent.analyze", return_value=c_result):
            with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
                response = web_client.post(
                    "/analyze/stream",
                    json={
                        "alert_text": "Sustained outbound traffic to 185.220.101.45 port 443",
                        "scenario_slug": None,
                    },
                )

    assert response.status_code == 200
    events = _parse_sse(response.text)

    # No error event — both agents succeeded
    assert not any(e["type"] == "error" for e in events)

    result_events = [e for e in events if e["type"] == "result"]
    assert len(result_events) == 1, "Expected exactly one result SSE event"

    data = result_events[0]["data"]

    # All VerdictSchema fields present
    for field in _VERDICT_SCHEMA_FIELDS:
        assert field in data, f"Missing VerdictSchema field: {field!r}"

    # Watchman medium + Cipher malicious → CONFIRMED (tier 3)
    assert data["confidence_tier"] == 3
    assert data["verdict"] == "Confirmed"

    # Both agents appear in methodology
    agents_in_methodology = {m["agent"] for m in data["methodology"]}
    assert "watchman" in agents_in_methodology
    assert "cipher" in agents_in_methodology

    # Citations reflect both agents' findings
    assert len(data["citations"]) >= 3  # 1 watchman + 2 cipher
