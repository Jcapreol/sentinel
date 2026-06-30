from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import sentinel.web.state as state_mod
from sentinel.web.main import app

if TYPE_CHECKING:
    from sentinel.config import Config


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_sse(text: str) -> list[dict]:  # type: ignore[type-arg]
    """Parse SSE response body into a list of JSON event dicts."""
    events = []
    for line in text.split("\n"):
        if line.startswith("data: "):
            events.append(json.loads(line[6:]))
    return events


_FAKE_VERDICT = {
    "verdict": "Confirmed",
    "confidence_tier": 3,
    "methodology": [{"agent": "watchman", "status": "success", "error": None}],
    "citations": [{"source": "watchman", "finding": "Suspicious outbound traffic detected."}],
    "blind_spots": [],
    "source_independence_confirmed": True,
    "execution_time_seconds": 1.234,
    "timestamp": "2026-06-29T12:00:00+00:00",
}


# ── Demo mode ─────────────────────────────────────────────────────────────────

def test_demo_stream_returns_200(web_client: TestClient) -> None:
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post("/analyze/stream", json={"scenario_slug": "tor-exit-node"})
    assert response.status_code == 200


def test_demo_stream_content_type_is_event_stream(web_client: TestClient) -> None:
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post("/analyze/stream", json={"scenario_slug": "tor-exit-node"})
    assert "text/event-stream" in response.headers["content-type"]


def test_demo_stream_emits_progress_events(web_client: TestClient) -> None:
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post("/analyze/stream", json={"scenario_slug": "google-benign"})
    events = parse_sse(response.text)
    assert any(e.get("type") == "progress" for e in events)


def test_demo_stream_last_event_is_result(web_client: TestClient) -> None:
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post("/analyze/stream", json={"scenario_slug": "ssh-brute-force"})
    events = parse_sse(response.text)
    assert events[-1]["type"] == "result"


def test_demo_stream_result_has_required_verdict_fields(web_client: TestClient) -> None:
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post(
            "/analyze/stream", json={"scenario_slug": "lsass-credential-dumping"}
        )
    events = parse_sse(response.text)
    result_event = next(e for e in events if e["type"] == "result")
    data = result_event["data"]
    for field in (
        "verdict", "confidence_tier", "methodology", "citations",
        "blind_spots", "source_independence_confirmed",
        "execution_time_seconds", "timestamp",
    ):
        assert field in data, f"Missing VerdictSchema field: {field!r}"


@pytest.mark.parametrize(
    "slug, expected_tier",
    [
        ("tor-exit-node", 3),
        ("lsass-credential-dumping", 2),
        ("urlhaus-malware-ip", 3),
        ("ssh-brute-force", 1),
        ("google-benign", 0),
    ],
)
def test_demo_stream_correct_tier_per_slug(
    web_client: TestClient, slug: str, expected_tier: int
) -> None:
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post("/analyze/stream", json={"scenario_slug": slug})
    events = parse_sse(response.text)
    result_event = next(e for e in events if e["type"] == "result")
    assert result_event["data"]["confidence_tier"] == expected_tier


def test_demo_stream_six_progress_steps(web_client: TestClient) -> None:
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post("/analyze/stream", json={"scenario_slug": "tor-exit-node"})
    events = parse_sse(response.text)
    progress_events = [e for e in events if e["type"] == "progress"]
    assert len(progress_events) == 6


# ── Unknown slug ──────────────────────────────────────────────────────────────

def test_unknown_slug_returns_http_200_not_500(web_client: TestClient) -> None:
    response = web_client.post(
        "/analyze/stream", json={"scenario_slug": "not-a-real-scenario"}
    )
    assert response.status_code == 200


def test_unknown_slug_emits_error_event(web_client: TestClient) -> None:
    response = web_client.post(
        "/analyze/stream", json={"scenario_slug": "bogus-slug"}
    )
    events = parse_sse(response.text)
    assert any(e["type"] == "error" for e in events)


def test_unknown_slug_error_event_has_blind_spot_keys(web_client: TestClient) -> None:
    response = web_client.post(
        "/analyze/stream", json={"scenario_slug": "not-real"}
    )
    events = parse_sse(response.text)
    error_events = [e for e in events if e["type"] == "error"]
    assert len(error_events) == 1
    bs = error_events[0]["blind_spot"]
    assert "source" in bs
    assert "reason" in bs
    assert "next_step" in bs


def test_unknown_slug_no_result_event(web_client: TestClient) -> None:
    response = web_client.post(
        "/analyze/stream", json={"scenario_slug": "definitely-bogus"}
    )
    events = parse_sse(response.text)
    assert not any(e["type"] == "result" for e in events)


# ── /quota endpoint ───────────────────────────────────────────────────────────

def test_quota_returns_200(web_client: TestClient) -> None:
    assert web_client.get("/quota").status_code == 200


def test_quota_response_has_remaining_key(web_client: TestClient) -> None:
    data = web_client.get("/quota").json()
    assert "remaining" in data


def test_quota_response_has_limit_key(web_client: TestClient) -> None:
    data = web_client.get("/quota").json()
    assert "limit" in data


def test_quota_limit_is_500(web_client: TestClient) -> None:
    data = web_client.get("/quota").json()
    assert data["limit"] == 500


def test_quota_remaining_is_integer(web_client: TestClient) -> None:
    data = web_client.get("/quota").json()
    assert isinstance(data["remaining"], int)


def test_quota_initial_remaining_equals_limit(web_client: TestClient) -> None:
    state_mod._vt_calls_used = 0
    data = web_client.get("/quota").json()
    assert data["remaining"] == 500


def test_quota_remaining_decrements_when_calls_used(web_client: TestClient) -> None:
    state_mod._vt_calls_used = 3
    data = web_client.get("/quota").json()
    assert data["remaining"] == 497


# ── Error conversion: run_analysis() exception → SSE error event ──────────────

def test_run_analysis_exception_yields_http_200(fake_config: "Config") -> None:
    state_mod._config = fake_config
    with patch("sentinel.web.routes.run_analysis", side_effect=RuntimeError("boom")):
        with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
            with patch("sentinel.web.main.load_config", return_value=fake_config):
                with TestClient(app) as client:
                    response = client.post(
                        "/analyze/stream",
                        json={"alert_text": "suspicious traffic", "scenario_slug": None},
                    )
    assert response.status_code == 200


def test_run_analysis_exception_emits_error_event(fake_config: "Config") -> None:
    state_mod._config = fake_config
    with patch("sentinel.web.routes.run_analysis", side_effect=RuntimeError("api failure")):
        with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
            with patch("sentinel.web.main.load_config", return_value=fake_config):
                with TestClient(app) as client:
                    response = client.post(
                        "/analyze/stream",
                        json={"alert_text": "test alert", "scenario_slug": None},
                    )
    events = parse_sse(response.text)
    assert any(e["type"] == "error" for e in events)


def test_run_analysis_exception_no_raw_exception_type_in_response(
    fake_config: "Config",
) -> None:
    state_mod._config = fake_config
    with patch(
        "sentinel.web.routes.run_analysis",
        side_effect=RuntimeError("internal-secret-value"),
    ):
        with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
            with patch("sentinel.web.main.load_config", return_value=fake_config):
                with TestClient(app) as client:
                    response = client.post(
                        "/analyze/stream",
                        json={"alert_text": "test", "scenario_slug": None},
                    )
    assert "RuntimeError" not in response.text
    assert "internal-secret-value" not in response.text
    assert "Traceback" not in response.text


def test_run_analysis_exception_error_event_has_blind_spot(
    fake_config: "Config",
) -> None:
    state_mod._config = fake_config
    with patch("sentinel.web.routes.run_analysis", side_effect=ValueError("some error")):
        with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
            with patch("sentinel.web.main.load_config", return_value=fake_config):
                with TestClient(app) as client:
                    response = client.post(
                        "/analyze/stream",
                        json={"alert_text": "test alert", "scenario_slug": None},
                    )
    events = parse_sse(response.text)
    error_events = [e for e in events if e["type"] == "error"]
    assert len(error_events) == 1
    bs = error_events[0]["blind_spot"]
    assert "source" in bs
    assert "reason" in bs
    assert "next_step" in bs


def test_missing_config_yields_error_event_not_crash(fake_config: "Config") -> None:
    """Live analysis with no config emits error event rather than 500."""
    state_mod._config = None  # override — no config set
    with patch("sentinel.web.main.load_config", return_value=fake_config):
        with TestClient(app) as client:
            # Override config back to None after lifespan sets it
            state_mod._config = None
            response = client.post(
                "/analyze/stream",
                json={"alert_text": "test", "scenario_slug": None},
            )
    assert response.status_code == 200
    events = parse_sse(response.text)
    assert any(e["type"] == "error" for e in events)
