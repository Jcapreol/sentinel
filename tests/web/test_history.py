"""
Story 2.1 — Session History Table tests.

The history feature is client-side (sessionStorage + DOM). These tests verify it
at two levels:
  1. Backend contract: the SSE result event carries every field appendHistory() reads.
  2. Static analysis: app.js and index.html implement the canonical schema, truncation
     limit, column set, and on-load restoration required by the architecture doc.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

if TYPE_CHECKING:
    pass


_STATIC_DIR = Path(__file__).parent.parent.parent / "static"


def _parse_sse(text: str) -> list[dict]:  # type: ignore[type-arg]
    events = []
    for line in text.split("\n"):
        if line.startswith("data: "):
            events.append(json.loads(line[6:]))
    return events


# ── Backend contract: result event provides all history-entry fields ──────────

def test_result_event_provides_confidence_tier(web_client: TestClient) -> None:
    """SSE result event includes confidence_tier — required by canonical history schema."""
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post(
            "/analyze/stream",
            json={"scenario_slug": "tor-exit-node"},
        )
    events = _parse_sse(response.text)
    result = next(e for e in events if e["type"] == "result")
    assert "confidence_tier" in result["data"]
    assert isinstance(result["data"]["confidence_tier"], int)


def test_result_event_provides_execution_time_seconds(web_client: TestClient) -> None:
    """SSE result event includes execution_time_seconds — mapped to execution_time in history."""
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post(
            "/analyze/stream",
            json={"scenario_slug": "google-benign"},
        )
    events = _parse_sse(response.text)
    result = next(e for e in events if e["type"] == "result")
    assert "execution_time_seconds" in result["data"]
    assert isinstance(result["data"]["execution_time_seconds"], float)


def test_result_event_provides_timestamp(web_client: TestClient) -> None:
    """SSE result event includes timestamp — used as the display value in the history row."""
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        response = web_client.post(
            "/analyze/stream",
            json={"scenario_slug": "ssh-brute-force"},
        )
    events = _parse_sse(response.text)
    result = next(e for e in events if e["type"] == "result")
    assert "timestamp" in result["data"]
    ts = result["data"]["timestamp"]
    assert isinstance(ts, str) and len(ts) > 0


# ── Static analysis: app.js implements the canonical history schema ───────────

def test_app_js_truncates_indicator_to_60_chars() -> None:
    """app.js uses slice(0, 60) for the indicator field per the canonical history schema.
    The architecture doc specifies 60, not 80."""
    app_js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert "slice(0, 60)" in app_js, (
        "appendHistory() must truncate indicator to 60 characters (architecture canonical schema)"
    )


def test_app_js_restores_history_on_domcontentloaded() -> None:
    """app.js calls renderHistoryTable() inside the DOMContentLoaded listener
    so history is restored from sessionStorage on page load and after a browser refresh."""
    app_js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")
    domload_idx = app_js.find("DOMContentLoaded")
    assert domload_idx != -1, "DOMContentLoaded listener not found in app.js"
    tail = app_js[domload_idx:]
    assert "renderHistoryTable()" in tail, (
        "renderHistoryTable() must be called in the DOMContentLoaded block to restore history on page load"
    )


def test_app_js_uses_render_tier_badge_in_history_table() -> None:
    """renderHistoryTable() delegates badge rendering to renderTierBadge() —
    no separate badge logic, as required by the architecture anti-pattern rule."""
    app_js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")
    fn_idx = app_js.find("function renderHistoryTable")
    assert fn_idx != -1, "renderHistoryTable function not found in app.js"
    fn_body = app_js[fn_idx:fn_idx + 2000]
    assert "renderTierBadge" in fn_body, (
        "renderHistoryTable() must call renderTierBadge() — no inline color/label strings"
    )


# ── Static analysis: index.html has the history table with correct columns ───

def test_index_html_has_history_panel() -> None:
    """index.html contains the session history panel element."""
    html = (_STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert "history-panel" in html, "index.html must contain id='history-panel'"


def test_history_table_has_timestamp_column() -> None:
    """History table includes a Timestamp column header."""
    html = (_STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert "Timestamp" in html


def test_history_table_has_indicator_column() -> None:
    """History table includes an Indicator column header."""
    html = (_STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert "Indicator" in html


def test_history_table_has_tier_column() -> None:
    """History table includes a Tier column header."""
    html = (_STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert "Tier" in html
