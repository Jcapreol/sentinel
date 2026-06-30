"""
Story 2.3 — VirusTotal Quota Badge tests.

Tests are split across two concerns:
  1. Backend contract: demo mode must NOT increment the quota counter.
  2. Static analysis: app.js and index.html implement the quota badge UI per FR25–FR26.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient


_STATIC_DIR = Path(__file__).parent.parent.parent / "static"


def _parse_sse(text: str) -> list[dict]:  # type: ignore[type-arg]
    events = []
    for line in text.split("\n"):
        if line.startswith("data: "):
            events.append(json.loads(line[6:]))
    return events


# ── Backend contract: demo must not consume quota ─────────────────────────────

def test_demo_analysis_does_not_change_quota(web_client: TestClient) -> None:
    """Demo analysis (scenario_slug set) must not increment the VT quota counter."""
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)):
        before = web_client.get("/quota").json()["remaining"]
        web_client.post(
            "/analyze/stream",
            json={"scenario_slug": "tor-exit-node"},
        )
        after = web_client.get("/quota").json()["remaining"]
    assert after == before, (
        "Demo analysis must not consume VirusTotal quota — scenario_slug path skips increment_vt_calls()"
    )


# ── Static analysis: index.html has the quota badge container ─────────────────

def test_index_html_has_quota_badge_container() -> None:
    """index.html contains the quota badge element that app.js populates."""
    html = (_STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert 'id="quota-badge"' in html


# ── Static analysis: app.js implements quota badge fetch and rendering ─────────

def test_app_js_has_update_quota_badge_function() -> None:
    """app.js defines updateQuotaBadge() — fetches /quota and updates the DOM element."""
    app_js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert "function updateQuotaBadge" in app_js


def test_app_js_quota_badge_fetched_on_page_load() -> None:
    """updateQuotaBadge() is called inside the DOMContentLoaded listener (FR25 — visible at all times)."""
    app_js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")
    domload_idx = app_js.find("DOMContentLoaded")
    assert domload_idx != -1, "DOMContentLoaded listener not found"
    tail = app_js[domload_idx:]
    assert "updateQuotaBadge()" in tail, (
        "updateQuotaBadge() must be called in the DOMContentLoaded block to display quota on page load"
    )


def test_app_js_quota_badge_updated_after_live_analysis() -> None:
    """updateQuotaBadge() is called inside handleSubmit() after a live analysis result (FR26)."""
    app_js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")
    fn_idx = app_js.find("async function handleSubmit")
    assert fn_idx != -1, "handleSubmit function not found"
    fn_body = app_js[fn_idx : fn_idx + 5000]
    assert "updateQuotaBadge" in fn_body, (
        "updateQuotaBadge() must be called in handleSubmit() after a live analysis completes"
    )


def test_app_js_quota_badge_not_updated_in_demo_mode() -> None:
    """updateQuotaBadge() is guarded by a scenarioSlug check — not called for demo analyses."""
    app_js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")
    fn_idx = app_js.find("async function handleSubmit")
    assert fn_idx != -1
    fn_body = app_js[fn_idx : fn_idx + 5000]
    update_idx = fn_body.find("updateQuotaBadge")
    assert update_idx != -1
    # The text leading up to updateQuotaBadge must contain a scenarioSlug guard
    context_before = fn_body[:update_idx]
    assert "scenarioSlug" in context_before, (
        "updateQuotaBadge must be guarded by scenarioSlug — demo mode (slug set) must not refresh quota"
    )


def test_app_js_quota_badge_has_warning_visual_state() -> None:
    """Quota badge config defines at least two visual states (healthy + warning) per the spec."""
    app_js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")
    # QUOTA_STATES or similar must define a warning/low/critical state distinct from healthy
    assert "QUOTA_STATES" in app_js or "QUOTA_CONFIG" in app_js, (
        "app.js must define a QUOTA_STATES or QUOTA_CONFIG object"
    )
    # Must have at least one non-healthy label (low or critical)
    assert "low" in app_js.lower() or "critical" in app_js.lower(), (
        "Quota badge must define a warning visual state for low/critical quota"
    )


def test_app_js_render_quota_badge_shows_remaining_and_limit() -> None:
    """renderQuotaBadge() renders both remaining count and limit — value never shown without context."""
    app_js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")
    fn_idx = app_js.find("function renderQuotaBadge")
    assert fn_idx != -1, "renderQuotaBadge function not found"
    fn_body = app_js[fn_idx : fn_idx + 500]
    # Must reference both remaining and limit parameters
    assert "remaining" in fn_body
    assert "limit" in fn_body
