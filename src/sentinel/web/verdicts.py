"""Read-only live verdict list and detail views (Story 10.1, styled and
timezone-aware per Story 10.2, chrome/summary/health status per Story 10.3,
labelling per Story 11.1, navigation/save-affordance/dark theme per Story
11.2).

Reads exclusively through sentinel.triage.store's existing, validated,
read-only functions -- no direct sqlite3 or Fernet usage anywhere in this
module (AC1), enforced by test_web_imports_no_direct_db_or_crypto_access,
which mirrors triage/'s existing smtplib-ban structural test. The header
bar's status indicator (Story 10.3) reads sentinel.triage.health's own
JSON-file read function the same way -- no new file-parsing logic here.

Renders its own minimal HTML, entirely independent of demo.py/routes.py's
SSE+JSON rendering path (AC5, D5): the demo route never touches a real
evidence record, and these routes never touch a demo fixture, so there is
no shared renderer to drift between the two.

Every value pulled from a stored record is attacker-influenced (an email's
sender display name, a finding's text, a coverage-gap reason all
ultimately derive from message content Sentinel does not control) and is
therefore escaped at render time via _esc, without exception -- including
fields that look server-controlled, so no future field is accidentally
exempted (Notes for dev, AC6). Story 10.2's CSS badges/classes derive from
the same escaped values (verdict, direction) for exactly the same reason:
a malformed-but-decryptable record's verdict/direction is only guaranteed
to be a present key, never a value drawn from the expected Literal (see
_format_confidence's docstring below for the identical gap already found
in calibrated_confidence during Story 10.1's review). Story 11.2's `back`
query param (AC1, navigation) is the same kind of attacker-adjacent input
by a different route -- a query string, not a stored record -- and gets
the identical treatment: escaped wherever it reaches an href, never
trusted to be well-formed.
"""

from __future__ import annotations

import asyncio
import html
import sys
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import parse_qsl, quote
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from sentinel.config import ConfigError
from sentinel.triage.health import HealthState, try_load_health_state
from sentinel.triage.store import EvidenceRecord, read_recent_evidence_records
from sentinel.web import state
from sentinel.web.labels import VALID_LABELS, Label, LabelEntry, load_labels, save_label

router = APIRouter()

Verdict = Literal["Malicious", "Benign", "Deferred", "CoverageGap"]
LabelFilter = Literal["confirmed-phishing", "confirmed-benign", "unclear", "unlabelled"]
_VALID_VERDICTS: tuple[Verdict, ...] = ("Malicious", "Benign", "Deferred", "CoverageGap")

# [Story 10.2, AC3] Hardcoded to US Eastern for this dashboard's current
# audience (Notes for dev: a CS instructor, eventually a small business
# owner -- both Eastern). Storage (report["timestamp"]) stays UTC,
# unconditionally, everywhere else in the codebase; this constant exists
# ONLY to drive the display-layer conversion in this module. Would need to
# become a per-viewer or config-driven setting if this dashboard is ever
# used by someone outside Eastern time -- no such mechanism exists yet.
_DISPLAY_TIMEZONE = ZoneInfo("America/New_York")

# [Story 11.2, AC4] Dark theme, one theme, not a toggle (Notes for dev: "the
# audience is a CS instructor and eventually a small business owner -- clean
# and legible beats designed"). Every color is a custom property here, none
# scattered as a literal elsewhere in this file (Notes for dev: "grep for
# them rather than assuming the theme swap is complete" -- the light-theme
# version of this file had exactly two literal hex values outside :root,
# `background: #ffffff` on body and `color: #ffffff` on the label-form
# button, both invisible to a palette swap until they were found and moved
# in here too). Inline, not served: keeps the whole feature -- every escape
# point, every style rule -- auditable in this one module, and needs no new
# route/static-file surface. No CDN, no build step, no framework -- plain
# CSS custom properties, flexbox, and grid.
_STYLE = """
:root {
  --bg: #14161f;
  --surface: #1c1f2b;
  --row-alt: #1f2331;
  --border: #2d3142;
  --fg: #e8eaf2;
  --muted: #8b90a8;
  --dim: #6d7290;
  --accent: #f0b429;
  --link: #f0b429;
  --button-text: #14161f;

  --malicious-fg: #ff6b6b; --malicious-bg: rgba(255, 107, 107, 0.13);
  --deferred-fg: #f0b429; --deferred-bg: rgba(240, 180, 41, 0.13);
  --benign-fg: #4ecdc4; --benign-bg: rgba(78, 205, 196, 0.13);
  --coveragegap-fg: #8b90a8; --coveragegap-bg: #262a38;
  --neutral-fg: #8b90a8; --neutral-bg: #262a38;
}
* { box-sizing: border-box; }
body {
  max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem 4rem;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 16px; line-height: 1.5; color: var(--fg); background: var(--bg);
}
h1 { font-size: 1.5rem; margin: 0 0 1rem; }
a { color: var(--link); }
.app-header {
  display: flex; justify-content: space-between; align-items: center;
  flex-wrap: wrap; gap: 0.5rem;
  padding-bottom: 1rem; margin-bottom: 1.5rem; border-bottom: 2px solid var(--border);
}
.app-name {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  text-transform: uppercase; letter-spacing: 0.14em;
  font-weight: 700; font-size: 1.1rem; color: var(--accent); text-decoration: none;
}
.back-link { display: inline-block; margin-bottom: 1rem; }
.flash {
  border-radius: 6px; padding: 0.6rem 1rem; margin-bottom: 1rem; font-weight: 600;
}
.flash-success { background: var(--benign-bg); color: var(--benign-fg); }
.flash-error { background: var(--malicious-bg); color: var(--malicious-fg); }
.metrics { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 1.25rem; }
.metric-card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  padding: 0.7rem 1rem; min-width: 96px;
}
.metric-value {
  display: block; font-size: 1.5rem; font-weight: 700; color: var(--fg);
  font-variant-numeric: tabular-nums;
}
.metric-value-malicious { color: var(--malicious-fg); }
.metric-value-benign { color: var(--benign-fg); }
.metric-value-deferred { color: var(--deferred-fg); }
.metric-value-coveragegap { color: var(--coveragegap-fg); }
.filters { margin-bottom: 1.5rem; }
.filters a { margin-right: 0.9rem; text-decoration: none; }
.filters strong { color: var(--fg); }
.table-surface {
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  overflow-x: auto; margin-bottom: 1rem;
}
table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
th, td {
  text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border);
  overflow-wrap: break-word;
}
th, .metric-label {
  font-weight: 600; color: var(--muted); text-transform: uppercase;
  font-size: 11px; letter-spacing: 0.06em;
}
.metric-label { display: block; margin-bottom: 0.25rem; }
.ts-cell { white-space: nowrap; }
tbody tr:nth-child(even) { background: var(--row-alt); }
.summary { margin-top: 1rem; color: var(--muted); font-size: 0.9rem; }
.badge {
  display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px;
  font-size: 0.8rem; font-weight: 600; white-space: nowrap;
}
.badge-malicious { background: var(--malicious-bg); color: var(--malicious-fg); }
.badge-benign { background: var(--benign-bg); color: var(--benign-fg); }
.badge-deferred { background: var(--deferred-bg); color: var(--deferred-fg); }
.badge-coveragegap { background: var(--coveragegap-bg); color: var(--coveragegap-fg); }
.badge-neutral { background: var(--neutral-bg); color: var(--neutral-fg); }
.badge-healthy { background: var(--benign-bg); color: var(--benign-fg); }
.badge-unhealthy { background: var(--malicious-bg); color: var(--malicious-fg); }
.badge-unknown { background: var(--neutral-bg); color: var(--neutral-fg); }
.badge-confirmed-phishing { background: var(--malicious-bg); color: var(--malicious-fg); }
.badge-confirmed-benign { background: var(--benign-bg); color: var(--benign-fg); }
.badge-unclear { background: var(--deferred-bg); color: var(--deferred-fg); }
.unlabelled { color: var(--dim); }
.meta { color: var(--muted); margin: 0.3rem 0; }
.crosstab { margin: 0; font-size: 0.9rem; }
.crosstab caption {
  text-align: left; font-weight: 600; padding: 0.75rem 0.75rem 0.4rem; color: var(--fg);
}
.label-form {
  border: 1px solid var(--border); border-radius: 6px; background: var(--surface);
  padding: 0.9rem 1rem; margin: 1rem 0; max-width: 480px;
}
.label-form label { display: block; font-weight: 600; margin-bottom: 0.3rem; font-size: 0.85rem; }
.label-form select, .label-form textarea {
  width: 100%; font: inherit; padding: 0.4rem; margin-bottom: 0.75rem;
  border: 1px solid var(--border); border-radius: 4px;
  background: var(--bg); color: var(--fg);
}
.label-form textarea { min-height: 4rem; resize: vertical; }
.label-form button {
  font: inherit; font-weight: 600; padding: 0.4rem 1rem; border-radius: 4px;
  border: 1px solid var(--accent); background: var(--accent); color: var(--button-text);
  cursor: pointer;
}
.evidence-list { list-style: none; margin: 1rem 0 0; padding: 0; }
.evidence-item {
  background: var(--surface); border-left: 3px solid var(--border); border-radius: 0;
  padding: 0.9rem 1rem; margin-bottom: 0.75rem;
}
.evidence-item-malicious { border-left-color: var(--malicious-fg); }
.evidence-item-benign { border-left-color: var(--benign-fg); }
.evidence-item-neutral { border-left-color: var(--neutral-fg); }
.evidence-header {
  display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;
  margin-bottom: 0.5rem;
}
.evidence-name {
  font-weight: 600; font-size: 0.9rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.evidence-weight {
  color: var(--muted); font-size: 0.85rem; margin-left: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-variant-numeric: tabular-nums;
}
.evidence-finding { margin: 0; overflow-wrap: break-word; color: var(--fg); }
"""


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _badge(label: object, extra_text: str | None = None) -> str:
    """AC4 (Story 10.2)/AC2 (Story 10.3): verdict/direction/status rendered
    as a colored badge -- color is a supplementary signal only, the
    escaped text is always present, never replaced by color/icon alone.
    The CSS class slug is derived from `label` alone, so an unexpected/
    malformed verdict or direction (see module docstring) just falls back
    to an unstyled badge (no matching CSS rule) rather than crashing or
    reaching an attribute unescaped -- `_esc` covers both the visible text
    and the class slug.

    [Story 10.3, AC4] `extra_text`, when given, is appended to the visible
    text (space-separated) WITHOUT affecting the CSS class slug, which
    stays derived from `label` alone -- lets the verdict badge show
    "Malicious 1.00" (confidence folded in) while still keying its color
    off "Malicious" alone, and lets the header status badge show
    "Healthy — last poll ..." while keying color off "Healthy" alone.

    [Review, Edge Case Hunter] Whitespace is stripped from the slug (all
    of it, not just leading/trailing -- `"".join(...split())`) before
    escaping: HTML treats whitespace as the class-list delimiter, so an
    unescaped-by-design space in a malformed value (e.g. "malicious x")
    would otherwise produce class="badge badge-malicious x" -- three real
    tokens, one of which (badge-malicious) is a genuine, defined CSS rule
    that would spuriously color the badge as Malicious for a value that
    isn't. Not an injection (the attribute itself can't be broken out of
    either way), but it actively defeats "color is a supplementary signal
    only" for that one malformed case, which is worth closing."""
    text = _esc(label)
    if extra_text is not None:
        text = f"{text} {_esc(extra_text)}"
    slug = _esc("".join(str(label).lower().split()))
    return f'<span class="badge badge-{slug}">{text}</span>'


def _format_display_timestamp(timestamp: object) -> str:
    """AC1/AC2: converts a stored UTC timestamp to US Eastern, DST-correct
    (zoneinfo + "America/New_York", not a fixed offset -- the store spans
    months, so a fixed offset would be wrong for some records), 12-hour
    clock, e.g. "Aug 20, 2026 3:10 PM". Storage is untouched; this is a
    display-layer conversion only. Hour is computed manually (`hour % 12
    or 12`) rather than via a no-leading-zero strftime code -- %-I/%#I are
    platform-specific (glibc vs. Windows) and neither is portable.

    Accepts `object`, not `str`: read_recent_evidence_records only
    guarantees "timestamp" is a present key, never that it's a parseable
    ISO 8601 string (same well-formedness gap _format_confidence's
    docstring documents for calibrated_confidence). A malformed value
    falls back to the raw stringified value rather than crashing the
    route with an uncaught exception.

    [Review, Blind Hunter] OverflowError, not just ValueError/TypeError:
    a UTC timestamp near datetime.min (year 1) in winter converts to a
    negative-year Eastern local time, which astimezone() cannot represent
    and raises OverflowError instead of ValueError -- confirmed reachable
    with '0001-01-01T00:00:00'. Same "requires a corrupted, hand-edited
    record" reachability as every other gap in this file, but the fix is
    one word and keeps this function's own "never crashes" claim true.

    [Story 10.3] Also used for health_state.json's last_success_utc (AC1)
    -- that value is written by save_health_state as datetime.isoformat()
    (health.py), the same shape report["timestamp"] uses, so this function
    is shared rather than duplicated for the two callers.

    [Story 11.2, AC5] The list route's Timestamp column got a `white-space:
    nowrap` CSS treatment (`.ts-cell`) rather than a shorter format here --
    this function is already DST-verified and shared with the header's
    health-status line; changing its output format would mean re-verifying
    both callers instead of adding one CSS rule."""
    try:
        dt = datetime.fromisoformat(str(timestamp))
    except (ValueError, TypeError):
        return str(timestamp)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        local = dt.astimezone(_DISPLAY_TIMEZONE)
    except OverflowError:
        return str(timestamp)
    date_part = local.strftime("%b %d, %Y")
    hour_12 = local.hour % 12 or 12
    minute = local.strftime("%M")
    am_pm = local.strftime("%p")
    return f"{date_part} {hour_12}:{minute} {am_pm}"


def _render_header(health: HealthState | None) -> str:
    """[Story 10.3, AC1/AC2/AC6] Header bar with product name and a live
    status indicator, shared by both routes.

    `health` is None specifically when the state cannot be determined at
    all -- the server has no config to locate health_state.json from, or
    try_load_health_state found the file missing/unreadable/corrupt/
    malformed (health.py's own docstring: "possibly mid-write, possibly
    absent, possibly stale" per this story's Notes for dev). That is
    distinct from a successfully-read file whose values happen to be
    {"last_success_utc": None, "alert_active": False} (a genuinely fresh
    deployment) -- AC6 wants the FIRST case shown as "Unknown", not
    silently rendered as "Healthy" just because both cases share a
    similar-looking default. See try_load_health_state's own docstring
    in health.py for why this distinction needed a new function there.

    AC2: alert_active is the sole discriminator between Healthy/Unhealthy
    (not last_success_utc) -- a poll that has NEVER succeeded still
    alerts immediately per health.py's own _threshold_exceeded, and that
    Unhealthy signal must not be softened into "Unknown" just because
    there's no timestamp to show yet."""
    if health is None:
        status = _badge("Unknown")
    elif health["alert_active"]:
        if health["last_success_utc"] is not None:
            extra = f"— last successful poll {_format_display_timestamp(health['last_success_utc'])}"
        else:
            extra = "— no successful poll recorded"
        status = _badge("Unhealthy", extra)
    else:
        if health["last_success_utc"] is not None:
            extra = f"— last poll {_format_display_timestamp(health['last_success_utc'])}"
        else:
            extra = "— no successful poll recorded yet"
        status = _badge("Healthy", extra)
    return f'<header class="app-header"><a class="app-name" href="/verdicts">Sentinel</a>{status}</header>'


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{_esc(title)}</title><style>{_STYLE}</style>"
        f"</head><body>{body}</body></html>",
        status_code=status_code,
    )


def _load_records() -> tuple[list[tuple[str, EvidenceRecord]] | None, str | None]:
    """Synchronous by design -- disk I/O plus a Fernet decrypt per row.
    Every caller must bridge this through loop.run_in_executor (see the
    route handlers below), never call it directly from an async def, per
    project-context.md's async<->sync FastAPI rule.

    Returns (records, error_message) -- exactly one is non-None. Never
    raises: a missing/misconfigured encryption key or an unreadable
    database file are both reported as a clean message (matching worker.py's
    run_view "must never crash" convention), not a 500 traceback. Catches
    Exception broadly rather than sqlite3.OperationalError specifically so
    this module never needs `import sqlite3` at all -- AC1 bans it outright,
    not just direct connection use."""
    config = state._config
    if config is None:
        return None, "Server is not configured — required environment variables are missing."
    try:
        records, _skipped = read_recent_evidence_records(config.evidence_db_path, config)
    except ConfigError as exc:
        return None, str(exc)
    except Exception as exc:
        print(f"[sentinel-web] Evidence store read error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None, "Could not read the evidence database — check server logs for details."
    return records, None


def _load_health_status() -> HealthState | None:
    """[Story 10.3, AC1/AC6] Synchronous by design -- reads and parses a
    small local JSON file (health.py's own _health_state_path, a sibling
    of evidence.db). Bridged through loop.run_in_executor in both routes,
    like _load_records, for the same async<->sync reason -- even though
    this specific read is far cheaper than decrypting the evidence store,
    it is still blocking file I/O and the project's own FastAPI rule
    doesn't carve out an exception for "small" reads.

    Returns None when status can't be determined at all: no config to
    locate the file from (state._config is None), or
    try_load_health_state itself found the file missing/unreadable/
    corrupt (see that function's own docstring in health.py). _render_header
    renders both as "Unknown" (AC6)."""
    config = state._config
    if config is None:
        return None
    return try_load_health_state(config.evidence_db_path)


def _load_labels_safe() -> dict[str, LabelEntry]:
    """[Story 11.1] Synchronous by design -- reads and parses labels.json
    (a small local file, sibling of evidence.db). Bridged through
    loop.run_in_executor in both routes, like _load_records and
    _load_health_status, for the same async<->sync reason.

    Returns {} when there is no config to locate the file from --
    load_labels itself already never raises for a missing/corrupt file
    (see its own docstring), so the only extra case here is "no Config at
    all", mirroring _load_records/_load_health_status's identical guard."""
    config = state._config
    if config is None:
        return {}
    return load_labels(config.evidence_db_path, config)


def _format_confidence(confidence: object, decimals: int = 3) -> str:
    """[Review, Blind Hunter] read_recent_evidence_records' well-formedness
    check only guarantees calibrated_confidence is a PRESENT key, never
    that its value is actually numeric -- a row that decrypts successfully
    but carries a corrupted/malformed payload (requires already holding
    the real Fernet key; not attacker-reachable without that, but a real
    robustness gap in a "never crashes on a malformed record" module) could
    previously reach f"{confidence:.3f}" with a non-numeric value and raise
    an uncaught ValueError -- a 500, contradicting this module's own design
    intent. "N/A" is the correct display either way: it means "no usable
    confidence value," true whether that's because none was ever computed
    (CoverageGap, the common case) or because the stored value is corrupt
    (rare, but no longer a crash). isinstance(x, bool) is excluded even
    though bool is an int subclass -- a boolean was never a valid
    confidence value, formatting one as "1.000" would be misleading.

    [Story 10.3, AC4] `decimals` defaults to 3 (the detail route's
    "Confidence: 0.920" line, unchanged from Story 10.2) but the list
    route's verdict badge uses 2, matching AC4's own worked example
    ("Malicious 1.00") -- a compact chip reads better with one digit
    fewer than a dedicated line-item."""
    if isinstance(confidence, bool):
        return "N/A"
    if isinstance(confidence, (int, float)):
        return f"{confidence:.{decimals}f}"
    return "N/A"


def _is_well_formed_evidence_item(item: object) -> bool:
    """[Review, Blind Hunter] Mirrors store.py's own
    _is_well_formed_evidence_record philosophy -- skip a malformed unit
    wholesale and report a count, rather than partially rendering it or
    crashing. Needed because read_recent_evidence_records validates that
    report["evidence"] is present, never that each ITEM within it has all
    four required keys with the right types; a missing key (e.g. no
    "weight") would otherwise raise an uncaught KeyError in the render
    loop below."""
    return (
        isinstance(item, dict)
        and item.keys() >= {"name", "finding", "weight", "direction"}
        and isinstance(item.get("weight"), (int, float))
        and not isinstance(item.get("weight"), bool)
    )


def _evidence_item_class(direction: object) -> str:
    """[Story 11.2, AC4] "Evidence cards ... left border 3px in the
    finding's direction colour". Mirrors _badge's own defensive slugging
    (escape, lowercase, strip whitespace) for the identical reason:
    _is_well_formed_evidence_item validates that "direction" is a present
    key with the right structural shape, never that its VALUE is one of
    the three real directions -- a malformed item could carry an
    unrecognized string here. An unrecognized slug just matches no
    .evidence-item-{slug} rule, leaving the base .evidence-item's default
    border-left color -- never a crash, never an unescaped class name."""
    slug = _esc("".join(str(direction).lower().split()))
    return f"evidence-item evidence-item-{slug}"


def _sender_display(sender: str | None) -> str:
    """[Story 10.3, AC5] CoverageGap records have sender: null by design
    (Story 6.1 -- the message itself could never be fetched, so there was
    never a sender to read). A clear, explicit placeholder, not an empty
    cell that could read as a rendering bug."""
    return sender if sender is not None else "Message unavailable (coverage gap)"


def _filter_query(verdict: str | None, label: str | None) -> str:
    """[Story 11.1] Shared by both filter-link rows so the verdict and
    label filters combine rather than clobber each other -- clicking a
    verdict link while a label filter is active must keep the label
    filter in the resulting URL, and vice versa (e.g. "show me all Benign
    records labelled confirmed-phishing", exactly the kind of query this
    story exists to make possible)."""
    params = []
    if verdict is not None:
        params.append(f"verdict={verdict}")
    if label is not None:
        params.append(f"label={label}")
    return "?" + "&".join(params) if params else ""


def _back_value(verdict: str | None, label: str | None) -> str:
    """[Story 11.2, AC1] The raw (unencoded) query string representing the
    list view's currently active filters, e.g. "verdict=Deferred" or
    "verdict=Deferred&label=unclear" or "" for no filter -- reuses
    _filter_query's exact same construction (stripping its leading "?")
    rather than a second, parallel implementation. This is the value
    embedded as the `back` query PARAM on every detail-page link, so the
    detail view can reconstruct "return to the list exactly as the reader
    left it" (AC1's own example: arriving via ?verdict=Deferred must not
    return to an unfiltered list). Callers embedding this as another URL's
    query VALUE must percent-encode it (urllib.parse.quote(..., safe=""))
    -- it contains "&"/"=" characters that are only safe as the FINAL
    query string of a URL, not as one param's value within another."""
    return _filter_query(verdict, label).removeprefix("?")


def _back_link_href(back: str | None) -> str:
    """[Story 11.2, AC1] The inverse of _back_value: given the (already
    URL-decoded, by FastAPI's own query-param parsing) `back` value a
    detail-page route received, builds the href that returns to the list
    with that exact filter state. No validation beyond escaping -- an
    unexpected/malformed `back` can only ever become the query STRING of
    the hardcoded /verdicts path (never the scheme/host/path themselves),
    so there is no open-redirect surface regardless of its content; at
    worst a malformed `back` produces a /verdicts?<garbage> link that
    FastAPI's own query validation on that route already rejects
    cleanly (422) or ignores (unrecognized param names)."""
    return f"/verdicts?{back}" if back else "/verdicts"


def _filter_links(active_verdict: str | None, active_label: str | None) -> str:
    options: list[tuple[str, str | None]] = [("All", None)]
    options += [(v, v) for v in _VALID_VERDICTS]
    parts = []
    for display, value in options:
        is_active = active_verdict == value
        text = f"<strong>{_esc(display)}</strong>" if is_active else _esc(display)
        href = f"/verdicts{_filter_query(value, active_label)}"
        parts.append(f'<a href="{_esc(href)}">{text}</a>')
    return '<div class="filters">' + " | ".join(parts) + "</div>"


def _label_filter_links(active_verdict: str | None, active_label: str | None) -> str:
    """[Story 11.1, AC5] "Unlabelled" is deliberately a real filter option,
    not just the three stored label values -- Notes for dev: alerted
    records get reviewed, quiet Benign records do not, and that sampling
    bias is exactly what hid the auth-alignment finding. Filtering to
    Unlabelled is how a reviewer deliberately reaches records nothing
    would otherwise draw them to."""
    options: list[tuple[str, str | None]] = [("All", None)]
    options += [(v, v) for v in VALID_LABELS]
    options.append(("Unlabelled", "unlabelled"))
    parts = []
    for display, value in options:
        is_active = active_label == value
        text = f"<strong>{_esc(display)}</strong>" if is_active else _esc(display)
        href = f"/verdicts{_filter_query(active_verdict, value)}"
        parts.append(f'<a href="{_esc(href)}">{text}</a>')
    return '<div class="filters">' + " | ".join(parts) + "</div>"


def _summary_strip(records: list[tuple[str, EvidenceRecord]]) -> str:
    """[Story 10.3, AC3/AC7] Total record count and a per-verdict
    breakdown, computed from the SAME already-decrypted `records` list the
    list route builds its table from -- not a second store read. AC7
    asked, explicitly, whether counting forces decrypting every record: it
    does (verdict lives only inside the Fernet-encrypted blob, not a plain
    SQL column -- read_recent_evidence_records' own docstring), but the
    list route already pays that cost once per page load to render the
    table itself, so this is a single O(n) pass over data already in
    memory, not an additional decrypt pass. Measured empirically before
    implementing: 188 real local records ~8.7ms, 900 synthetic records
    (this story's own cited scale) ~14ms end-to-end for the full decrypt
    -- not a performance problem today. If the store grows enough that
    even the base list-page decrypt becomes slow, the fix would be adding
    a plain-text `verdict` SQL column (verdict alone isn't sensitive
    content, unlike sender/finding text) so COUNT/GROUP BY could run
    without touching Fernet at all -- a real schema migration, out of
    scope for a presentation-only story and not justified by today's
    numbers. Always computed from the FULL, unfiltered list (called
    before any ?verdict= filtering in verdict_list) so the strip is a
    stable overview, not a number that changes confusingly as the filter
    changes.

    [Story 11.2, AC5] Rendered as metric cards (small uppercase label,
    larger number below) rather than inline badge pills -- the previous
    pill rendering read as the same kind of element as the filter links
    directly beneath it, with no visual separation between "here is a
    count" and "here is a link." Each card's number is colored per
    verdict (reusing the same semantic palette as the badges) except
    Total, which stays neutral -- it isn't one of the four verdict
    buckets."""
    counts: dict[str, int] = {v: 0 for v in _VALID_VERDICTS}
    for _message_hash, record in records:
        verdict = record["report"]["verdict"]
        # [Review, Blind Hunter] isinstance check first: well-formedness
        # only guarantees "verdict" is a present key, never that its value
        # is a string -- a decrypted-but-corrupted record could have it be
        # a list or dict, and `verdict in counts` on an unhashable value
        # raises TypeError uncaught, crashing the entire list route (every
        # visitor, not just a request touching that one record, since this
        # runs unconditionally over the full, unfiltered list). Every
        # other malformed-value path in this file already degrades safely
        # (_badge stringifies via _esc/str(), _format_confidence type-
        # checks) -- this one didn't, and it's now the only one that does.
        if isinstance(verdict, str) and verdict in counts:
            counts[verdict] += 1
        # else: malformed verdict value (see module docstring) -- still
        # counted in the total below, just not attributable to any known
        # per-verdict bucket.
    cards = [
        '<div class="metric-card"><span class="metric-label">Total</span>'
        f'<span class="metric-value">{len(records)}</span></div>'
    ]
    for v in _VALID_VERDICTS:
        slug = _esc("".join(v.lower().split()))
        cards.append(
            '<div class="metric-card">'
            f'<span class="metric-label">{_esc(v)}</span>'
            f'<span class="metric-value metric-value-{slug}">{counts[v]}</span>'
            "</div>"
        )
    return '<div class="metrics">' + "".join(cards) + "</div>"


def _label_display(entry: LabelEntry | None) -> str:
    """[Story 11.1, AC5] Plain, muted text for "no label" -- not a colored
    badge, matching the existing convention that a missing value (e.g.
    _sender_display's CoverageGap placeholder) reads as a placeholder,
    not a chip suggesting a real, positive value."""
    if entry is None:
        return '<span class="unlabelled">Unlabelled</span>'
    return _badge(entry["label"])


def _label_verdict_crosstab(
    records: list[tuple[str, EvidenceRecord]], labels: dict[str, LabelEntry]
) -> str:
    """[Story 11.1, AC6] The point of the story: turns "here are five
    examples" into a number. Rows are label status -- including "no label
    at all", not just the three stored values, since "how many Benign
    records are still unlabelled" is exactly the number that makes the
    sampling-bias gap (Notes for dev) visible rather than invisible.
    Columns are verdict.

    Computed from the SAME already-decrypted `records` list _summary_strip
    uses (see its own AC7 discussion -- no extra store decrypt) crossed
    against the separately, cheaply loaded `labels` dict (a small local
    JSON file, nowhere near evidence.db's scale). Always computed from the
    full, unfiltered records list, matching _summary_strip's "stable
    overview" precedent -- this table would be far less useful if its own
    numbers moved every time a filter link was clicked.

    A record with a malformed (non-string / unrecognized) verdict is
    skipped from this table entirely, unlike _summary_strip's "still
    counts toward the total" treatment -- there is no single grand-total
    cell here for it to safely land in without either double-counting a
    row or needing a fifth verdict-shaped column for "unknown", and the
    case is already narrow and extensively guarded elsewhere (see
    _summary_strip's own comment on the same gap)."""
    row_keys: tuple[str, ...] = (*VALID_LABELS, "unlabelled")
    counts: dict[str, dict[str, int]] = {row: {v: 0 for v in _VALID_VERDICTS} for row in row_keys}
    for message_hash, record in records:
        verdict = record["report"]["verdict"]
        if not isinstance(verdict, str) or verdict not in _VALID_VERDICTS:
            continue
        entry = labels.get(message_hash)
        row = entry["label"] if entry is not None else "unlabelled"
        counts[row][verdict] += 1

    header_cells = "".join(f"<th>{_esc(v)}</th>" for v in _VALID_VERDICTS)
    body_rows = []
    for row_key in row_keys:
        row_display = "Unlabelled" if row_key == "unlabelled" else row_key
        row_total = sum(counts[row_key].values())
        data_cells = "".join(f"<td>{counts[row_key][v]}</td>" for v in _VALID_VERDICTS)
        body_rows.append(f"<tr><th>{_esc(row_display)}</th>{data_cells}<td>{row_total}</td></tr>")
    return (
        '<table class="crosstab"><caption>Labels vs. Verdict</caption>'
        f"<thead><tr><th></th>{header_cells}<th>Total</th></tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table>"
    )


def _render_label_form(message_hash: str, current: LabelEntry | None, back: str | None) -> str:
    """[Story 11.1, AC3] Plain HTML form, no JavaScript -- consistent with
    every other page in this dashboard. The POST body is
    application/x-www-form-urlencoded (the <form> default; no enctype
    set) and is parsed in the route handler below via stdlib
    urllib.parse.parse_qsl, NOT FastAPI's Form()/Starlette's
    Request.form() -- both require the python-multipart package, which
    is not an existing dependency and AC9 forbids adding one for this.

    Pre-selects the current label and pre-fills the current note (if any)
    so "set OR change a label" (AC3) is the same form either way -- the
    button text is the only thing that differs.

    [Story 11.2, AC1] `back` (the current list-filter state, if any) is
    embedded in the form's action URL as a query param -- a <form method=
    "post"> does not otherwise forward the page's own query string to its
    action, so without this, submitting the form would silently drop the
    filter context the reader arrived with, even though the redirect
    target is the same page. Percent-encoded here (it becomes a query
    VALUE on the action URL) and read back via FastAPI's own query-param
    parsing in the POST route, not via the hand-rolled body parser."""
    options = []
    for value in VALID_LABELS:
        selected = " selected" if current is not None and current["label"] == value else ""
        options.append(f'<option value="{_esc(value)}"{selected}>{_esc(value)}</option>')
    note_value = _esc(current["note"]) if current is not None else ""
    button_text = "Change label" if current is not None else "Set label"
    action = f"/verdicts/{quote(message_hash, safe='')}/label"
    if back:
        action += f"?back={quote(back, safe='')}"
    return (
        f'<form class="label-form" method="post" action="{_esc(action)}">'
        '<label for="label-select">Label</label>'
        f'<select name="label" id="label-select">{"".join(options)}</select>'
        '<label for="label-note">Note</label>'
        f'<textarea name="note" id="label-note">{note_value}</textarea>'
        f'<button type="submit">{_esc(button_text)}</button>'
        "</form>"
    )


@router.get("/verdicts", response_class=HTMLResponse)
async def verdict_list(verdict: Verdict | None = None, label: LabelFilter | None = None) -> HTMLResponse:
    """AC1/AC2 (Story 10.1): verdict list -- timestamp, sender, verdict,
    filterable by verdict via ?verdict=. `verdict: Verdict | None` reuses
    the same four-value Literal store.py's own EvidenceRecord/TriageReport
    are built from, so FastAPI rejects anything else with a 422 rather than
    this route needing to hand-validate a duplicate set of legal values.

    [Story 10.3, AC4] Confidence no longer has its own column -- it folds
    into the verdict badge (e.g. "Malicious 1.00"); a CoverageGap or
    otherwise-unusable confidence shows the verdict with no number at all,
    not "N/A" inside the badge (that would read as clutter next to a
    colored chip that already means "no analysis ran").

    [Story 11.1, AC5] `label: LabelFilter | None` -- the three real Label
    values plus "unlabelled" -- filters and combines with `verdict` (see
    _filter_query). Records are matched by joining the already-decrypted
    `records` list against the separately-loaded `labels` dict on
    message_hash, in memory -- no additional store read.

    [Story 11.2, AC1] Every row's Detail link carries the current filter
    state as `?back=` (see _back_value/_back_link_href) so the detail
    view's own "back to list" link returns here exactly as filtered,
    computed once per request and reused for every row rather than
    recomputed per row."""
    loop = asyncio.get_running_loop()
    records, error = await loop.run_in_executor(None, _load_records)
    health = await loop.run_in_executor(None, _load_health_status)
    labels = await loop.run_in_executor(None, _load_labels_safe)
    header = _render_header(health)
    if error is not None or records is None:
        return _page("Verdicts", f'{header}<p class="flash flash-error">{_esc(error)}</p>')

    summary = _summary_strip(records)
    crosstab = _label_verdict_crosstab(records, labels)
    back_param = quote(_back_value(verdict, label), safe="")

    if verdict is not None:
        records = [r for r in records if r[1]["report"]["verdict"] == verdict]
    if label is not None:
        if label == "unlabelled":
            records = [r for r in records if r[0] not in labels]
        else:
            records = [
                r for r in records
                if (entry := labels.get(r[0])) is not None and entry["label"] == label
            ]

    rows = []
    for message_hash, record in records:
        report = record["report"]
        sender_display = _sender_display(record["sender"])
        confidence_short = _format_confidence(report["calibrated_confidence"], decimals=2)
        confidence_suffix = None if confidence_short == "N/A" else confidence_short
        detail_href = f"/verdicts/{quote(message_hash, safe='')}"
        if back_param:
            detail_href += f"?back={back_param}"
        rows.append(
            "<tr>"
            f"<td class=\"ts-cell\">{_esc(_format_display_timestamp(report['timestamp']))}</td>"
            f"<td>{_esc(sender_display)}</td>"
            f"<td>{_badge(report['verdict'], confidence_suffix)}</td>"
            f"<td>{_label_display(labels.get(message_hash))}</td>"
            f'<td><a href="{_esc(detail_href)}">Detail</a></td>'
            "</tr>"
        )

    body = (
        f"{header}<h1>Verdicts</h1>"
        f"{summary}"
        f'<div class="table-surface">{crosstab}</div>'
        f"{_filter_links(verdict, label)}"
        f"{_label_filter_links(verdict, label)}"
        '<div class="table-surface"><table><thead><tr><th>Timestamp</th><th>Sender</th>'
        "<th>Verdict</th><th>Label</th><th></th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
        f'<p class="summary">{len(records)} record(s) shown.</p>'
    )
    return _page("Verdicts", body)


@router.get("/verdicts/{message_hash}", response_class=HTMLResponse)
async def verdict_detail(
    message_hash: str, back: str | None = None, saved: bool = False
) -> HTMLResponse:
    """AC3 (Story 10.1): full evidence list for one record -- every
    finding's name, text, weight, and direction, nothing truncated. Looked
    up from the same validated read_recent_evidence_records() list the
    list route uses (rather than store.py's read_evidence_record, which
    skips the well-formedness check -- acceptable for --replay, an
    operator-chosen lookup, but not for a route reachable with an
    arbitrary URL segment).

    [Story 10.2, AC4] The evidence list is the most important thing on
    this page (Notes for dev) -- each item renders as its own bordered
    block (name + direction badge + weight in a header line, finding text
    as its own paragraph below) rather than a table row, so a long finding
    string doesn't stretch one cell while its neighbours stay compact and
    visually disconnected from it.

    [Story 10.3, AC1] Shares the same header bar as the list route -- no
    per-verdict summary strip here (AC3 places it "above the filter
    links", which only exist on the list page).

    [Story 11.1, AC3] The label set/change control lives here, and only
    here (Out of scope: not the alert email -- a clickable action link in
    email is a request-forgery surface and a phishing-shaped pattern in a
    product that warns about phishing). Setting a label never touches
    `match`/`report`/anything from the evidence store -- it only ever
    calls sentinel.web.labels.save_label, a completely separate file
    (AC4).

    [Story 11.2, AC1] `back`, when present, is the raw query string the
    list view was showing when the reader clicked into this record (see
    _back_value/_back_link_href) -- used to build the "back to list" link
    so it returns exactly as filtered, not to an unfiltered list. Not
    validated beyond escaping; see _back_link_href's own docstring for why
    that's sufficient.

    [Story 11.2, AC2] `saved`, when true, renders a visible confirmation
    banner. The label-set POST route redirects here with ?saved=1 on
    success -- AC2's own finding was that a successful save previously had
    no distinct signal beyond the (sometimes unchanged-looking) page
    re-rendering; this makes "it worked" independent of whether the saved
    values happened to differ from what was already stored."""
    loop = asyncio.get_running_loop()
    records, error = await loop.run_in_executor(None, _load_records)
    health = await loop.run_in_executor(None, _load_health_status)
    labels = await loop.run_in_executor(None, _load_labels_safe)
    header = _render_header(health)
    back_link = f'<a class="back-link" href="{_esc(_back_link_href(back))}">&larr; Back to list</a>'
    if error is not None or records is None:
        return _page(
            "Verdict Detail", f'{header}{back_link}<p class="flash flash-error">{_esc(error)}</p>'
        )

    match = next((record for h, record in records if h == message_hash), None)
    if match is None:
        return _page(
            "Verdict Detail",
            f'{header}{back_link}<p class="flash flash-error">No record found for '
            f"{_esc(message_hash)}.</p>",
            status_code=404,
        )

    report = match["report"]
    sender_display = _sender_display(match["sender"])
    confidence_display = _format_confidence(report["calibrated_confidence"])
    current_label = labels.get(message_hash)

    lines = [header, back_link, "<h1>Verdict Detail</h1>"]
    if saved:
        lines.append('<p class="flash flash-success">Label saved.</p>')
    lines += [
        f'<p class="meta">Timestamp: {_esc(_format_display_timestamp(report["timestamp"]))}</p>',
        f'<p class="meta">Sender: {_esc(sender_display)}</p>',
        f'<p class="meta">Verdict: {_badge(report["verdict"])}</p>',
        f'<p class="meta">Confidence: {_esc(confidence_display)}</p>',
        f'<p class="meta">Label: {_label_display(current_label)}</p>',
    ]
    if current_label is not None and current_label["note"]:
        lines.append(
            f'<p class="meta">Note ({_esc(_format_display_timestamp(current_label["timestamp"]))}): '
            f'{_esc(current_label["note"])}</p>'
        )
    lines.append(_render_label_form(message_hash, current_label, back))
    # .get(): a loaded record can predate coverage_gap_reason's schema
    # addition (Story 6.1) and lack the key entirely -- see
    # TriageReport.coverage_gap_reason's own docstring in report.py.
    coverage_gap_reason = report.get("coverage_gap_reason")
    if coverage_gap_reason is not None:
        lines.append(f'<p class="meta">Coverage gap reason: {_esc(coverage_gap_reason)}</p>')

    evidence = report["evidence"]
    if not evidence:
        lines.append("<p>No evidence — no analysis was performed for this record.</p>")
    else:
        item_blocks = []
        skipped_items = 0
        for item in evidence:
            if not _is_well_formed_evidence_item(item):
                skipped_items += 1
                continue
            item_blocks.append(
                f'<li class="{_evidence_item_class(item["direction"])}">'
                '<div class="evidence-header">'
                f'<span class="evidence-name">{_esc(item["name"])}</span>'
                f'{_badge(item["direction"])}'
                f'<span class="evidence-weight">weight {_esc(item["weight"])}</span>'
                "</div>"
                f'<p class="evidence-finding">{_esc(item["finding"])}</p>'
                "</li>"
            )
        if skipped_items:
            lines.append(
                f"<p>{skipped_items} evidence item(s) could not be rendered (malformed).</p>"
            )
        lines.append('<ul class="evidence-list">' + "".join(item_blocks) + "</ul>")

    return _page("Verdict Detail", "".join(lines))


@router.post("/verdicts/{message_hash}/label", response_model=None)
async def set_verdict_label(
    message_hash: str, request: Request, back: str | None = None
) -> HTMLResponse | RedirectResponse:
    """[Story 11.1, AC3] Sets or changes a label. Never touches the
    evidence record or stored verdict -- structurally guaranteed by only
    ever calling sentinel.web.labels.save_label, a module with no
    knowledge of evidence.db at all (AC4's structural test).

    Parses the POST body itself via stdlib urllib.parse.parse_qsl rather
    than FastAPI's Form()/Starlette's Request.form() -- both require the
    python-multipart package, which is not an existing dependency and
    AC9 forbids adding one for this. The <form> in _render_label_form
    has no enctype set, so the browser sends
    application/x-www-form-urlencoded -- exactly what parse_qsl expects.

    `back` is a QUERY param (from the form's action URL, see
    _render_label_form), deliberately separate from the hand-parsed body
    fields -- FastAPI still parses ordinary query params on a POST route
    without needing python-multipart, since that only gates BODY parsing.

    Does not verify message_hash corresponds to a real evidence record
    before saving. The only path that reaches this route under normal
    use already validated the hash (the detail page 404s first), and a
    label for a hash that turns out not to exist is a harmless orphan
    entry -- never rendered anywhere, since nothing ever joins against a
    hash absent from the evidence store. Adding that check would mean
    reading evidence.db from this route for no functional benefit, on a
    loopback-only, single-operator, no-auth tool (AC8) where the
    realistic threat model does not include a stranger guessing an
    unguessable SHA-256 hash.

    [Notes for dev] save_label raises on any failure (deliberately,
    unlike health.py's save_health_state -- see save_label's own
    docstring). Caught here and rendered as an explicit failure page, not
    a redirect that would look like success to a human who just clicked
    submit and has no other way to know whether it actually worked.

    [Story 11.2, AC3] Failure pages are styled as a visible .flash-error
    banner, not a bare, unstyled sentence -- readable was already true
    (see the finding this story's own investigation reported); this makes
    it also unmistakable at a glance, matching the same treatment the
    success path (AC2) gets."""
    back_suffix = f"?back={quote(back, safe='')}" if back else ""
    record_href = f"/verdicts/{quote(message_hash, safe='')}{back_suffix}"

    body = await request.body()
    # [Review, Blind Hunter/Edge Case Hunter] Every other failure path in
    # this route (invalid label, no config, save_label raising) renders a
    # clean message per this module's own convention -- a raw body
    # containing non-UTF-8 bytes previously reached body.decode("utf-8")
    # unguarded, raising an uncaught UnicodeDecodeError and producing
    # Starlette's generic "Internal Server Error" 500 instead. Reachable
    # by any client on the loopback port (or the accepted CSRF-shaped
    # vector docs/labelling-design.md's D4 already discusses), with no
    # data-corruption consequence -- but it broke this route's own "never
    # crash uncaught" design intent, which every other branch honors.
    try:
        decoded_body = body.decode("utf-8")
    except UnicodeDecodeError:
        return _page(
            "Verdict Detail",
            '<p class="flash flash-error">Invalid form submission (not valid UTF-8). '
            "Nothing was saved.</p>"
            f'<p><a href="{_esc(record_href)}">Back to record</a></p>',
            status_code=400,
        )
    fields = dict(parse_qsl(decoded_body, strict_parsing=False))
    label_value = fields.get("label")
    note = fields.get("note", "")

    if label_value not in VALID_LABELS:
        return _page(
            "Verdict Detail",
            f'<p class="flash flash-error">Invalid label "{_esc(label_value)}" — must be one of '
            "confirmed-phishing, confirmed-benign, unclear. Nothing was saved.</p>"
            f'<p><a href="{_esc(record_href)}">Back to record</a></p>',
            status_code=400,
        )
    label: Label = label_value

    config = state._config
    if config is None:
        return _page(
            "Verdict Detail",
            '<p class="flash flash-error">Server is not configured — required environment '
            "variables are missing. Nothing was saved.</p>"
            f'<p><a href="{_esc(record_href)}">Back to record</a></p>',
            status_code=500,
        )

    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, save_label, config.evidence_db_path, config, message_hash, label, note
        )
    except Exception as exc:
        print(f"[sentinel-web] Label save error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return _page(
            "Verdict Detail",
            '<p class="flash flash-error">Failed to save the label — nothing was recorded. '
            "Check server logs and try again.</p>"
            f'<p><a href="{_esc(record_href)}">Back to record</a></p>',
            status_code=500,
        )

    redirect_url = f"/verdicts/{quote(message_hash, safe='')}?saved=1"
    if back:
        redirect_url += f"&back={quote(back, safe='')}"
    return RedirectResponse(url=redirect_url, status_code=303)
