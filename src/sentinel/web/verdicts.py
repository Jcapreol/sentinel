"""Read-only live verdict list and detail views (Story 10.1, styled and
timezone-aware per Story 10.2, chrome/summary/health status per Story 10.3).

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
in calibrated_confidence during Story 10.1's review).
"""

from __future__ import annotations

import asyncio
import html
import sys
from datetime import datetime, timezone
from typing import Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from sentinel.config import ConfigError
from sentinel.triage.health import HealthState, try_load_health_state
from sentinel.triage.store import EvidenceRecord, read_recent_evidence_records
from sentinel.web import state

router = APIRouter()

Verdict = Literal["Malicious", "Benign", "Deferred", "CoverageGap"]
_VALID_VERDICTS: tuple[Verdict, ...] = ("Malicious", "Benign", "Deferred", "CoverageGap")

# [Story 10.2, AC3] Hardcoded to US Eastern for this dashboard's current
# audience (Notes for dev: a CS instructor, eventually a small business
# owner -- both Eastern). Storage (report["timestamp"]) stays UTC,
# unconditionally, everywhere else in the codebase; this constant exists
# ONLY to drive the display-layer conversion in this module. Would need to
# become a per-viewer or config-driven setting if this dashboard is ever
# used by someone outside Eastern time -- no such mechanism exists yet.
_DISPLAY_TIMEZONE = ZoneInfo("America/New_York")

# [Story 10.2, AC4/AC5] Inline, not served: keeps the whole feature -- every
# escape point, every style rule -- auditable in this one module, and needs
# no new route/static-file surface (AC1's "reads only through store.py"
# structural test has nothing new to consider). No CDN, no build step, no
# framework -- plain CSS custom properties and flexbox. Deliberately a
# single light theme (Notes for dev: "clean and legible beats designed";
# dark mode is explicitly out of scope).
_STYLE = """
:root {
  --fg: #1f2933; --muted: #6b7280; --border: #e5e7eb; --row-alt: #f9fafb;
  --link: #1d4ed8;
  --malicious-bg: #fee2e2; --malicious-fg: #991b1b;
  --benign-bg: #dcfce7; --benign-fg: #166534;
  --deferred-bg: #fef3c7; --deferred-fg: #92400e;
  --coveragegap-bg: #e5e7eb; --coveragegap-fg: #374151;
  --neutral-bg: #e5e7eb; --neutral-fg: #374151;
}
* { box-sizing: border-box; }
body {
  max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem 4rem;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 16px; line-height: 1.5; color: var(--fg); background: #ffffff;
}
h1 { font-size: 1.5rem; margin: 0 0 1rem; }
a { color: var(--link); }
.app-header {
  display: flex; justify-content: space-between; align-items: center;
  flex-wrap: wrap; gap: 0.5rem;
  padding-bottom: 1rem; margin-bottom: 1.5rem; border-bottom: 2px solid var(--border);
}
.app-name { font-weight: 700; font-size: 1.1rem; color: var(--fg); text-decoration: none; }
.summary-strip {
  display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem;
  margin-bottom: 1rem;
}
.summary-strip .summary-total { font-weight: 600; margin-right: 0.4rem; }
.filters { margin-bottom: 1.5rem; }
.filters a { margin-right: 0.9rem; text-decoration: none; }
.filters strong { color: var(--fg); }
table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
th, td {
  text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border);
  overflow-wrap: break-word;
}
th {
  font-weight: 600; color: var(--muted); text-transform: uppercase;
  font-size: 0.75rem; letter-spacing: 0.03em;
}
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
.meta { color: var(--muted); margin: 0.3rem 0; }
.evidence-list { list-style: none; margin: 1rem 0 0; padding: 0; }
.evidence-item {
  border: 1px solid var(--border); border-radius: 6px;
  padding: 0.9rem 1rem; margin-bottom: 0.75rem;
}
.evidence-header {
  display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;
  margin-bottom: 0.5rem;
}
.evidence-name {
  font-weight: 600; font-size: 0.9rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.evidence-weight { color: var(--muted); font-size: 0.85rem; margin-left: auto; }
.evidence-finding { margin: 0; overflow-wrap: break-word; }
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
    is shared rather than duplicated for the two callers."""
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


def _sender_display(sender: str | None) -> str:
    """[Story 10.3, AC5] CoverageGap records have sender: null by design
    (Story 6.1 -- the message itself could never be fetched, so there was
    never a sender to read). A clear, explicit placeholder, not an empty
    cell that could read as a rendering bug."""
    return sender if sender is not None else "Message unavailable (coverage gap)"


def _filter_links(active: str | None) -> str:
    options: list[tuple[str, str]] = [("All", "/verdicts")]
    options += [(v, f"/verdicts?verdict={v}") for v in _VALID_VERDICTS]
    parts = []
    for label, href in options:
        is_active = (active is None and label == "All") or active == label
        text = f"<strong>{_esc(label)}</strong>" if is_active else _esc(label)
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
    changes."""
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
    parts = [f'<span class="summary-total">{len(records)} total</span>']
    parts += [_badge(v, str(counts[v])) for v in _VALID_VERDICTS]
    return '<div class="summary-strip">' + "".join(parts) + "</div>"


@router.get("/verdicts", response_class=HTMLResponse)
async def verdict_list(verdict: Verdict | None = None) -> HTMLResponse:
    """AC1/AC2 (Story 10.1): verdict list -- timestamp, sender, verdict,
    filterable by verdict via ?verdict=. `verdict: Verdict | None` reuses
    the same four-value Literal store.py's own EvidenceRecord/TriageReport
    are built from, so FastAPI rejects anything else with a 422 rather than
    this route needing to hand-validate a duplicate set of legal values.

    [Story 10.3, AC4] Confidence no longer has its own column -- it folds
    into the verdict badge (e.g. "Malicious 1.00"); a CoverageGap or
    otherwise-unusable confidence shows the verdict with no number at all,
    not "N/A" inside the badge (that would read as clutter next to a
    colored chip that already means "no analysis ran")."""
    loop = asyncio.get_running_loop()
    records, error = await loop.run_in_executor(None, _load_records)
    health = await loop.run_in_executor(None, _load_health_status)
    header = _render_header(health)
    if error is not None or records is None:
        return _page("Verdicts", f"{header}<p>{_esc(error)}</p>")

    summary = _summary_strip(records)

    if verdict is not None:
        records = [r for r in records if r[1]["report"]["verdict"] == verdict]

    rows = []
    for message_hash, record in records:
        report = record["report"]
        sender_display = _sender_display(record["sender"])
        confidence_short = _format_confidence(report["calibrated_confidence"], decimals=2)
        confidence_suffix = None if confidence_short == "N/A" else confidence_short
        rows.append(
            "<tr>"
            f"<td>{_esc(_format_display_timestamp(report['timestamp']))}</td>"
            f"<td>{_esc(sender_display)}</td>"
            f"<td>{_badge(report['verdict'], confidence_suffix)}</td>"
            f'<td><a href="/verdicts/{_esc(message_hash)}">Detail</a></td>'
            "</tr>"
        )

    body = (
        f"{header}<h1>Verdicts</h1>"
        f"{summary}"
        f"{_filter_links(verdict)}"
        "<table><thead><tr><th>Timestamp</th><th>Sender</th><th>Verdict</th>"
        "<th></th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        f'<p class="summary">{len(records)} record(s) shown.</p>'
    )
    return _page("Verdicts", body)


@router.get("/verdicts/{message_hash}", response_class=HTMLResponse)
async def verdict_detail(message_hash: str) -> HTMLResponse:
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
    links", which only exist on the list page)."""
    loop = asyncio.get_running_loop()
    records, error = await loop.run_in_executor(None, _load_records)
    health = await loop.run_in_executor(None, _load_health_status)
    header = _render_header(health)
    if error is not None or records is None:
        return _page("Verdict Detail", f"{header}<p>{_esc(error)}</p>")

    match = next((record for h, record in records if h == message_hash), None)
    if match is None:
        return _page(
            "Verdict Detail",
            f"{header}<p>No record found for {_esc(message_hash)}.</p>",
            status_code=404,
        )

    report = match["report"]
    sender_display = _sender_display(match["sender"])
    confidence_display = _format_confidence(report["calibrated_confidence"])

    lines = [
        header,
        "<h1>Verdict Detail</h1>",
        f'<p class="meta">Timestamp: {_esc(_format_display_timestamp(report["timestamp"]))}</p>',
        f'<p class="meta">Sender: {_esc(sender_display)}</p>',
        f'<p class="meta">Verdict: {_badge(report["verdict"])}</p>',
        f'<p class="meta">Confidence: {_esc(confidence_display)}</p>',
    ]
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
                '<li class="evidence-item">'
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
