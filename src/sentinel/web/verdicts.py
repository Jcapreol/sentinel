"""Read-only live verdict list and detail views (Story 10.1).

Reads exclusively through sentinel.triage.store's existing, validated,
read-only functions -- no direct sqlite3 or Fernet usage anywhere in this
module (AC1), enforced by test_web_imports_no_direct_db_or_crypto_access,
which mirrors triage/'s existing smtplib-ban structural test.

Renders its own minimal HTML, entirely independent of demo.py/routes.py's
SSE+JSON rendering path (AC5, D5): the demo route never touches a real
evidence record, and these routes never touch a demo fixture, so there is
no shared renderer to drift between the two.

Every value pulled from a stored record is attacker-influenced (an email's
sender display name, a finding's text, a coverage-gap reason all
ultimately derive from message content Sentinel does not control) and is
therefore escaped at render time via _esc, without exception -- including
fields that look server-controlled, so no future field is accidentally
exempted (Notes for dev, AC6).
"""

from __future__ import annotations

import asyncio
import html
import sys
from typing import Literal

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from sentinel.config import ConfigError
from sentinel.triage.store import EvidenceRecord, read_recent_evidence_records
from sentinel.web import state

router = APIRouter()

Verdict = Literal["Malicious", "Benign", "Deferred", "CoverageGap"]
_VALID_VERDICTS: tuple[Verdict, ...] = ("Malicious", "Benign", "Deferred", "CoverageGap")


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{_esc(title)}</title></head><body>{body}</body></html>",
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


def _format_confidence(confidence: object) -> str:
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
    confidence value, formatting one as "1.000" would be misleading."""
    if isinstance(confidence, bool):
        return "N/A"
    if isinstance(confidence, (int, float)):
        return f"{confidence:.3f}"
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


def _filter_links(active: str | None) -> str:
    options: list[tuple[str, str]] = [("All", "/verdicts")]
    options += [(v, f"/verdicts?verdict={v}") for v in _VALID_VERDICTS]
    parts = []
    for label, href in options:
        is_active = (active is None and label == "All") or active == label
        text = f"<strong>{_esc(label)}</strong>" if is_active else _esc(label)
        parts.append(f'<a href="{_esc(href)}">{text}</a>')
    return " | ".join(parts)


@router.get("/verdicts", response_class=HTMLResponse)
async def verdict_list(verdict: Verdict | None = None) -> HTMLResponse:
    """AC1/AC2: verdict list -- timestamp, sender, verdict, confidence,
    filterable by verdict via ?verdict=. `verdict: Verdict | None` reuses
    the same four-value Literal store.py's own EvidenceRecord/TriageReport
    are built from, so FastAPI rejects anything else with a 422 rather than
    this route needing to hand-validate a duplicate set of legal values."""
    loop = asyncio.get_running_loop()
    records, error = await loop.run_in_executor(None, _load_records)
    if error is not None or records is None:
        return _page("Verdicts", f"<p>{_esc(error)}</p>")

    if verdict is not None:
        records = [r for r in records if r[1]["report"]["verdict"] == verdict]

    rows = []
    for message_hash, record in records:
        report = record["report"]
        sender = record["sender"]
        # [Story 6.1] CoverageGap records have sender: null -- must render,
        # never crash on a None sender.
        sender_display = sender if sender is not None else "(no sender — coverage gap)"
        # [Story 6.1] None confidence (CoverageGap only) renders "N/A", never
        # 0.000/0.500 -- both would misleadingly look like a real measurement.
        confidence_display = _format_confidence(report["calibrated_confidence"])
        rows.append(
            "<tr>"
            f"<td>{_esc(report['timestamp'])}</td>"
            f"<td>{_esc(sender_display)}</td>"
            f"<td>{_esc(report['verdict'])}</td>"
            f"<td>{_esc(confidence_display)}</td>"
            f'<td><a href="/verdicts/{_esc(message_hash)}">Detail</a></td>'
            "</tr>"
        )

    body = (
        "<h1>Verdicts</h1>"
        f"<p>{_filter_links(verdict)}</p>"
        "<table><thead><tr><th>Timestamp</th><th>Sender</th><th>Verdict</th>"
        "<th>Confidence</th><th></th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        f"<p>{len(records)} record(s) shown.</p>"
    )
    return _page("Verdicts", body)


@router.get("/verdicts/{message_hash}", response_class=HTMLResponse)
async def verdict_detail(message_hash: str) -> HTMLResponse:
    """AC3: full evidence list for one record -- every finding's name,
    text, weight, and direction, nothing truncated. Looked up from the
    same validated read_recent_evidence_records() list the list route
    uses (rather than store.py's read_evidence_record, which skips the
    well-formedness check -- acceptable for --replay, an operator-chosen
    lookup, but not for a route reachable with an arbitrary URL segment)."""
    loop = asyncio.get_running_loop()
    records, error = await loop.run_in_executor(None, _load_records)
    if error is not None or records is None:
        return _page("Verdict Detail", f"<p>{_esc(error)}</p>")

    match = next((record for h, record in records if h == message_hash), None)
    if match is None:
        return _page(
            "Verdict Detail",
            f"<p>No record found for {_esc(message_hash)}.</p>",
            status_code=404,
        )

    report = match["report"]
    sender = match["sender"]
    sender_display = sender if sender is not None else "(no sender — coverage gap)"
    confidence_display = _format_confidence(report["calibrated_confidence"])

    lines = [
        "<h1>Verdict Detail</h1>",
        f"<p>Timestamp: {_esc(report['timestamp'])}</p>",
        f"<p>Sender: {_esc(sender_display)}</p>",
        f"<p>Verdict: {_esc(report['verdict'])}</p>",
        f"<p>Confidence: {_esc(confidence_display)}</p>",
    ]
    # .get(): a loaded record can predate coverage_gap_reason's schema
    # addition (Story 6.1) and lack the key entirely -- see
    # TriageReport.coverage_gap_reason's own docstring in report.py.
    coverage_gap_reason = report.get("coverage_gap_reason")
    if coverage_gap_reason is not None:
        lines.append(f"<p>Coverage gap reason: {_esc(coverage_gap_reason)}</p>")

    evidence = report["evidence"]
    if not evidence:
        lines.append("<p>No evidence — no analysis was performed for this record.</p>")
    else:
        item_rows = []
        skipped_items = 0
        for item in evidence:
            if not _is_well_formed_evidence_item(item):
                skipped_items += 1
                continue
            item_rows.append(
                "<tr>"
                f"<td>{_esc(item['name'])}</td>"
                f"<td>{_esc(item['finding'])}</td>"
                f"<td>{_esc(item['weight'])}</td>"
                f"<td>{_esc(item['direction'])}</td>"
                "</tr>"
            )
        if skipped_items:
            lines.append(
                f"<p>{skipped_items} evidence item(s) could not be rendered (malformed).</p>"
            )
        lines.append(
            "<table><thead><tr><th>Name</th><th>Finding</th><th>Weight</th>"
            "<th>Direction</th></tr></thead><tbody>"
            + "".join(item_rows)
            + "</tbody></table>"
        )

    return _page("Verdict Detail", "".join(lines))
