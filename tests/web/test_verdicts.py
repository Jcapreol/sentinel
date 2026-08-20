from __future__ import annotations

import asyncio
import ast
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Generator
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from sentinel.config import Config, ConfigError
from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.health import save_health_state
from sentinel.triage.report import TriageReport
from sentinel.triage.store import EvidenceRecord, persist_evidence_record
from sentinel.triage.store import _connect as _store_connect
from sentinel.web import verdicts as verdicts_mod
from sentinel.web.main import DEFAULT_HOST, app


@dataclass
class VerdictsEnv:
    client: TestClient
    config: Config
    db_path: str


@pytest.fixture
def verdicts_env(tmp_path: Path) -> Generator[VerdictsEnv, None, None]:
    """A real deployment's evidence.db already exists (created by
    sentinel-triage's own first run) by the time anyone loads the
    dashboard -- so the file is pre-created here (schema only, zero rows),
    matching test_worker.py's own precedent for building an empty-but-
    valid store. Tests that specifically care about a genuinely MISSING
    database file build their own fixture-free TestClient instead."""
    db_path = str(tmp_path / "evidence.db")
    _store_connect(db_path).close()
    config = Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        evidence_encryption_key=Fernet.generate_key().decode(),
        evidence_db_path=db_path,
    )
    with patch("sentinel.web.main.load_config", return_value=config):
        with TestClient(app) as client:
            yield VerdictsEnv(client=client, config=config, db_path=db_path)


def _make_report(
    verdict: str = "Malicious",
    calibrated_confidence: float | None = 0.9,
    evidence: list[EvidenceItem] | None = None,
    message_hash: str = "hash1",
    timestamp: str = "2026-08-20T00:00:00+00:00",
    coverage_gap_reason: str | None = None,
) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[typeddict-item]
        calibrated_confidence=calibrated_confidence,
        evidence=evidence if evidence is not None else [],
        schema_version=1,
        message_hash=message_hash,
        timestamp=timestamp,
        coverage_gap_reason=coverage_gap_reason,
    )


def _persist(
    env: VerdictsEnv,
    message_hash: str,
    verdict: str = "Malicious",
    sender: str | None = "alice@example.com",
    evidence: list[EvidenceItem] | None = None,
    timestamp: str = "2026-08-20T00:00:00+00:00",
    calibrated_confidence: float | None = 0.9,
    coverage_gap_reason: str | None = None,
) -> None:
    report = _make_report(
        verdict=verdict,
        calibrated_confidence=calibrated_confidence,
        evidence=evidence,
        message_hash=message_hash,
        timestamp=timestamp,
        coverage_gap_reason=coverage_gap_reason,
    )
    record = EvidenceRecord(
        message_id=message_hash,
        sender=sender,
        report=report,
        deferral_threshold_used=env.config.deferral_threshold,
    )
    persist_evidence_record(env.db_path, message_hash, record, env.config)


def _persist_raw(env: VerdictsEnv, message_hash: str, record: dict) -> None:  # type: ignore[type-arg]
    """[Review, Blind Hunter] Bypasses persist_evidence_record's TypedDict
    construction entirely to insert an arbitrary, possibly-malformed-value
    record -- e.g. calibrated_confidence as a string, an evidence item
    missing a required key. Mirrors test_worker.py's own
    test_run_view_renders_genuinely_legacy_record_missing_coverage_gap_
    reason_key precedent (same _connect + Fernet.encrypt(json.dumps(...))
    pattern) for simulating data that a real EvidenceRecord construction
    could never itself produce, but a corrupted/pre-schema row could."""
    import json

    from sentinel.triage.store import _require_fernet

    fernet = _require_fernet(env.config)
    encrypted = fernet.encrypt(json.dumps(record).encode())
    conn = _store_connect(env.db_path)
    conn.execute(
        "INSERT INTO evidence_records "
        "(message_hash, verdict_json, created_at, expires_at, schema_version) "
        "VALUES (?, ?, '2026-08-20T00:00:00+00:00', '2099-01-01T00:00:00+00:00', 1)",
        (message_hash, encrypted),
    )
    conn.commit()
    conn.close()


# --- AC1: structural boundary -------------------------------------------


def _matches_forbidden(module_name: str | None, forbidden: set[str]) -> bool:
    """[Review, Blind Hunter] Exact-match-only (`alias.name not in forbidden`)
    misses a dotted submodule import -- `import sqlite3.dbapi2` binds
    `sqlite3` in the namespace exactly like `import sqlite3` does, but
    `alias.name == "sqlite3.dbapi2"` is not literally in the forbidden set.
    Matches test_triage_modules_downstream_of_provider_boundary_do_not_
    import_googleapiclient's existing startswith-prefix pattern in
    test_worker.py, applied here to both the ast.Import and ast.ImportFrom
    branches (a `from sqlite3.dbapi2 import X` has the identical gap)."""
    if module_name is None:
        return False
    return module_name in forbidden or any(
        module_name.startswith(f"{mod}.") for mod in forbidden
    )


def test_web_imports_no_direct_db_or_crypto_access() -> None:
    """AC1: no file under src/sentinel/web/ may import sqlite3 or
    cryptography.fernet directly -- all reads go through store.py's
    existing functions. Mirrors test_triage_imports_no_remediation_capable_
    library's ast.walk pattern exactly."""
    web_dir = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "web"
    forbidden = {"sqlite3", "cryptography.fernet", "fernet"}
    for source_path in web_dir.glob("*.py"):
        tree = ast.parse(source_path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not _matches_forbidden(alias.name, forbidden), (
                        f"{source_path.name} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                assert not _matches_forbidden(node.module, forbidden), (
                    f"{source_path.name} imports from {node.module}"
                )


def test_verdicts_module_does_not_import_demo_or_routes() -> None:
    """AC5: live and demo paths do not share rendering code -- verdicts.py
    must not import from routes.py or demo.py (and vice versa is already
    true: neither existing module knows verdicts.py exists)."""
    verdicts_path = (
        Path(__file__).resolve().parents[2] / "src" / "sentinel" / "web" / "verdicts.py"
    )
    tree = ast.parse(verdicts_path.read_text())
    forbidden = {"sentinel.web.routes", "sentinel.web.demo"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden, f"verdicts.py imports from {node.module}"


# --- AC4: loopback-only binding -------------------------------------------


def test_default_host_is_loopback() -> None:
    assert DEFAULT_HOST == "127.0.0.1"


def test_main_never_references_all_interfaces_binding() -> None:
    main_path = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "web" / "main.py"
    assert "0.0.0.0" not in main_path.read_text()


# --- AC2: verdict list ------------------------------------------------------


def test_verdict_list_shows_timestamp_sender_verdict_confidence(
    verdicts_env: VerdictsEnv,
) -> None:
    _persist(
        verdicts_env,
        "hash1",
        verdict="Malicious",
        sender="phisher@evil.example",
        timestamp="2026-08-20T12:00:00+00:00",
        calibrated_confidence=0.87,
    )

    response = verdicts_env.client.get("/verdicts")

    assert response.status_code == 200
    body = response.text
    # [Story 10.2, AC1] 12:00 UTC in August (EDT, UTC-4) -> 8:00 AM Eastern.
    assert "Aug 20, 2026 8:00 AM" in body
    assert "phisher@evil.example" in body
    assert "Malicious" in body
    # [Story 10.3, AC4] Confidence folds into the verdict badge, 2 decimals
    # (matching the AC's own "Malicious 1.00" example) -- not the 3-decimal
    # format used elsewhere (e.g. the detail route's dedicated line).
    assert "Malicious 0.87" in body


def test_verdict_list_filters_by_verdict(verdicts_env: VerdictsEnv) -> None:
    _persist(verdicts_env, "hash1", verdict="Malicious", sender="a@example.com")
    _persist(verdicts_env, "hash2", verdict="Benign", sender="b@example.com")

    response = verdicts_env.client.get("/verdicts", params={"verdict": "Benign"})

    assert response.status_code == 200
    body = response.text
    assert "b@example.com" in body
    assert "a@example.com" not in body


def test_verdict_list_rejects_invalid_verdict_filter(verdicts_env: VerdictsEnv) -> None:
    response = verdicts_env.client.get("/verdicts", params={"verdict": "NotAVerdict"})
    assert response.status_code == 422


def test_verdict_list_renders_coverage_gap_without_confidence_and_without_crashing(
    verdicts_env: VerdictsEnv,
) -> None:
    """[Story 6.1 model; Story 10.3, AC4] CoverageGap has sender: null and
    calibrated_confidence: None -- must render, never crash, never show
    0.000/0.500 (either would look like a real measurement). Per AC4, the
    badge shows the verdict with NO number at all (not "N/A" inside the
    badge -- that would read as clutter next to a chip that already means
    "no analysis ran"); sender gets the AC5 placeholder."""
    _persist(
        verdicts_env,
        "hash-gap",
        verdict="CoverageGap",
        sender=None,
        evidence=[],
        calibrated_confidence=None,
        coverage_gap_reason="Failed to fetch raw message content: HttpError 404",
    )

    response = verdicts_env.client.get("/verdicts")

    assert response.status_code == 200
    body = response.text
    assert '<span class="badge badge-coveragegap">CoverageGap</span>' in body
    assert "Message unavailable" in body
    assert "0.000" not in body
    assert "0.500" not in body


def test_verdict_list_empty_store_does_not_crash(verdicts_env: VerdictsEnv) -> None:
    response = verdicts_env.client.get("/verdicts")
    assert response.status_code == 200
    assert "0 record(s) shown" in response.text


def test_verdict_list_missing_database_file_renders_clean_message_not_crash(
    tmp_path: Path,
) -> None:
    """Mirrors test_run_view_missing_database_file_prints_clean_message_
    not_traceback: a database file that has never been created at all
    (distinct from an existing-but-empty store) must still render cleanly,
    never a 500."""
    db_path = str(tmp_path / "never-created.db")
    config = Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        evidence_encryption_key=Fernet.generate_key().decode(),
        evidence_db_path=db_path,
    )
    with patch("sentinel.web.main.load_config", return_value=config):
        with TestClient(app) as client:
            response = client.get("/verdicts")
    assert response.status_code == 200
    assert "could not read the evidence database" in response.text.lower()


def test_verdict_list_server_not_configured_renders_clean_message() -> None:
    """Mirrors test_missing_api_key_logs_to_stderr_not_traceback's pattern:
    load_config() raising ConfigError leaves state._config as None (per
    main.py's lifespan), and /verdicts must render a clean message rather
    than crash trying to read a store it has no config for."""
    with patch(
        "sentinel.web.main.load_config",
        side_effect=ConfigError("Missing required environment variable: ANTHROPIC_API_KEY"),
    ):
        with TestClient(app) as client:
            response = client.get("/verdicts")
    assert response.status_code == 200
    assert "not configured" in response.text.lower()


# --- Story 10.2, AC1/AC2/AC3: Eastern-time timestamp display ---------------


def test_display_timezone_is_a_module_constant_set_to_america_new_york() -> None:
    """AC3: confirms _DISPLAY_TIMEZONE is exactly zoneinfo's
    "America/New_York" (AC2), not some other Eastern-adjacent
    representation. That it's a bare module attribute rather than a
    Config field is a source-level fact (see verdicts.py's own AC3
    comment) -- Config itself has no timezone-related field at all,
    confirmed by fake_config's fixture construction not needing one."""
    from zoneinfo import ZoneInfo

    assert verdicts_mod._DISPLAY_TIMEZONE == ZoneInfo("America/New_York")


@pytest.mark.parametrize(
    "iso_timestamp,expected",
    [
        # AC2: EDT (UTC-4) in August -- summer.
        ("2026-08-20T19:10:00+00:00", "Aug 20, 2026 3:10 PM"),
        # AC2: EST (UTC-5) in January -- winter. Same wall-clock UTC hour
        # (19:10) as the summer case above, but a DIFFERENT local result
        # (2:10 PM, not 3:10 PM) -- a fixed offset would get one of these
        # two wrong; zoneinfo gets both right.
        ("2026-01-20T19:10:00+00:00", "Jan 20, 2026 2:10 PM"),
        # Midnight UTC crosses to the previous Eastern calendar day.
        ("2026-08-20T02:00:00+00:00", "Aug 19, 2026 10:00 PM"),
        # Noon -> 12-hour clock boundary (not "0:00 PM").
        ("2026-08-20T16:00:00+00:00", "Aug 20, 2026 12:00 PM"),
        # Midnight Eastern -> 12-hour clock boundary (not "0:00 AM").
        ("2026-08-20T04:00:00+00:00", "Aug 20, 2026 12:00 AM"),
        # Naive (no tzinfo) timestamp treated as UTC, not local-naive.
        ("2026-08-20T19:10:00", "Aug 20, 2026 3:10 PM"),
    ],
)
def test_format_display_timestamp_dst_and_boundary_cases(
    iso_timestamp: str, expected: str
) -> None:
    assert verdicts_mod._format_display_timestamp(iso_timestamp) == expected


def test_format_display_timestamp_malformed_value_falls_back_not_crash() -> None:
    """Same well-formedness gap as calibrated_confidence/evidence items:
    read_recent_evidence_records only guarantees "timestamp" is present,
    never that it's parseable. Falls back to the raw value, never raises."""
    assert verdicts_mod._format_display_timestamp("not-a-timestamp") == "not-a-timestamp"
    assert verdicts_mod._format_display_timestamp(None) == "None"
    assert verdicts_mod._format_display_timestamp(12345) == "12345"


def test_format_display_timestamp_extreme_past_falls_back_not_crash() -> None:
    """[Review, Blind Hunter] A UTC timestamp near datetime.min in winter
    converts to a negative-year Eastern local time, which
    datetime.astimezone() cannot represent -- it raises OverflowError,
    not ValueError/TypeError. Confirmed reproducible before this was
    caught: both call sites would 500 on a record carrying a timestamp
    this old. Falls back to the raw value like every other malformed
    case, never raises."""
    assert verdicts_mod._format_display_timestamp("0001-01-01T00:00:00") == "0001-01-01T00:00:00"
    assert verdicts_mod._format_display_timestamp("0001-01-01T04:00:00") == "0001-01-01T04:00:00"


def test_verdict_list_renders_eastern_time_not_raw_utc(verdicts_env: VerdictsEnv) -> None:
    _persist(verdicts_env, "hash1", verdict="Benign", timestamp="2026-08-20T19:10:00+00:00")

    response = verdicts_env.client.get("/verdicts")

    assert "Aug 20, 2026 3:10 PM" in response.text
    assert "2026-08-20T19:10:00" not in response.text


def test_verdict_detail_renders_eastern_time_not_raw_utc(verdicts_env: VerdictsEnv) -> None:
    _persist(verdicts_env, "hash1", verdict="Benign", timestamp="2026-01-20T19:10:00+00:00")

    response = verdicts_env.client.get("/verdicts/hash1")

    assert "Jan 20, 2026 2:10 PM" in response.text  # EST, UTC-5
    assert "2026-01-20T19:10:00" not in response.text


# --- AC3: detail view --------------------------------------------------------


def test_verdict_detail_shows_every_finding_field_untruncated(
    verdicts_env: VerdictsEnv,
) -> None:
    long_finding = "A" * 500  # far past worker.py's _VIEW_FINDING_MAX_LEN (50)
    _persist(
        verdicts_env,
        "hash1",
        verdict="Malicious",
        sender="phisher@evil.example",
        evidence=[
            EvidenceItem(
                name="watchman_finding",
                finding=long_finding,
                weight=0.7123,
                direction="malicious",
            ),
            EvidenceItem(
                name="dmarc_check",
                finding="DMARC authentication result: pass (policy: none)",
                weight=0.45,
                direction="benign",
            ),
        ],
    )

    response = verdicts_env.client.get("/verdicts/hash1")

    assert response.status_code == 200
    body = response.text
    assert "watchman_finding" in body
    assert long_finding in body  # nothing truncated, no "…" substitution
    assert "0.7123" in body
    assert "malicious" in body
    assert "dmarc_check" in body
    assert "DMARC authentication result: pass (policy: none)" in body
    assert "0.45" in body
    assert "benign" in body


def test_verdict_detail_coverage_gap_renders_reason_and_empty_evidence(
    verdicts_env: VerdictsEnv,
) -> None:
    _persist(
        verdicts_env,
        "hash-gap",
        verdict="CoverageGap",
        sender=None,
        evidence=[],
        calibrated_confidence=None,
        coverage_gap_reason="Failed to fetch raw message content: HttpError 404",
    )

    response = verdicts_env.client.get("/verdicts/hash-gap")

    assert response.status_code == 200
    body = response.text
    assert "Failed to fetch raw message content" in body
    assert "N/A" in body


def test_verdict_detail_unknown_hash_returns_404(verdicts_env: VerdictsEnv) -> None:
    response = verdicts_env.client.get("/verdicts/no-such-hash")
    assert response.status_code == 404


# --- Defensive rendering against malformed-but-decryptable records ---------
# [Review, Blind Hunter] read_recent_evidence_records only guarantees the
# required KEYS are present, never that their VALUES are well-typed. These
# reproduce the two confirmed crash paths and confirm the fix.


def test_verdict_list_malformed_confidence_value_renders_no_number_not_crash(
    verdicts_env: VerdictsEnv,
) -> None:
    """[Story 10.3, AC4] The list route's badge shows the verdict with no
    number for an unusable confidence -- not "N/A" (that display moved
    into the badge's own convention, distinct from the detail route's
    dedicated "Confidence: N/A" line, which is unchanged)."""
    report = _make_report(verdict="Malicious", calibrated_confidence=0.9)
    report["calibrated_confidence"] = "not-a-number"  # type: ignore[typeddict-item]
    _persist_raw(
        verdicts_env,
        "hash-bad-conf",
        {
            "message_id": "hash-bad-conf",
            "sender": "alice@example.com",
            "report": report,
            "deferral_threshold_used": verdicts_env.config.deferral_threshold,
        },
    )

    response = verdicts_env.client.get("/verdicts")

    assert response.status_code == 200
    assert '<span class="badge badge-malicious">Malicious</span>' in response.text


def test_verdict_detail_malformed_confidence_value_renders_na_not_crash(
    verdicts_env: VerdictsEnv,
) -> None:
    report = _make_report(verdict="Malicious", calibrated_confidence=0.9)
    report["calibrated_confidence"] = "not-a-number"  # type: ignore[typeddict-item]
    _persist_raw(
        verdicts_env,
        "hash-bad-conf",
        {
            "message_id": "hash-bad-conf",
            "sender": "alice@example.com",
            "report": report,
            "deferral_threshold_used": verdicts_env.config.deferral_threshold,
        },
    )

    response = verdicts_env.client.get("/verdicts/hash-bad-conf")

    assert response.status_code == 200
    assert "Confidence: N/A" in response.text


def test_verdict_detail_malformed_evidence_item_skipped_not_crash(
    verdicts_env: VerdictsEnv,
) -> None:
    good_item = EvidenceItem(
        name="watchman_finding", finding="A real finding", weight=0.7, direction="malicious"
    )
    bad_item = {"name": "broken_item", "finding": "missing its weight", "direction": "malicious"}
    report = _make_report(verdict="Malicious", evidence=[good_item])
    report["evidence"] = [good_item, bad_item]  # type: ignore[list-item]
    _persist_raw(
        verdicts_env,
        "hash-bad-item",
        {
            "message_id": "hash-bad-item",
            "sender": "alice@example.com",
            "report": report,
            "deferral_threshold_used": verdicts_env.config.deferral_threshold,
        },
    )

    response = verdicts_env.client.get("/verdicts/hash-bad-item")

    assert response.status_code == 200
    body = response.text
    assert "A real finding" in body
    assert "1 evidence item(s) could not be rendered" in body


def test_malformed_verdict_value_with_injection_payload_is_escaped_in_badge(
    verdicts_env: VerdictsEnv,
) -> None:
    """[Story 10.2, AC6] The new _badge() helper builds a CSS class slug
    from the same value used for display text (verdict/direction). Same
    well-formedness gap as calibrated_confidence/timestamp: only the KEY
    is guaranteed present, never that the VALUE is one of the four real
    Verdict literals. A malformed value must stay inert in both the
    visible badge text and the class attribute it's used to build --
    checked on both the list route (verdict badge) and detail route
    (verdict badge + evidence-item direction badge, a distinct code
    path since _is_well_formed_evidence_item never validates direction's
    value, only weight's type)."""
    payload = '"><script>alert(1)</script>'
    report = _make_report(verdict="Malicious", evidence=[])
    report["verdict"] = payload  # type: ignore[typeddict-item]
    bad_direction_item = {
        "name": "watchman_finding",
        "finding": "some finding",
        "weight": 0.5,
        "direction": payload,
    }
    report["evidence"] = [bad_direction_item]  # type: ignore[list-item]
    _persist_raw(
        verdicts_env,
        "hash-bad-verdict",
        {
            "message_id": "hash-bad-verdict",
            "sender": "alice@example.com",
            "report": report,
            "deferral_threshold_used": verdicts_env.config.deferral_threshold,
        },
    )

    list_response = verdicts_env.client.get("/verdicts")
    detail_response = verdicts_env.client.get("/verdicts/hash-bad-verdict")

    for response in (list_response, detail_response):
        assert response.status_code == 200
        assert "<script>alert" not in response.text
        assert "&lt;script&gt;" in response.text


def test_badge_with_embedded_whitespace_does_not_spoof_a_real_css_class() -> None:
    """[Review, Edge Case Hunter] A malformed value containing whitespace
    (e.g. "malicious x") would otherwise produce class="badge
    badge-malicious x" -- HTML splits on whitespace, so badge-malicious
    (a real, defined rule) would spuriously match and color the badge as
    Malicious for a value that isn't. Not an escaping test (no injection
    possible either way) -- this is a display-correctness regression
    guard on _badge()'s own slug construction."""
    rendered = verdicts_mod._badge("malicious x")
    assert 'class="badge badge-maliciousx"' in rendered
    assert "badge-malicious x" not in rendered
    assert ">malicious x<" in rendered  # text stays fully intact and correct


def test_verdict_list_timestamp_with_script_tag_is_escaped(
    verdicts_env: VerdictsEnv,
) -> None:
    """[Review, Edge Case Hunter] Mutation-test finding: _format_display_
    timestamp's malformed-value fallback path echoes the raw value with
    no escaping of its own -- correctness today relies entirely on the
    call-site _esc() wrapper in both routes, and that specific point had
    no dedicated regression test (unlike sender/finding/coverage_gap_
    reason/verdict, which all do). Pins it directly: an unparseable
    timestamp carrying a script tag must still render inert."""
    payload = '<script>alert("ts")</script>'
    report = _make_report(verdict="Malicious")
    report["timestamp"] = payload  # type: ignore[typeddict-item]
    _persist_raw(
        verdicts_env,
        "hash-bad-ts",
        {
            "message_id": "hash-bad-ts",
            "sender": "alice@example.com",
            "report": report,
            "deferral_threshold_used": verdicts_env.config.deferral_threshold,
        },
    )

    list_response = verdicts_env.client.get("/verdicts")
    detail_response = verdicts_env.client.get("/verdicts/hash-bad-ts")

    for response in (list_response, detail_response):
        assert response.status_code == 200
        assert "<script>alert" not in response.text
        assert "&lt;script&gt;" in response.text


# --- Story 10.2, AC4/AC5: presentation structure ----------------------------


def test_page_includes_inline_style_no_cdn_no_script(verdicts_env: VerdictsEnv) -> None:
    """AC5: styling is inline/served only -- no CSS framework, no CDN link,
    no build step, no JavaScript of any kind (Out of scope)."""
    response = verdicts_env.client.get("/verdicts")
    body = response.text
    assert "<style>" in body
    assert "<link" not in body
    assert "<script" not in body
    assert "cdn." not in body.lower()


def test_verdict_badge_carries_both_color_class_and_text(verdicts_env: VerdictsEnv) -> None:
    """AC4: verdict must be visually distinguishable AND never rely on
    color alone -- the escaped text stays present alongside the CSS class."""
    _persist(verdicts_env, "hash1", verdict="Malicious")

    response = verdicts_env.client.get("/verdicts")

    assert 'class="badge badge-malicious"' in response.text
    assert ">Malicious<" in response.text


def test_evidence_items_render_as_grouped_blocks_not_table_rows(
    verdicts_env: VerdictsEnv,
) -> None:
    """AC4: each finding's name/weight/direction/text grouped per item
    (a bordered block with a header line) rather than running together
    in table cells."""
    _persist(
        verdicts_env,
        "hash1",
        verdict="Malicious",
        evidence=[
            EvidenceItem(
                name="watchman_finding",
                finding="Suspicious login URL",
                weight=0.7,
                direction="malicious",
            )
        ],
    )

    response = verdicts_env.client.get("/verdicts/hash1")
    body = response.text

    assert '<ul class="evidence-list">' in body
    assert '<li class="evidence-item">' in body
    assert '<div class="evidence-header">' in body
    assert '<span class="evidence-name">watchman_finding</span>' in body
    assert 'class="evidence-weight"' in body
    assert '<p class="evidence-finding">Suspicious login URL</p>' in body


# --- AC5: demo route and /quota unaffected ----------------------------------


def test_quota_route_still_works(verdicts_env: VerdictsEnv) -> None:
    response = verdicts_env.client.get("/quota")
    assert response.status_code == 200
    assert "remaining" in response.json()


def test_demo_analyze_stream_still_works(verdicts_env: VerdictsEnv) -> None:
    response = verdicts_env.client.post(
        "/analyze/stream", json={"scenario_slug": "google-benign"}
    )
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]


# --- AC6: stored-XSS resistance ---------------------------------------------


_XSS_SENDER = '<script>alert("xss")</script>@evil.example'


def test_sender_with_script_tag_is_escaped_in_list(verdicts_env: VerdictsEnv) -> None:
    _persist(verdicts_env, "hash1", verdict="Malicious", sender=_XSS_SENDER)

    response = verdicts_env.client.get("/verdicts")

    assert response.status_code == 200
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;" in response.text


def test_sender_with_script_tag_is_escaped_in_detail(verdicts_env: VerdictsEnv) -> None:
    _persist(verdicts_env, "hash1", verdict="Malicious", sender=_XSS_SENDER)

    response = verdicts_env.client.get("/verdicts/hash1")

    assert response.status_code == 200
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;" in response.text


def test_finding_text_with_script_tag_is_escaped_in_detail(verdicts_env: VerdictsEnv) -> None:
    _persist(
        verdicts_env,
        "hash1",
        verdict="Malicious",
        evidence=[
            EvidenceItem(
                name="watchman_finding",
                finding='<img src=x onerror=alert(1)>',
                weight=0.7,
                direction="malicious",
            )
        ],
    )

    response = verdicts_env.client.get("/verdicts/hash1")

    assert response.status_code == 200
    assert "<img src=x onerror" not in response.text
    assert "&lt;img" in response.text


def test_coverage_gap_reason_with_script_tag_is_escaped(verdicts_env: VerdictsEnv) -> None:
    _persist(
        verdicts_env,
        "hash-gap",
        verdict="CoverageGap",
        sender=None,
        evidence=[],
        calibrated_confidence=None,
        coverage_gap_reason='<script>alert("gap")</script>',
    )

    response = verdicts_env.client.get("/verdicts/hash-gap")

    assert response.status_code == 200
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;" in response.text


# --- run_in_executor bridge: proves it genuinely dispatches off the event loop ---


def test_verdict_list_concurrent_requests_do_not_serialize_on_event_loop(
    verdicts_env: VerdictsEnv,
) -> None:
    """[Review, Edge Case Hunter] Both routes bridge the synchronous, disk-
    I/O-plus-Fernet-decrypt _load_records() through loop.run_in_executor so
    it doesn't block the event loop. A mutation test during review (calling
    _load_records() directly, bypassing run_in_executor) found NO existing
    test noticed -- the bridge was correct but unverified. This proves it:
    patches _load_records with an artificial 0.2s delay and fires 4
    concurrent requests through a real ASGI async client (TestClient's sync
    wrapper can't exercise genuine concurrency). If the bridge were removed
    and requests instead serialized on the event loop, 4 requests would take
    ~0.8s; genuine thread-pool dispatch keeps it close to one delay."""
    real_load_records = verdicts_mod._load_records

    def _slow_load_records() -> tuple[list, str | None]:  # type: ignore[type-arg]
        time.sleep(0.2)
        return real_load_records()

    async def _fire_concurrent_requests() -> float:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            start = time.monotonic()
            responses = await asyncio.gather(*(client.get("/verdicts") for _ in range(4)))
            elapsed = time.monotonic() - start
        assert all(r.status_code == 200 for r in responses)
        return elapsed

    with patch.object(verdicts_mod, "_load_records", _slow_load_records):
        elapsed = asyncio.run(_fire_concurrent_requests())

    # Serialized on the event loop: ~4 x 0.2s = 0.8s. Genuinely concurrent
    # (dispatched to a thread pool): close to one delay. 0.6s is a
    # comfortable line between the two, not a tight timing assertion.
    assert elapsed < 0.6, f"requests appear serialized on the event loop ({elapsed:.3f}s)"


# --- Story 10.3: header bar, live status, summary strip ---------------------


def _write_raw_health_state(env: VerdictsEnv, raw: str) -> None:
    Path(env.db_path).with_name("health_state.json").write_text(raw)


def test_header_shows_product_name_on_both_pages(verdicts_env: VerdictsEnv) -> None:
    """AC1: a header bar with the product name on both the list and
    detail pages."""
    _persist(verdicts_env, "hash1", verdict="Malicious")

    list_response = verdicts_env.client.get("/verdicts")
    detail_response = verdicts_env.client.get("/verdicts/hash1")

    for response in (list_response, detail_response):
        assert '<header class="app-header">' in response.text
        assert ">Sentinel<" in response.text


def test_header_status_healthy_shows_text_and_last_poll_time(
    verdicts_env: VerdictsEnv,
) -> None:
    """AC1/AC2: alert_active=False -> Healthy, with the last successful
    poll time formatted in Eastern (same convention as Story 10.2)."""
    save_health_state(
        verdicts_env.db_path,
        {"last_success_utc": "2026-08-20T19:10:00+00:00", "alert_active": False},
    )

    response = verdicts_env.client.get("/verdicts")

    assert response.status_code == 200
    assert '<span class="badge badge-healthy">Healthy' in response.text
    assert "Aug 20, 2026 3:10 PM" in response.text  # EDT


def test_header_status_unhealthy_uses_alert_active(verdicts_env: VerdictsEnv) -> None:
    """AC2: alert_active is the sole discriminator between healthy and
    unhealthy."""
    save_health_state(
        verdicts_env.db_path,
        {"last_success_utc": "2026-08-20T19:10:00+00:00", "alert_active": True},
    )

    response = verdicts_env.client.get("/verdicts")

    assert '<span class="badge badge-unhealthy">Unhealthy' in response.text
    assert '<span class="badge badge-healthy">' not in response.text


def test_header_status_unhealthy_with_no_successful_poll_ever(
    verdicts_env: VerdictsEnv,
) -> None:
    """AC2: alert_active=True can co-occur with last_success_utc=None (the
    poll has never once succeeded -- health.py's own _threshold_exceeded
    fires immediately in that case). Must still show Unhealthy, not
    Unknown -- the operator has already been alerted about exactly this;
    the dashboard must not soften that signal."""
    save_health_state(verdicts_env.db_path, {"last_success_utc": None, "alert_active": True})

    response = verdicts_env.client.get("/verdicts")

    assert (
        '<span class="badge badge-unhealthy">Unhealthy — no successful poll recorded</span>'
        in response.text
    )


def test_header_status_unknown_when_health_file_missing(verdicts_env: VerdictsEnv) -> None:
    """AC6: the health state file may be missing -- must render as
    Unknown, not error, not silently render Healthy."""
    response = verdicts_env.client.get("/verdicts")

    assert response.status_code == 200
    assert '<span class="badge badge-unknown">Unknown</span>' in response.text


def test_header_status_unknown_when_health_file_corrupt(verdicts_env: VerdictsEnv) -> None:
    """AC6: the health state file may be unreadable/corrupt (Notes for
    dev: "possibly mid-write") -- same Unknown outcome as missing, not a
    crash and not a silent Healthy default."""
    _write_raw_health_state(verdicts_env, "{not valid json, mid-write")

    response = verdicts_env.client.get("/verdicts")

    assert response.status_code == 200
    assert '<span class="badge badge-unknown">Unknown</span>' in response.text


def test_header_status_unknown_when_server_not_configured() -> None:
    """AC6: no config at all (state._config is None) means there is no
    evidence_db_path to even locate the health file from -- also Unknown,
    not a crash."""
    with patch(
        "sentinel.web.main.load_config",
        side_effect=ConfigError("Missing required environment variable: ANTHROPIC_API_KEY"),
    ):
        with TestClient(app) as client:
            response = client.get("/verdicts")
    assert response.status_code == 200
    assert '<span class="badge badge-unknown">Unknown</span>' in response.text


def test_header_status_with_injected_timestamp_is_escaped(verdicts_env: VerdictsEnv) -> None:
    """AC8: health_state.json is written by a separate cron process --
    treated as untrusted the same way record fields are. A hand-tampered
    last_success_utc must still render inert."""
    import json as _json

    payload = '<script>alert("health")</script>'
    raw = _json.dumps({"last_success_utc": payload, "alert_active": False})
    _write_raw_health_state(verdicts_env, raw)

    response = verdicts_env.client.get("/verdicts")

    assert response.status_code == 200
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;" in response.text


def test_summary_strip_shows_total_and_per_verdict_counts(verdicts_env: VerdictsEnv) -> None:
    """AC3: total and per-verdict counts, computed from the store, not
    hardcoded -- verified against a specific, known distribution."""
    _persist(verdicts_env, "hash1", verdict="Malicious")
    _persist(verdicts_env, "hash2", verdict="Malicious")
    _persist(verdicts_env, "hash3", verdict="Benign")
    _persist(
        verdicts_env,
        "hash4",
        verdict="CoverageGap",
        sender=None,
        evidence=[],
        calibrated_confidence=None,
        coverage_gap_reason="gap",
    )

    response = verdicts_env.client.get("/verdicts")
    body = response.text

    assert '<span class="summary-total">4 total</span>' in body
    assert '<span class="badge badge-malicious">Malicious 2</span>' in body
    assert '<span class="badge badge-benign">Benign 1</span>' in body
    assert '<span class="badge badge-deferred">Deferred 0</span>' in body
    assert '<span class="badge badge-coveragegap">CoverageGap 1</span>' in body


def test_summary_strip_unhashable_verdict_value_does_not_crash(
    verdicts_env: VerdictsEnv,
) -> None:
    """[Review, Blind Hunter] Well-formedness only guarantees "verdict" is
    a present key, never that its value is a string -- a corrupted record
    could have it decrypt to a list or dict. `verdict in counts` on an
    unhashable value raised an uncaught TypeError, crashing the ENTIRE
    list route for every visitor (this runs unconditionally over the full
    list, not per-filtered-request). Must render cleanly instead: the
    malformed record still counts toward the total, just not toward any
    per-verdict bucket."""
    _persist(verdicts_env, "hash-good", verdict="Malicious")
    report = _make_report(verdict="Malicious")
    report["verdict"] = ["Malicious"]  # type: ignore[typeddict-item]
    _persist_raw(
        verdicts_env,
        "hash-bad-verdict-list",
        {
            "message_id": "hash-bad-verdict-list",
            "sender": "alice@example.com",
            "report": report,
            "deferral_threshold_used": verdicts_env.config.deferral_threshold,
        },
    )

    response = verdicts_env.client.get("/verdicts")

    assert response.status_code == 200
    assert '<span class="summary-total">2 total</span>' in response.text
    assert '<span class="badge badge-malicious">Malicious 1</span>' in response.text


def test_summary_strip_reflects_full_store_not_the_active_filter(
    verdicts_env: VerdictsEnv,
) -> None:
    """AC3: the strip is a stable overview of the whole store -- it must
    not change to reflect only the currently-filtered subset."""
    _persist(verdicts_env, "hash1", verdict="Malicious")
    _persist(verdicts_env, "hash2", verdict="Benign")

    response = verdicts_env.client.get("/verdicts", params={"verdict": "Benign"})
    body = response.text

    assert '<span class="summary-total">2 total</span>' in body
    assert '<span class="badge badge-malicious">Malicious 1</span>' in body


def test_summary_strip_not_present_on_detail_page(verdicts_env: VerdictsEnv) -> None:
    """AC3 places the strip "above the filter links", which exist only on
    the list page -- the detail page must not render it. Checks for the
    actual element, not the bare class-name substring, which also appears
    in every page's shared <style> block (the CSS rule itself)."""
    _persist(verdicts_env, "hash1", verdict="Malicious")

    response = verdicts_env.client.get("/verdicts/hash1")

    assert '<div class="summary-strip">' not in response.text


def test_sender_placeholder_exact_wording_in_list_and_detail(verdicts_env: VerdictsEnv) -> None:
    """AC5: a specific, clear placeholder -- not an empty cell -- for a
    CoverageGap record's null sender, on both routes."""
    _persist(
        verdicts_env,
        "hash-gap",
        verdict="CoverageGap",
        sender=None,
        evidence=[],
        calibrated_confidence=None,
        coverage_gap_reason="gap",
    )

    list_response = verdicts_env.client.get("/verdicts")
    detail_response = verdicts_env.client.get("/verdicts/hash-gap")

    for response in (list_response, detail_response):
        assert "Message unavailable" in response.text
        assert "<td></td>" not in response.text


def test_verdict_badge_folds_in_confidence_for_real_records(verdicts_env: VerdictsEnv) -> None:
    """AC4: a positive case matching the AC's own worked example exactly
    ("Malicious 1.00")."""
    _persist(verdicts_env, "hash1", verdict="Malicious", calibrated_confidence=1.0)

    response = verdicts_env.client.get("/verdicts")

    assert '<span class="badge badge-malicious">Malicious 1.00</span>' in response.text
