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
    assert "2026-08-20T12:00:00" in body
    assert "phisher@evil.example" in body
    assert "Malicious" in body
    assert "0.870" in body


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
    """[Story 6.1 model, AC2] CoverageGap has sender: null and
    calibrated_confidence: None -- must render "N/A", never crash, and
    never show 0.000/0.500 (either would look like a real measurement)."""
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
    assert "CoverageGap" in body
    assert "N/A" in body
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


def test_verdict_list_malformed_confidence_value_renders_na_not_crash(
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

    response = verdicts_env.client.get("/verdicts")

    assert response.status_code == 200
    assert "N/A" in response.text


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
