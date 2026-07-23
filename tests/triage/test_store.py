import ast
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel.config import Config, ConfigError
from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.report import TriageReport
from sentinel.triage.store import (
    EvidenceRecord,
    load_history_checkpoint,
    mark_message_processed,
    persist_evidence_record,
    purge_expired,
    read_evidence_record,
    save_history_checkpoint,
)


def _make_report(
    evidence: list[EvidenceItem] | None = None,
    timestamp: str = "2026-07-22T00:00:00+00:00",
) -> TriageReport:
    return TriageReport(
        verdict="Malicious",
        calibrated_confidence=0.9,
        evidence=evidence if evidence is not None else [],
        schema_version=1,
        message_hash="idhash123",
        timestamp=timestamp,
    )


def _make_record(
    message_id: str = "m1",
    sender: str | None = "alice@example.com",
    report: TriageReport | None = None,
    deferral_threshold_used: float = 0.05,
) -> EvidenceRecord:
    return EvidenceRecord(
        message_id=message_id,
        sender=sender,
        report=report if report is not None else _make_report(),
        deferral_threshold_used=deferral_threshold_used,
    )


# --- persist_evidence_record / read_evidence_record ---------------------------


def test_persist_then_read_round_trips_exactly(
    store_db_path: str, store_config: Config, make_evidence_item: Callable[..., EvidenceItem]
) -> None:
    record = _make_record(
        report=_make_report(evidence=[make_evidence_item(name="spf", direction="malicious")])
    )

    persist_evidence_record(store_db_path, "contenthash1", record, store_config)
    result = read_evidence_record(store_db_path, "contenthash1", store_config)

    assert result == record


def test_read_missing_record_returns_none(store_db_path: str, store_config: Config) -> None:
    result = read_evidence_record(store_db_path, "no-such-hash", store_config)

    assert result is None


def test_persist_raises_config_error_when_key_missing(store_db_path: str) -> None:
    config = Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        evidence_encryption_key=None,
    )
    record = _make_record()

    with pytest.raises(ConfigError, match="SENTINEL_EVIDENCE_KEY"):
        persist_evidence_record(store_db_path, "contenthash1", record, config)


def test_persist_raises_config_error_when_key_malformed(store_db_path: str) -> None:
    config = Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        evidence_encryption_key="not-a-valid-fernet-key",
    )
    record = _make_record()

    with pytest.raises(ConfigError, match="Fernet"):
        persist_evidence_record(store_db_path, "contenthash1", record, config)


def test_persist_raises_config_error_when_retention_days_not_positive(
    store_db_path: str, store_config: Config
) -> None:
    bad_config = replace(store_config, retention_days=0)
    record = _make_record()

    with pytest.raises(ConfigError, match="SENTINEL_RETENTION_DAYS"):
        persist_evidence_record(store_db_path, "contenthash1", record, bad_config)


def test_purge_expired_raises_config_error_when_retention_days_not_positive(
    store_db_path: str, store_config: Config
) -> None:
    bad_config = replace(store_config, retention_days=-5)

    with pytest.raises(ConfigError, match="SENTINEL_RETENTION_DAYS"):
        purge_expired(store_db_path, bad_config)


def test_raw_sqlite_file_contains_no_plaintext_evidence_strings(
    store_db_path: str, store_config: Config, make_evidence_item: Callable[..., EvidenceItem]
) -> None:
    secret_finding = "spf=fail dkim=fail dmarc=fail SUPER_SECRET_MARKER"
    record = _make_record(
        report=_make_report(
            evidence=[make_evidence_item(name="spf", finding=secret_finding, direction="malicious")]
        )
    )

    persist_evidence_record(store_db_path, "contenthash1", record, store_config)

    raw_bytes = Path(store_db_path).read_bytes()
    assert b"SUPER_SECRET_MARKER" not in raw_bytes
    assert secret_finding.encode() not in raw_bytes


# --- purge_expired --------------------------------------------------------------


def test_purge_expired_deletes_past_records_keeps_future(
    store_db_path: str, store_config: Config
) -> None:
    record = _make_record()
    persist_evidence_record(store_db_path, "expired-hash", record, store_config)

    conn = sqlite3.connect(store_db_path)
    conn.execute(
        "UPDATE evidence_records SET expires_at = ? WHERE message_hash = ?",
        ("2000-01-01T00:00:00+00:00", "expired-hash"),
    )
    conn.commit()
    conn.close()

    persist_evidence_record(store_db_path, "future-hash", record, store_config)

    deleted_count = purge_expired(store_db_path, store_config)

    conn = sqlite3.connect(store_db_path)
    remaining = conn.execute("SELECT message_hash FROM evidence_records").fetchall()
    conn.close()

    assert deleted_count == 1
    assert remaining == [("future-hash",)]


# --- since_history_id checkpoint -------------------------------------------------


def test_checkpoint_round_trips(store_db_path: str) -> None:
    save_history_checkpoint(store_db_path, "12345")

    result = load_history_checkpoint(store_db_path)

    assert result == "12345"


def test_checkpoint_returns_none_when_never_saved(store_db_path: str) -> None:
    result = load_history_checkpoint(store_db_path)

    assert result is None


def test_checkpoint_second_save_overwrites_first_single_row(store_db_path: str) -> None:
    save_history_checkpoint(store_db_path, "111")
    save_history_checkpoint(store_db_path, "222")

    result = load_history_checkpoint(store_db_path)

    conn = sqlite3.connect(store_db_path)
    row_count = conn.execute("SELECT COUNT(*) FROM poll_checkpoint").fetchone()[0]
    conn.close()

    assert result == "222"
    assert row_count == 1


# --- mark_message_processed ------------------------------------------------------


def test_mark_message_processed_first_call_returns_true(store_db_path: str) -> None:
    assert mark_message_processed(store_db_path, "m1") is True


def test_mark_message_processed_second_call_same_id_returns_false(store_db_path: str) -> None:
    mark_message_processed(store_db_path, "m1")

    assert mark_message_processed(store_db_path, "m1") is False


def test_mark_message_processed_different_ids_both_return_true(store_db_path: str) -> None:
    assert mark_message_processed(store_db_path, "m1") is True
    assert mark_message_processed(store_db_path, "m2") is True


def test_purge_expired_removes_old_processed_message_ids(
    store_db_path: str, store_config: Config
) -> None:
    mark_message_processed(store_db_path, "old-id")

    conn = sqlite3.connect(store_db_path)
    conn.execute(
        "UPDATE processed_message_ids SET processed_at = ? WHERE message_id = ?",
        ("2000-01-01T00:00:00+00:00", "old-id"),
    )
    conn.commit()
    conn.close()

    mark_message_processed(store_db_path, "recent-id")

    purge_expired(store_db_path, store_config)

    conn = sqlite3.connect(store_db_path)
    remaining = conn.execute("SELECT message_id FROM processed_message_ids").fetchall()
    conn.close()

    assert remaining == [("recent-id",)]


# --- cross-cycle duplicate persist (AC6b) ----------------------------------------


def test_persist_same_message_hash_twice_yields_one_record_first_write_wins(
    store_db_path: str, store_config: Config
) -> None:
    first_record = _make_record(report=_make_report(timestamp="2026-01-01T00:00:00+00:00"))
    second_record = _make_record(report=_make_report(timestamp="2026-12-31T23:59:59+00:00"))

    persist_evidence_record(store_db_path, "samehash", first_record, store_config)
    persist_evidence_record(store_db_path, "samehash", second_record, store_config)

    conn = sqlite3.connect(store_db_path)
    row_count = conn.execute(
        "SELECT COUNT(*) FROM evidence_records WHERE message_hash = ?", ("samehash",)
    ).fetchone()[0]
    conn.close()

    result = read_evidence_record(store_db_path, "samehash", store_config)

    assert row_count == 1
    assert result is not None
    assert result["report"]["timestamp"] == "2026-01-01T00:00:00+00:00"


# --- structural / boundary checks ------------------------------------------------


def test_store_never_imports_ingest() -> None:
    source_path = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "triage" / "store.py"
    tree = ast.parse(source_path.read_text())
    forbidden = {"sentinel.triage.ingest", "ingest"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden, f"store.py imports {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden, f"store.py imports from {node.module}"
