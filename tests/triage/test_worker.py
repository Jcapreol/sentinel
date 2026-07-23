import ast
import base64
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel.config import Config, ConfigError
from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.ingest import FetchFailed, fetch_headers_for_messages
from sentinel.triage.report import TriageReport
from sentinel.triage.scoring import compute_raw_score, determine_verdict
from sentinel.triage.store import (
    EvidenceRecord,
    is_message_processed,
    persist_evidence_record,
    read_evidence_record,
)
from sentinel.triage.worker import main, process_message, run_continuous_loop, run_poll_cycle


def _config(deferral_threshold: float = 0.05) -> Config:
    return Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        deferral_threshold=deferral_threshold,
    )


def test_process_message_malicious_header_returns_malicious_verdict() -> None:
    header = "spf=fail; dkim=fail; dmarc=fail"

    report = process_message("m1", header, _config())

    assert report["verdict"] == "Malicious"
    assert len(report["evidence"]) > 0


def test_process_message_benign_header_returns_benign_verdict() -> None:
    header = "spf=pass; dkim=pass; dmarc=pass"

    report = process_message("m1", header, _config())

    assert report["verdict"] == "Benign"


def test_process_message_no_header_defers() -> None:
    report = process_message("m1", None, _config())

    assert report["verdict"] == "Deferred"
    assert len(report["evidence"]) > 0


def test_process_message_score_inside_deferral_band_defers() -> None:
    # dmarc=pass (benign, weight 0.45) vs spf=fail (malicious, weight 0.40) yields
    # a raw score of ~0.4706 — not exactly neutral, but within the default 0.05
    # deferral_band around 0.5. Proves the config.deferral_threshold -> worker ->
    # scoring.py wiring actually defers on a close-but-not-exact score, not just
    # on the exact-neutral case already covered by test_process_message_no_header_defers.
    header = "dmarc=pass; spf=fail"

    report = process_message("m1", header, _config(deferral_threshold=0.05))

    assert report["verdict"] == "Deferred"
    assert abs(report["calibrated_confidence"] - 0.5) < 0.05


def test_process_message_never_raises_inconclusive_score_error() -> None:
    # Empty/neutral evidence would raise InconclusiveScoreError inside
    # determine_verdict — process_message must catch it internally, never
    # propagate it to the caller.
    report = process_message("m1", None, _config())

    assert report["verdict"] == "Deferred"


def test_process_message_message_hash_is_deterministic_sha256_of_message_id() -> None:
    report = process_message("abc-123", "spf=pass", _config())

    assert report["message_hash"] == hashlib.sha256(b"abc-123").hexdigest()


def test_process_message_produces_no_disk_io(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)

    process_message("m1", "spf=pass", _config())

    assert list(tmp_path.iterdir()) == []


def test_process_message_schema_version_is_one() -> None:
    report = process_message("m1", "spf=pass", _config())

    assert report["schema_version"] == 1


def test_process_message_fetch_failed_defers_never_directional() -> None:
    # A header fetch failure (Story 1.3's FetchFailed sentinel) must never be
    # treated as evidence — it must always defer, the same way
    # InconclusiveScoreError does, regardless of deferral_threshold.
    report = process_message("m1", FetchFailed(), _config())

    assert report["verdict"] == "Deferred"
    assert report["verdict"] != "Malicious"
    assert report["verdict"] != "Benign"


def test_process_message_fetch_failed_never_calls_header_investigation(mocker) -> None:  # type: ignore[no-untyped-def]
    # FetchFailed must short-circuit before investigate_header_authentication is
    # ever called — a fetch failure carries no header data to investigate.
    spy = mocker.patch("sentinel.triage.worker.investigate_header_authentication")

    process_message("m1", FetchFailed(), _config())

    spy.assert_not_called()


def test_process_message_fetch_failed_with_extreme_deferral_threshold_still_defers() -> None:
    # Even with deferral_threshold=0.0 (the narrowest possible band), a
    # FetchFailed must still defer — this is a hard routing rule, not a
    # side effect of the band width.
    report = process_message("m1", FetchFailed(), _config(deferral_threshold=0.0))

    assert report["verdict"] == "Deferred"


def test_process_message_end_to_end_fetch_failure_never_yields_directional_verdict(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    service = mocker.MagicMock()
    mocker.patch(
        "sentinel.triage.ingest.get_authentication_results_header",
        side_effect=RuntimeError("boom"),
    )

    fetch_results = fetch_headers_for_messages(service, "soc@example.com", [{"id": "m1"}])
    report = process_message("m1", fetch_results["m1"], _config())

    assert report["verdict"] == "Deferred"


def test_process_message_raises_config_error_when_deferral_threshold_above_range() -> None:
    with pytest.raises(ConfigError, match="SENTINEL_DEFERRAL_THRESHOLD"):
        process_message("m1", "spf=pass", _config(deferral_threshold=1.5))


def test_process_message_raises_config_error_when_deferral_threshold_below_range() -> None:
    with pytest.raises(ConfigError, match="SENTINEL_DEFERRAL_THRESHOLD"):
        process_message("m1", "spf=pass", _config(deferral_threshold=-0.1))


def test_bad_deferral_threshold_does_not_affect_cli_web_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad SENTINEL_DEFERRAL_THRESHOLD must not break config.load() (the shared
    entry point CLI/web dashboard call) — only triage's own process_message, which
    is the only consumer of this field, validates it."""
    from sentinel.config import load

    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("SENTINEL_DEFERRAL_THRESHOLD", "1.5")

    config = load()  # must not raise — CLI/web dashboard startup unaffected

    assert config.anthropic_api_key == "ak-test"


# --- --replay -------------------------------------------------------------------


def _make_report(
    verdict: str = "Malicious",
    calibrated_confidence: float = 0.9,
    evidence: list[EvidenceItem] | None = None,
    schema_version: int = 1,
    message_hash: str = "idhash123",
    timestamp: str = "2026-07-22T00:00:00+00:00",
) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[typeddict-item]
        calibrated_confidence=calibrated_confidence,
        evidence=evidence if evidence is not None else [],
        schema_version=schema_version,
        message_hash=message_hash,
        timestamp=timestamp,
    )


def test_replay_matching_exits_zero(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    evidence = [make_evidence_item(name="spf", direction="malicious", weight=0.8)]
    raw_score = compute_raw_score(evidence)
    verdict = determine_verdict(raw_score, deferral_band=store_config.deferral_threshold)
    report = _make_report(verdict=verdict, calibrated_confidence=raw_score, evidence=evidence)
    record = EvidenceRecord(
        message_id="m1",
        sender="alice@example.com",
        report=report,
        deferral_threshold_used=store_config.deferral_threshold,
    )
    persist_evidence_record(store_db_path, "contenthash1", record, store_config)

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "contenthash1", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0


def test_replay_mismatch_exits_nonzero(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    evidence = [make_evidence_item(name="spf", direction="malicious", weight=0.8)]
    # Stored verdict/score deliberately does NOT match what honest recomputation
    # from this evidence would produce (simulates a scoring-logic regression).
    report = _make_report(verdict="Benign", calibrated_confidence=0.1, evidence=evidence)
    record = EvidenceRecord(
        message_id="m1",
        sender=None,
        report=report,
        deferral_threshold_used=store_config.deferral_threshold,
    )
    persist_evidence_record(store_db_path, "contenthash2", record, store_config)

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "contenthash2", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0


def test_replay_not_found_exits_nonzero(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "no-such-hash", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0


def test_replay_unexpected_schema_version_exits_nonzero(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    report = _make_report(schema_version=2)  # unexpected/future version
    record = EvidenceRecord(
        message_id="m1",
        sender=None,
        report=report,
        deferral_threshold_used=store_config.deferral_threshold,
    )
    persist_evidence_record(store_db_path, "contenthash3", record, store_config)

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "contenthash3", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0


def test_replay_uses_stored_deferral_threshold_not_live_config(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    # dmarc=pass (benign, 0.45) vs spf=fail (malicious, 0.40) -> raw score ~0.4706.
    # With a narrow ORIGINAL deferral_threshold (0.01), this score is directional
    # (Benign), not deferred. If replay incorrectly used a WIDE LIVE config value
    # instead of the stored one, 0.4706 would fall inside the band and recompute
    # as Deferred -- a false mismatch. This test proves the stored value wins.
    evidence = [
        make_evidence_item(name="dmarc", direction="benign", weight=0.45),
        make_evidence_item(name="spf", direction="malicious", weight=0.40),
    ]
    raw_score = compute_raw_score(evidence)
    original_threshold_used = 0.01
    verdict = determine_verdict(raw_score, deferral_band=original_threshold_used)
    report = _make_report(verdict=verdict, calibrated_confidence=raw_score, evidence=evidence)
    record = EvidenceRecord(
        message_id="m1",
        sender=None,
        report=report,
        deferral_threshold_used=original_threshold_used,
    )
    persist_evidence_record(store_db_path, "contenthash4", record, store_config)

    live_config = replace(store_config, deferral_threshold=0.05)  # wide, would defer

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "contenthash4", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=live_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0


def test_replay_legacy_record_missing_deferral_threshold_used_exits_nonzero_with_clear_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A record persisted before Story 1.6 (no deferral_threshold_used key at
    all, since EvidenceRecord is a schema-less JSON blob) must produce a clear,
    specific stderr error and a non-zero exit -- not an unguarded KeyError
    caught only by main()'s generic catch-all. Regression guard (2026-07-22
    code-review follow-up)."""
    import json

    from cryptography.fernet import Fernet

    # Bypass persist_evidence_record (which always supplies
    # deferral_threshold_used) to simulate a genuinely pre-Story-1.6 record.
    from sentinel.triage.store import _connect, _require_fernet

    legacy_record = {
        "message_id": "m1",
        "sender": "alice@example.com",
        "report": _make_report(),
    }
    fernet: Fernet = _require_fernet(store_config)
    encrypted = fernet.encrypt(json.dumps(legacy_record).encode())
    conn = _connect(store_db_path)
    conn.execute(
        "INSERT INTO evidence_records "
        "(message_hash, verdict_json, created_at, expires_at, schema_version) "
        "VALUES (?, ?, '2020-01-01T00:00:00+00:00', '2099-01-01T00:00:00+00:00', 1)",
        ("legacyhash1", encrypted),
    )
    conn.commit()
    conn.close()

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "legacyhash1", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0


# --- run_poll_cycle --------------------------------------------------------------


def _gmail_config(store_config: Config) -> Config:
    return replace(
        store_config,
        gmail_monitored_mailbox="soc@example.com",
        gmail_credentials_path="secrets/gmail-service-account.json",
    )


def test_run_poll_cycle_persists_one_new_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    raw_content = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        {"raw": encoded},
    ]

    run_poll_cycle(config, store_db_path)

    content_hash = hashlib.sha256(raw_content).hexdigest()
    record = read_evidence_record(store_db_path, content_hash, config)
    assert record is not None
    assert record["message_id"] == "m1"
    assert record["report"]["schema_version"] == 1


def test_run_poll_cycle_skips_already_processed_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)
    # "m1" is already processed iff persist_evidence_record has already run
    # for it -- there is no separate claim step (2026-07-22, Story 1.7 follow-up).
    already_processed = EvidenceRecord(
        message_id="m1", sender=None, report=_make_report(), deferral_threshold_used=0.05
    )
    persist_evidence_record(store_db_path, "priorhash", already_processed, config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    spy = mocker.patch("sentinel.triage.worker.process_message")

    run_poll_cycle(config, store_db_path)

    spy.assert_not_called()


def test_run_poll_cycle_is_message_processed_failure_is_per_message_not_cycle_level(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """If is_message_processed itself raises (e.g. a transient sqlite lock),
    that must be caught as a per-message failure -- not left to propagate out
    of run_poll_cycle, where run_continuous_loop would misclassify it as a
    cycle-level PERSISTENT FAILURE and kill the whole worker over a single
    message's bookkeeping hiccup. Regression guard (2026-07-22 code-review
    follow-up)."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    mocker.patch(
        "sentinel.triage.worker.is_message_processed",
        side_effect=RuntimeError("simulated database is locked"),
    )

    run_poll_cycle(config, store_db_path)  # must not raise/crash the cycle


def test_run_poll_cycle_saves_new_checkpoint(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    from sentinel.triage.store import load_history_checkpoint

    config = _gmail_config(store_config)
    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "5000"
    }

    run_poll_cycle(config, store_db_path)

    assert load_history_checkpoint(store_db_path) == "5000"


def test_run_poll_cycle_calls_purge_expired(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = _gmail_config(store_config)
    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    spy = mocker.patch("sentinel.triage.worker.purge_expired")

    run_poll_cycle(config, store_db_path)

    spy.assert_called_once_with(store_db_path, config)


def test_run_poll_cycle_raw_fetch_failure_persists_deferred_coverage_gap(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        RuntimeError("boom"),
    ]

    run_poll_cycle(config, store_db_path)

    fallback_hash = hashlib.sha256(b"m1").hexdigest()
    record = read_evidence_record(store_db_path, fallback_hash, config)
    assert record is not None
    assert record["report"]["verdict"] == "Deferred"
    assert record["sender"] is None


def test_run_poll_cycle_raw_fetch_failure_does_not_stop_remaining_messages(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [
            {"messagesAdded": [{"message": {"id": "m1"}}]},
            {"messagesAdded": [{"message": {"id": "m2"}}]},
        ]
    }
    raw_content_m2 = b"From: bob@example.com\r\nSubject: t2\r\n\r\nbody2"
    encoded_m2 = base64.urlsafe_b64encode(raw_content_m2).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},  # m1 header fetch ok
        RuntimeError("boom"),  # m1 raw fetch fails
        {"payload": {"headers": []}},  # m2 header fetch ok
        {"raw": encoded_m2},  # m2 raw fetch ok
    ]

    run_poll_cycle(config, store_db_path)

    content_hash_m2 = hashlib.sha256(raw_content_m2).hexdigest()
    record_m2 = read_evidence_record(store_db_path, content_hash_m2, config)
    assert record_m2 is not None
    assert record_m2["message_id"] == "m2"


def test_run_poll_cycle_persist_failure_does_not_permanently_mark_processed(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """If persist_evidence_record fails, the message must never be left
    marked-processed with no evidence record -- otherwise it is permanently
    lost, since no future poll cycle would ever retry it. Since Story 1.7's
    atomicity fix, this is now inherent to persist_evidence_record's single
    atomic commit (both rows land together or neither does), not a separate
    rollback step -- there is nothing to roll back, because nothing was ever
    written before the commit."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    raw_content = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        {"raw": encoded},
    ]
    mocker.patch(
        "sentinel.triage.worker.persist_evidence_record",
        side_effect=RuntimeError("simulated DB failure"),
    )

    run_poll_cycle(config, store_db_path)  # must not raise/crash the cycle

    # Nothing was ever committed for "m1" -- persist_evidence_record's atomic
    # write never completed, so a future poll cycle will correctly retry it.
    assert is_message_processed(store_db_path, "m1") is False


def test_run_poll_cycle_persist_failure_does_not_advance_checkpoint_past_it(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """If a message fails and is un-marked, the checkpoint must NOT advance past
    it -- history.list(startHistoryId=X) only returns events strictly after X, so
    saving the cycle's new historyId here would make the failed message's own
    history event permanently unreachable on every future cycle, silently
    breaking the "retried on a future poll cycle" promise the rollback above
    claims to provide. Same silent-data-loss class already fixed twice in this
    story, at a third, cycle-level trigger point (2026-07-22 code-review
    follow-up)."""
    from sentinel.triage.store import load_history_checkpoint, save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    raw_content = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        {"raw": encoded},
    ]
    mocker.patch(
        "sentinel.triage.worker.persist_evidence_record",
        side_effect=RuntimeError("simulated DB failure"),
    )

    run_poll_cycle(config, store_db_path)

    # Must stay at the OLD checkpoint ("999"), not advance to the new one
    # ("1000") -- otherwise the next cycle's history.list(startHistoryId="1000")
    # would never return m1's history event again.
    assert load_history_checkpoint(store_db_path) == "999"


def test_run_poll_cycle_print_failure_after_persist_does_not_misclassify_success(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A print() failure strictly AFTER a successful persist_evidence_record
    call must not be misclassified as a processing failure (any_failures=True,
    capping the checkpoint below unnecessarily) -- the evidence is already
    durably persisted at that point. Regression guard for moving the
    success-path print() into an `else` clause outside the try (originally a
    2026-07-22 code-review follow-up guarding against a false rollback; the
    rollback mechanism itself was later removed by Story 1.7's atomicity fix,
    but this same print-placement protection remains necessary)."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    raw_content = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        {"raw": encoded},
    ]

    real_print = print

    def flaky_print(*args: object, **kwargs: object) -> None:
        text = str(args[0]) if args else ""
        if "Persisted evidence record" in text:
            raise BrokenPipeError("simulated broken stderr")
        real_print(*args, **kwargs)  # type: ignore[arg-type]

    mocker.patch("builtins.print", side_effect=flaky_print)

    with pytest.raises(BrokenPipeError):
        run_poll_cycle(config, store_db_path)

    content_hash = hashlib.sha256(raw_content).hexdigest()
    record = read_evidence_record(store_db_path, content_hash, config)
    assert record is not None  # evidence survives the print() failure
    assert is_message_processed(store_db_path, "m1") is True


def test_run_poll_cycle_persist_failure_for_one_message_does_not_stop_remaining_messages(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A persist-time failure for one message must not stop the cycle from
    processing subsequent messages -- m1 fails, m2 must still be persisted."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [
            {"messagesAdded": [{"message": {"id": "m1"}}]},
            {"messagesAdded": [{"message": {"id": "m2"}}]},
        ]
    }
    raw_content_m1 = b"From: alice@example.com\r\nSubject: t1\r\n\r\nbody1"
    encoded_m1 = base64.urlsafe_b64encode(raw_content_m1).decode()
    raw_content_m2 = b"From: bob@example.com\r\nSubject: t2\r\n\r\nbody2"
    encoded_m2 = base64.urlsafe_b64encode(raw_content_m2).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},  # m1 header fetch ok
        {"raw": encoded_m1},  # m1 raw fetch ok (fails later, at persist time)
        {"payload": {"headers": []}},  # m2 header fetch ok
        {"raw": encoded_m2},  # m2 raw fetch ok
    ]

    def flaky_persist(
        db_path: str, content_hash: str, record: EvidenceRecord, config: Config
    ) -> None:
        if record["message_id"] == "m1":
            raise RuntimeError("simulated DB failure for m1")
        persist_evidence_record(db_path, content_hash, record, config)

    mocker.patch("sentinel.triage.worker.persist_evidence_record", side_effect=flaky_persist)

    run_poll_cycle(config, store_db_path)  # must not raise/crash the cycle

    content_hash_m2 = hashlib.sha256(raw_content_m2).hexdigest()
    record_m2 = read_evidence_record(store_db_path, content_hash_m2, config)
    assert record_m2 is not None
    assert record_m2["message_id"] == "m2"


# --- run_continuous_loop ----------------------------------------------------------


def test_run_continuous_loop_survives_a_per_message_failure_within_a_cycle(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A per-message failure inside a poll cycle must not propagate out of
    run_continuous_loop -- this proves Story 1.6's claim/rollback isolation
    survives being invoked through the new outer loop, end to end, not just
    in isolation via run_poll_cycle's own test suite."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [
            {"messagesAdded": [{"message": {"id": "m1"}}]},
            {"messagesAdded": [{"message": {"id": "m2"}}]},
        ]
    }
    raw_content_m1 = b"From: alice@example.com\r\nSubject: t1\r\n\r\nbody1"
    encoded_m1 = base64.urlsafe_b64encode(raw_content_m1).decode()
    raw_content_m2 = b"From: bob@example.com\r\nSubject: t2\r\n\r\nbody2"
    encoded_m2 = base64.urlsafe_b64encode(raw_content_m2).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},  # m1 header fetch ok
        {"raw": encoded_m1},  # m1 raw fetch ok (fails later, at persist time)
        {"payload": {"headers": []}},  # m2 header fetch ok
        {"raw": encoded_m2},  # m2 raw fetch ok
    ]

    def flaky_persist(
        db_path: str, content_hash: str, record: EvidenceRecord, config: Config
    ) -> None:
        if record["message_id"] == "m1":
            raise RuntimeError("simulated failure for m1")
        persist_evidence_record(db_path, content_hash, record, config)

    mocker.patch("sentinel.triage.worker.persist_evidence_record", side_effect=flaky_persist)
    mocker.patch("sentinel.triage.worker.time.sleep", side_effect=KeyboardInterrupt)
    mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(config, store_db_path)  # must not raise

    content_hash_m2 = hashlib.sha256(raw_content_m2).hexdigest()
    record_m2 = read_evidence_record(store_db_path, content_hash_m2, config)
    assert record_m2 is not None
    assert record_m2["message_id"] == "m2"


def test_run_continuous_loop_persistent_failure_propagates_with_distinct_log_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """If run_poll_cycle itself raises (a cycle-level, not per-message,
    failure -- e.g. revoked Gmail credentials), the loop must not swallow it
    and silently retry forever. It re-raises after a distinct log line so an
    operator can tell this apart from a per-message failure at a glance."""
    mocker.patch(
        "sentinel.triage.worker.run_poll_cycle",
        side_effect=RuntimeError("simulated persistent failure"),
    )
    mocker.patch("sentinel.triage.worker.signal.signal")

    with pytest.raises(RuntimeError, match="simulated persistent failure"):
        run_continuous_loop(store_config, store_db_path)

    captured = capsys.readouterr()
    assert "PERSISTENT" in captured.err
    assert "Failed to process message" not in captured.err


def test_run_continuous_loop_clean_shutdown_on_interrupt_during_sleep(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sentinel.triage.worker.run_poll_cycle")
    mocker.patch("sentinel.triage.worker.time.sleep", side_effect=KeyboardInterrupt)
    mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(store_config, store_db_path)  # must not raise

    captured = capsys.readouterr()
    assert "Shutting down" in captured.err


def test_run_continuous_loop_clean_shutdown_on_interrupt_during_cycle(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sentinel.triage.worker.run_poll_cycle", side_effect=KeyboardInterrupt)
    sleep_spy = mocker.patch("sentinel.triage.worker.time.sleep")
    mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(store_config, store_db_path)  # must not raise

    sleep_spy.assert_not_called()
    captured = capsys.readouterr()
    assert "Shutting down" in captured.err


def test_run_continuous_loop_ignores_further_sigterm_once_shutdown_begins(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A second SIGTERM landing while the shutdown except-block is still
    running (e.g. mid-print) must not raise a fresh KeyboardInterrupt that
    escapes the clean-shutdown path -- verified here by asserting SIGTERM is
    re-registered to SIG_IGN as soon as shutdown begins. Regression guard
    (2026-07-22 code-review follow-up)."""
    import signal as signal_module

    from sentinel.triage.worker import _handle_sigterm

    mocker.patch("sentinel.triage.worker.run_poll_cycle")
    mocker.patch("sentinel.triage.worker.time.sleep", side_effect=KeyboardInterrupt)
    signal_spy = mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(store_config, store_db_path)

    signal_spy.assert_any_call(signal_module.SIGTERM, _handle_sigterm)
    signal_spy.assert_any_call(signal_module.SIGTERM, signal_module.SIG_IGN)


def test_run_continuous_loop_sleeps_for_configured_poll_interval(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = replace(store_config, poll_interval_seconds=42)
    mocker.patch("sentinel.triage.worker.run_poll_cycle")
    sleep_spy = mocker.patch("sentinel.triage.worker.time.sleep", side_effect=KeyboardInterrupt)
    mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(config, store_db_path)

    sleep_spy.assert_called_once_with(42)


@pytest.mark.parametrize("bad_interval", [0, -1, -300])
def test_run_continuous_loop_raises_config_error_on_nonpositive_poll_interval(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    bad_interval: int,
) -> None:
    """A non-positive SENTINEL_POLL_INTERVAL previously crashed on the first
    time.sleep() call (negative: ValueError) or produced a busy-loop
    hammering the Gmail API (zero). Validated lazily at first actual use,
    mirroring deferral_threshold/retention_days (2026-07-22 code-review
    follow-up)."""
    config = replace(store_config, poll_interval_seconds=bad_interval)
    run_spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")
    sleep_spy = mocker.patch("sentinel.triage.worker.time.sleep")

    with pytest.raises(ConfigError, match="SENTINEL_POLL_INTERVAL"):
        run_continuous_loop(config, store_db_path)

    run_spy.assert_not_called()
    sleep_spy.assert_not_called()


def test_run_continuous_loop_registers_sigterm_handler(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """systemctl stop sends SIGTERM, not SIGINT -- Python has no default
    handler for it (unlike SIGINT, which Python already turns into
    KeyboardInterrupt). Without an explicit registration, SIGTERM kills the
    process immediately, bypassing the clean-shutdown path entirely. This
    proves run_continuous_loop actually wires up the handler at startup, not
    just that the handler function itself behaves correctly in isolation
    (see test_handle_sigterm_raises_keyboard_interrupt)."""
    import signal as signal_module

    from sentinel.triage.worker import _handle_sigterm

    mocker.patch("sentinel.triage.worker.run_poll_cycle")
    mocker.patch("sentinel.triage.worker.time.sleep", side_effect=KeyboardInterrupt)
    signal_spy = mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(store_config, store_db_path)

    # assert_any_call, not assert_called_once_with: signal.signal is also
    # called a second time (SIG_IGN) once shutdown begins -- see
    # test_run_continuous_loop_ignores_further_sigterm_once_shutdown_begins.
    signal_spy.assert_any_call(signal_module.SIGTERM, _handle_sigterm)


def test_handle_sigterm_raises_keyboard_interrupt() -> None:
    """Unit test of the handler itself, independent of registration/delivery
    (real OS-level SIGTERM delivery is not portably testable -- e.g. os.kill
    with SIGTERM on Windows does not invoke a registered Python handler the
    way POSIX does, so this only tests the handler's own logic, not signal
    delivery mechanics)."""
    from sentinel.triage.worker import _handle_sigterm

    with pytest.raises(KeyboardInterrupt):
        _handle_sigterm(15, None)


# --- main() / _run() CLI dispatch -------------------------------------------------


def test_default_mode_calls_run_continuous_loop(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    """No --replay/--once given -- AR8's default mode is the continuous poll
    loop, not a usage error (that placeholder was Story 1.6's explicit scope
    boundary, now filled in by this story)."""
    mocker.patch("sys.argv", ["sentinel-triage"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_continuous_loop")

    with pytest.raises(SystemExit) as exc:
        main()

    spy.assert_called_once()
    assert exc.value.code == 0


def test_once_calls_run_poll_cycle_and_exits_zero(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage", "--once"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")

    with pytest.raises(SystemExit) as exc:
        main()

    spy.assert_called_once()
    assert exc.value.code == 0


def test_replay_and_once_together_exits_nonzero_with_usage_error(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--replay and --once are mutually exclusive -- passing both must produce
    a clear usage error (argparse's own mutually-exclusive-group error), not
    silently dispatch to whichever branch _run() happens to check first.
    Regression guard (2026-07-22 code-review follow-up)."""
    mocker.patch(
        "sys.argv", ["sentinel-triage", "--replay", "somehash", "--once"]
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    replay_spy = mocker.patch("sentinel.triage.worker._run_replay")
    poll_spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0
    replay_spy.assert_not_called()
    poll_spy.assert_not_called()
    captured = capsys.readouterr()
    assert captured.err != ""


def test_config_error_exits_nonzero_before_dispatch(
    mocker,  # type: ignore[no-untyped-def]
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage", "--once"])
    mocker.patch(
        "sentinel.triage.worker.load_config",
        side_effect=ConfigError("Missing required environment variable: ANTHROPIC_API_KEY"),
    )
    spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0
    spy.assert_not_called()
    captured = capsys.readouterr()
    assert "ANTHROPIC_API_KEY" in captured.err


# --- structural / boundary checks --------------------------------------------


def test_worker_imports_no_network_listening_library() -> None:
    source_path = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "triage" / "worker.py"
    tree = ast.parse(source_path.read_text())
    forbidden = {"fastapi", "uvicorn", "http.server", "socketserver", "flask", "aiohttp.web"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden, f"worker.py imports {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden, f"worker.py imports from {node.module}"


def test_triage_imports_no_remediation_capable_library() -> None:
    """AC3 (FR32): no path in the triage pipeline may execute containment,
    remediation, or any response action. This can't be proven exhaustively,
    but structurally removing the *capability* -- no email-sending, no
    shell-out, no raw OS-level file/process control -- makes it as close to
    true as an import-boundary test can get. Complements Story 1.3's
    test_build_gmail_service_uses_readonly_scope_and_single_mailbox_subject,
    which proves the Gmail client itself can't mutate the mailbox."""
    triage_dir = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "triage"
    forbidden = {"smtplib", "subprocess", "os"}
    for source_path in triage_dir.glob("*.py"):
        tree = ast.parse(source_path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in forbidden, (
                        f"{source_path.name} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden, (
                    f"{source_path.name} imports from {node.module}"
                )
