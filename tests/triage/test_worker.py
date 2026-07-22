import hashlib

import pytest

from sentinel.config import Config, ConfigError
from sentinel.triage.ingest import FetchFailed, fetch_headers_for_messages
from sentinel.triage.worker import process_message


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
