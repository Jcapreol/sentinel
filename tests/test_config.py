import pytest

from sentinel.config import ConfigError, load


def test_all_vars_present_default_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.delenv("SENTINEL_TIMEOUT", raising=False)

    config = load()

    assert config.anthropic_api_key == "ak-test"
    assert config.virustotal_api_key == "vt-test"
    assert config.abuseipdb_api_key == "ab-test"
    assert config.urlhaus_api_key == "uh-test"
    assert config.timeout_seconds == 10


def test_sentinel_timeout_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("SENTINEL_TIMEOUT", "15")

    config = load()

    assert config.timeout_seconds == 15


def test_missing_anthropic_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")

    with pytest.raises(ConfigError, match="ANTHROPIC_API_KEY"):
        load()


def test_missing_virustotal_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")

    with pytest.raises(ConfigError, match="VIRUSTOTAL_API_KEY"):
        load()


def test_missing_abuseipdb_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")

    with pytest.raises(ConfigError, match="ABUSEIPDB_API_KEY"):
        load()


def test_missing_urlhaus_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.delenv("URLHAUS_API_KEY", raising=False)

    with pytest.raises(ConfigError, match="URLHAUS_API_KEY"):
        load()


def test_gmail_fields_default_to_none_and_default_poll_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.delenv("GMAIL_SERVICE_ACCOUNT_KEY_PATH", raising=False)
    monkeypatch.delenv("GMAIL_MONITORED_MAILBOX", raising=False)
    monkeypatch.delenv("SENTINEL_POLL_INTERVAL", raising=False)

    config = load()

    assert config.gmail_credentials_path is None
    assert config.gmail_monitored_mailbox is None
    assert config.poll_interval_seconds == 300


def test_gmail_fields_and_poll_interval_parsed_when_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("GMAIL_SERVICE_ACCOUNT_KEY_PATH", "secrets/gmail-service-account.json")
    monkeypatch.setenv("GMAIL_MONITORED_MAILBOX", "soc@example.com")
    monkeypatch.setenv("SENTINEL_POLL_INTERVAL", "60")

    config = load()

    assert config.gmail_credentials_path == "secrets/gmail-service-account.json"
    assert config.gmail_monitored_mailbox == "soc@example.com"
    assert config.poll_interval_seconds == 60


def test_load_succeeds_without_any_gmail_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI/web dashboard must keep working with zero Gmail configuration."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.delenv("GMAIL_SERVICE_ACCOUNT_KEY_PATH", raising=False)
    monkeypatch.delenv("GMAIL_MONITORED_MAILBOX", raising=False)

    config = load()  # must not raise

    assert config.anthropic_api_key == "ak-test"


def test_deferral_threshold_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.delenv("SENTINEL_DEFERRAL_THRESHOLD", raising=False)

    config = load()

    assert config.deferral_threshold == 0.05


def test_deferral_threshold_parsed_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("SENTINEL_DEFERRAL_THRESHOLD", "0.1")

    config = load()

    assert config.deferral_threshold == 0.1


def test_load_does_not_raise_on_deferral_threshold_above_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI/web dashboard startup must not break on a triage-only misconfiguration —
    deferral_threshold is validated lazily at first use in worker.py, not eagerly
    here, mirroring the retention_days/Gmail-field pattern (see test_worker.py for
    the actual range-validation tests)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("SENTINEL_DEFERRAL_THRESHOLD", "1.5")

    config = load()  # must not raise

    assert config.deferral_threshold == 1.5


def test_load_does_not_raise_on_deferral_threshold_below_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("SENTINEL_DEFERRAL_THRESHOLD", "-0.1")

    config = load()  # must not raise

    assert config.deferral_threshold == -0.1


def test_evidence_encryption_key_defaults_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY", raising=False)

    config = load()

    assert config.evidence_encryption_key is None


def test_evidence_encryption_key_parsed_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY", "some-fernet-key")

    config = load()

    assert config.evidence_encryption_key == "some-fernet-key"


def test_retention_days_defaults_to_thirty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.delenv("SENTINEL_RETENTION_DAYS", raising=False)

    config = load()

    assert config.retention_days == 30


def test_retention_days_parsed_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("SENTINEL_RETENTION_DAYS", "60")

    config = load()

    assert config.retention_days == 60


def test_load_does_not_raise_on_zero_retention_days(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI/web dashboard startup must not break on a triage-only misconfiguration —
    retention_days is validated lazily at first use in sentinel.triage.store,
    not eagerly here, mirroring the Gmail-field pattern (see test_store.py for
    the actual range-validation tests)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("SENTINEL_RETENTION_DAYS", "0")

    config = load()  # must not raise

    assert config.retention_days == 0


def test_load_does_not_raise_on_negative_retention_days(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("SENTINEL_RETENTION_DAYS", "-5")

    config = load()  # must not raise

    assert config.retention_days == -5


def test_load_succeeds_without_evidence_key_or_retention_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI/web dashboard must keep working with zero evidence-store configuration."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_RETENTION_DAYS", raising=False)

    config = load()  # must not raise

    assert config.anthropic_api_key == "ak-test"


def test_config_is_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.delenv("SENTINEL_TIMEOUT", raising=False)

    from dataclasses import FrozenInstanceError

    config = load()
    with pytest.raises(FrozenInstanceError):
        config.anthropic_api_key = "mutated"  # type: ignore[misc]
