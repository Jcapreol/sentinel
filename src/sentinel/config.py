import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    anthropic_api_key: str
    virustotal_api_key: str
    abuseipdb_api_key: str
    urlhaus_api_key: str
    timeout_seconds: int = 10
    gmail_credentials_path: str | None = None
    gmail_monitored_mailbox: str | None = None
    poll_interval_seconds: int = 300
    deferral_threshold: float = 0.05  # PROVISIONAL: pre-Epic-3 placeholder — FR15 wants this
    # eval-harness-derived, but the eval harness (Story 3.2) doesn't exist yet. Revisit then.
    evidence_encryption_key: str | None = None
    retention_days: int = 30
    eval_corpus_path: str | None = None


def load() -> Config:
    missing = [
        var
        for var in (
            "ANTHROPIC_API_KEY",
            "VIRUSTOTAL_API_KEY",
            "ABUSEIPDB_API_KEY",
            "URLHAUS_API_KEY",
        )
        # Gmail vars are intentionally NOT required here — the CLI and web
        # dashboard never need them. Triage-specific fail-fast validation lives
        # in sentinel.triage.ingest.build_gmail_service().
        if not os.environ.get(var)
    ]
    if missing:
        raise ConfigError(f"Missing required environment variable: {missing[0]}")

    timeout_raw = os.environ.get("SENTINEL_TIMEOUT")
    timeout = int(timeout_raw) if timeout_raw else 10

    poll_interval_raw = os.environ.get("SENTINEL_POLL_INTERVAL")
    poll_interval = int(poll_interval_raw) if poll_interval_raw else 300

    deferral_threshold_raw = os.environ.get("SENTINEL_DEFERRAL_THRESHOLD")
    deferral_threshold = float(deferral_threshold_raw) if deferral_threshold_raw else 0.05
    # Deliberately NOT range-validated here — deferral_threshold is a triage-only
    # concern, like the Gmail fields and retention_days. load() is shared by the
    # CLI and web dashboard, which never use it; validating it here would mean a
    # bad SENTINEL_DEFERRAL_THRESHOLD breaks their startup too. Validated lazily
    # at first actual use in sentinel.triage.worker.process_message.

    retention_days_raw = os.environ.get("SENTINEL_RETENTION_DAYS")
    retention_days = int(retention_days_raw) if retention_days_raw else 30
    # Deliberately NOT range-validated here — retention_days is a triage-only
    # concern, like the Gmail fields. load() is shared by the CLI and web
    # dashboard, which never use it; validating it here would mean a bad
    # SENTINEL_RETENTION_DAYS breaks their startup too. Validated lazily at
    # first actual use in sentinel.triage.store, mirroring
    # build_gmail_service()'s fail-fast-at-point-of-use pattern.

    return Config(
        anthropic_api_key=os.environ["ANTHROPIC_API_KEY"],
        virustotal_api_key=os.environ["VIRUSTOTAL_API_KEY"],
        abuseipdb_api_key=os.environ["ABUSEIPDB_API_KEY"],
        urlhaus_api_key=os.environ["URLHAUS_API_KEY"],
        timeout_seconds=timeout,
        gmail_credentials_path=os.environ.get("GMAIL_SERVICE_ACCOUNT_KEY_PATH"),
        gmail_monitored_mailbox=os.environ.get("GMAIL_MONITORED_MAILBOX"),
        poll_interval_seconds=poll_interval,
        deferral_threshold=deferral_threshold,
        evidence_encryption_key=os.environ.get("SENTINEL_EVIDENCE_KEY"),
        retention_days=retention_days,
        eval_corpus_path=os.environ.get("EVAL_CORPUS_PATH"),
    )
