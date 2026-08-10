import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Repo root, sibling to pyproject.toml -- mirrors scoring.py's
# _CALIBRATION_MODEL_PATH pattern (Path(__file__).resolve(), not CWD) so the
# default evidence-db location doesn't depend on the caller's working
# directory. parents[0]=sentinel, [1]=src, [2]=repo root.
_DEFAULT_EVIDENCE_DB_PATH = str(Path(__file__).resolve().parents[2] / "data" / "evidence.db")


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
    # "service_account" (default, existing Workspace domain-wide-delegation path)
    # or "oauth" (personal Gmail via triage/gmail_oauth.py). Validated lazily in
    # triage/ingest.py's build_gmail_service, mirroring the deferral_threshold/
    # retention_days pattern below -- load() is shared by the CLI and web
    # dashboard, which never use it.
    gmail_auth_mode: str = "service_account"
    # Defaults match harvest_own_inbox.py's own _DEFAULT_CLIENT_SECRET_PATH/
    # _DEFAULT_TOKEN_PATH literals (duplicated, not imported -- config.py is
    # foundation-layer and cannot depend on triage/*, per project-context.md's
    # import hierarchy). A maintainer who already did the one-time OAuth
    # consent for harvest_own_inbox.py needs to set only GMAIL_AUTH_MODE=oauth
    # to reuse that same cached token for live triage.
    gmail_oauth_client_secret_path: str | None = None
    gmail_oauth_token_path: str | None = None
    # [Review][Patch] Story 3.2's eval harness now exists (calibration_model_v1.json,
    # loaded/applied by triage/scoring.py), but this default is still a hardcoded
    # literal, not dynamically read from it -- config.py is a foundation-layer file
    # and deliberately does not import from triage/scoring.py or triage/eval.py (see
    # project-context.md's import hierarchy). calibration_model_v1.json's own
    # deferral_threshold_derived field documents what the calibration run recommends
    # (currently 0.05, matching this default, by deliberate placeholder design);
    # syncing a future non-0.05 recommendation into this literal is a manual step,
    # tracked in deferred-work.md, not automatic.
    deferral_threshold: float = 0.05
    evidence_encryption_key: str | None = None
    retention_days: int = 30
    eval_corpus_path: str | None = None
    # Always a concrete absolute path (unlike the Gmail/eval_corpus_path
    # fields) -- Story 5.1's read-only viewer command needs a definite
    # location to open, and a CWD-relative default was the root cause of a
    # real silent-empty-output bug (see triage-5-1's story file).
    evidence_db_path: str = _DEFAULT_EVIDENCE_DB_PATH


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
        gmail_auth_mode=os.environ.get("GMAIL_AUTH_MODE", "service_account"),
        gmail_oauth_client_secret_path=os.environ.get(
            "GMAIL_OAUTH_CLIENT_SECRET_PATH", "secrets/oauth-client.json"
        ),
        gmail_oauth_token_path=os.environ.get(
            "GMAIL_OAUTH_TOKEN_PATH", "secrets/oauth-token.json"
        ),
        deferral_threshold=deferral_threshold,
        evidence_encryption_key=os.environ.get("SENTINEL_EVIDENCE_KEY"),
        retention_days=retention_days,
        eval_corpus_path=os.environ.get("EVAL_CORPUS_PATH"),
        evidence_db_path=os.environ.get(
            "SENTINEL_EVIDENCE_DB_PATH", _DEFAULT_EVIDENCE_DB_PATH
        ),
    )
