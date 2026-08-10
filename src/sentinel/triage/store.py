"""Fernet-encrypted SQLite evidence store: persistence, retention/purge,
poll-checkpoint durability, and cross-cycle message dedup.

Never persists raw email body/attachment content (FR21) — only derived
EvidenceItems and source-identifying metadata, encrypted at rest.

Two complementary, non-redundant dedup mechanisms:

- ``is_message_processed`` (ID-based, read-only) is the primary, cheap
  mechanism. A polling loop MUST call it *before* fetching headers, fetching
  raw content (``ingest.fetch_raw_message_bytes``), or scoring — only
  proceed with that expensive pipeline if it returns ``False``. This is
  what actually avoids redundant Gmail API calls and redundant scoring work
  for a message already handled.
- ``evidence_records.message_hash`` (content-hash primary key, via
  ``INSERT OR IGNORE`` in ``persist_evidence_record``) is a storage-layer
  safety net, not a substitute for the check above. It only prevents a
  duplicate *row* — by the time a duplicate reaches ``persist_evidence_record``,
  the expensive work (raw-content fetch, hashing, scoring) has already run
  again.

``persist_evidence_record`` is the ONLY place ``processed_message_ids`` is
ever written — it inserts the evidence row and the processed-ID row in a
single transaction (one connection, one commit). This is deliberate: a
message is recorded as processed if and only if its evidence was also
durably persisted, in the very same atomic write. There is no separate
"claim" step, so there is no crash window where a hard process kill
(SIGKILL, OOM, power loss) between two writes could leave a message marked
processed with no evidence record to show for it — a residual risk flagged
during Story 1.6's code review (which could only guard against catchable
Python exceptions, never a hard kill) and closed here (2026-07-22, Story 1.7
follow-up).
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypedDict, cast

from cryptography.fernet import Fernet, InvalidToken

from sentinel.config import Config, ConfigError
from sentinel.triage.report import TriageReport


class EvidenceRecord(TypedDict):
    message_id: str
    sender: str | None
    report: TriageReport
    deferral_threshold_used: float


def _connect(db_path: str) -> sqlite3.Connection:
    parent = Path(db_path).parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_records (
            message_hash TEXT PRIMARY KEY,
            verdict_json BLOB NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            schema_version INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS poll_checkpoint (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            since_history_id TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS processed_message_ids (
            message_id TEXT PRIMARY KEY,
            processed_at TEXT NOT NULL
        )
        """
    )
    return conn


def _require_valid_retention_days(config: Config) -> None:
    if config.retention_days <= 0:
        raise ConfigError(
            f"SENTINEL_RETENTION_DAYS must be a positive integer, got "
            f"{config.retention_days!r}"
        )


def _require_fernet(config: Config) -> Fernet:
    if not config.evidence_encryption_key:
        raise ConfigError("Missing required environment variable: SENTINEL_EVIDENCE_KEY")
    try:
        return Fernet(config.evidence_encryption_key.encode())
    except Exception as e:
        raise ConfigError(
            "SENTINEL_EVIDENCE_KEY is not a valid Fernet key. Generate one with: "
            'python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        ) from e


def persist_evidence_record(
    db_path: str, message_hash: str, record: EvidenceRecord, config: Config
) -> None:
    """Atomically persists the evidence record AND marks record["message_id"]
    processed, in a single transaction (one connection, one commit). If
    anything fails before the commit — including a hard process kill — NEITHER
    row is written: the message is naturally retried by a future poll cycle,
    since is_message_processed will correctly report it as not yet processed."""
    fernet = _require_fernet(config)
    _require_valid_retention_days(config)
    plaintext = json.dumps(record).encode()
    encrypted = fernet.encrypt(plaintext)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=config.retention_days)

    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO evidence_records "
            "(message_hash, verdict_json, created_at, expires_at, schema_version) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                message_hash,
                encrypted,
                now.isoformat(),
                expires_at.isoformat(),
                record["report"]["schema_version"],
            ),
        )
        conn.execute(
            "INSERT OR IGNORE INTO processed_message_ids (message_id, processed_at) "
            "VALUES (?, ?)",
            (record["message_id"], now.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def read_evidence_record(
    db_path: str, message_hash: str, config: Config
) -> EvidenceRecord | None:
    fernet = _require_fernet(config)
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT verdict_json FROM evidence_records WHERE message_hash = ?",
            (message_hash,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    plaintext = fernet.decrypt(row[0])
    return cast(EvidenceRecord, json.loads(plaintext))


def _connect_read_only(db_path: str) -> sqlite3.Connection:
    """Genuinely read-only connection, enforced by SQLite itself (mode=ro
    URI) -- not merely "this caller happens not to call INSERT". Any write
    attempt raises sqlite3.OperationalError unconditionally, and a missing
    db file fails to open rather than silently creating an empty one
    (verified empirically on Windows during Story 5.1). Deliberately does
    NOT reuse _connect: that helper unconditionally runs CREATE TABLE IF
    NOT EXISTS on every call, which a real mode=ro connection rejects even
    when the table already exists and the statement would be a no-op."""
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


_REQUIRED_RECORD_KEYS = {"message_id", "sender", "report", "deferral_threshold_used"}
_REQUIRED_REPORT_KEYS = {"verdict", "calibrated_confidence", "evidence", "timestamp"}


def _is_well_formed_evidence_record(data: object) -> bool:
    """[Review] A row can decrypt successfully under the correct key and
    still not have the shape this codebase's EvidenceRecord/TriageReport
    TypedDicts assume -- e.g. a legacy record predating a schema field
    (real precedent: deferral_threshold_used was added in Story 1.6, per
    _run_replay's own guard for exactly this). Both adversarial reviewers
    independently reproduced a KeyError crash from an unguarded record
    like this reaching the --view table renderer. Checked here, once, so
    every caller of read_recent_evidence_records can trust the shape of
    whatever it gets back, the same way read_evidence_record's existing
    callers already implicitly do for well-formed data."""
    if not isinstance(data, dict) or not _REQUIRED_RECORD_KEYS.issubset(data.keys()):
        return False
    report = data["report"]
    return isinstance(report, dict) and _REQUIRED_REPORT_KEYS.issubset(report.keys())


def read_recent_evidence_records(
    db_path: str, config: Config
) -> tuple[list[tuple[str, EvidenceRecord]], int]:
    """Decrypts every row in evidence_records, most-recently-created first.
    Verdict isn't a SQL column (it lives inside the encrypted blob), so
    filtering by verdict and limiting the count are the caller's job, not
    this function's -- this returns everything so the caller can apply
    display policy on top. A row is skipped (never raised) for either of
    two reasons, both counted together in the second return value: it
    fails to decrypt under the current SENTINEL_EVIDENCE_KEY (e.g. a
    record from before a key rotation), or it decrypts fine but isn't
    valid JSON, or isn't shaped like a well-formed EvidenceRecord (see
    _is_well_formed_evidence_record)."""
    fernet = _require_fernet(config)
    conn = _connect_read_only(db_path)
    try:
        rows = conn.execute(
            "SELECT message_hash, verdict_json FROM evidence_records ORDER BY created_at DESC"
        ).fetchall()
    finally:
        conn.close()

    records: list[tuple[str, EvidenceRecord]] = []
    skipped = 0
    for message_hash, verdict_json in rows:
        try:
            plaintext = fernet.decrypt(verdict_json)
            parsed = json.loads(plaintext)
        except (InvalidToken, json.JSONDecodeError):
            skipped += 1
            continue
        if not _is_well_formed_evidence_record(parsed):
            skipped += 1
            continue
        records.append((message_hash, cast(EvidenceRecord, parsed)))
    return records, skipped


def purge_expired(db_path: str, config: Config) -> int:
    _require_valid_retention_days(config)
    now = datetime.now(timezone.utc)
    processed_ids_cutoff = (now - timedelta(days=config.retention_days)).isoformat()

    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "DELETE FROM evidence_records WHERE expires_at < ?", (now.isoformat(),)
        )
        deleted = cursor.rowcount
        conn.execute(
            "DELETE FROM processed_message_ids WHERE processed_at < ?",
            (processed_ids_cutoff,),
        )
        conn.commit()
        return deleted
    finally:
        conn.close()


def save_history_checkpoint(db_path: str, history_id: str) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO poll_checkpoint (id, since_history_id) VALUES (1, ?)",
            (history_id,),
        )
        conn.commit()
    finally:
        conn.close()


def load_history_checkpoint(db_path: str) -> str | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT since_history_id FROM poll_checkpoint WHERE id = 1"
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row is not None else None


def is_message_processed(db_path: str, message_id: str) -> bool:
    """Call this BEFORE fetching headers, fetching raw content
    (ingest.fetch_raw_message_bytes), or scoring — skip that work if this
    returns True. This is the cheap, ID-based check that avoids redundant
    Gmail API calls for a message already handled; it is not equivalent to
    relying on persist_evidence_record's content-hash INSERT OR IGNORE,
    which only prevents a duplicate row after the expensive work has already
    run again. Read-only: never writes to processed_message_ids —
    persist_evidence_record is the only writer, atomically alongside the
    evidence row."""
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM processed_message_ids WHERE message_id = ?", (message_id,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()
