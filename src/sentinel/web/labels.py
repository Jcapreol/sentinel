"""Human labelling of verdict records (Story 11.1).

Separate storage from evidence.db, per D1 in docs/labelling-design.md: the
evidence record is what the system concluded at a moment in time, tamper-
evident by design; a label is a human disagreeing later, and belongs
somewhere that cannot mutate that record even by accident. Follows
sentinel.triage.health's health_state.json precedent -- a small JSON file,
sibling of evidence.db, atomically written (temp file + Path.replace(), the
same chain as store.py's persist_evidence_record and eval.py's
save_calibration_model) -- with one deliberate deviation from that
precedent: see save_label's own docstring for why writes here raise on
failure where save_health_state never does, and see the module docstring
section below for why the note field is encrypted where health_state.json
is not.

This module never imports sqlite3 or cryptography.fernet directly (AC4,
enforced by tests/web/test_verdicts.py's test_web_imports_no_direct_db_or_
crypto_access) -- Fernet key handling reuses sentinel.triage.store's public
require_fernet rather than duplicating key validation here, and this module
never touches evidence_records at all, structurally: it has no SQL, no
sqlite3 import, and does not import any of store.py's write-capable
functions (persist_evidence_record, purge_expired, save_history_checkpoint)
-- the same test's extended check bans those imports anywhere under web/.

Why the note field is encrypted, unlike health_state.json: health.py's own
docstring justifies plaintext specifically because that file "holds only a
timestamp and a boolean, nothing about email content." A label's free-text
note is deliberately the opposite -- AC1 requires it, and a human writing
"this one had a fake DocuSign link" is exactly the kind of content-adjacent
commentary evidence.db's own encryption (and its explicit choice to never
persist raw content at all, FR21) exists to keep off disk in the clear.
message_hash/label/timestamp stay plaintext (none is sensitive; message_hash
is a one-way hash, label is the human's own conclusion, timestamp is just a
time) -- only the note value is Fernet-encrypted, under the same key
evidence.db already uses (see require_fernet's own docstring for why a
second key was not introduced).
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypedDict

from sentinel.config import Config
from sentinel.triage.store import require_fernet

Label = Literal["confirmed-phishing", "confirmed-benign", "unclear"]
VALID_LABELS: tuple[Label, ...] = ("confirmed-phishing", "confirmed-benign", "unclear")


class LabelEntry(TypedDict):
    label: Label
    timestamp: str
    note: str


_NOTE_UNAVAILABLE_NO_KEY = "(note unavailable — no encryption key configured)"
_NOTE_UNAVAILABLE_UNDECRYPTABLE = "(note unavailable — could not decrypt; key may have changed)"

# [Story 11.1] Serializes the read-modify-write-rename sequence in
# save_label against concurrent calls WITHIN this process. Sufficient for
# the actual deployment (a single uvicorn process, per Story 10.3's own
# established model, not multiple worker processes) -- without it, two
# label-set requests handled concurrently by the run_in_executor thread
# pool (proven genuinely concurrent by Story 10.1's own regression test)
# could both read the same starting file, each modify a DIFFERENT entry,
# and the second writer's atomic rename would silently discard the
# first writer's change -- a whole-file overwrite race, not a per-entry
# one. A human who just clicked "save" must not have that silently lost.
_LABELS_LOCK = threading.Lock()


def _labels_path(db_path: str) -> Path:
    """Sibling of evidence.db, mirroring health.py's _health_state_path
    exactly -- e.g. data/evidence.db -> data/labels.json."""
    return Path(db_path).with_name("labels.json")


def load_labels(db_path: str, config: Config) -> dict[str, LabelEntry]:
    """Never raises. A missing, corrupt, or unreadable labels file degrades
    to {} (no labels) -- the same "first run ever" default a genuinely
    fresh deployment starts with, matching health.load_health_state's own
    read-path philosophy. Per-entry, not whole-file: an individual entry
    with an unparseable shape is skipped (not counted, not raised on) so
    one bad entry can't hide every other label; an entry whose note fails
    to decrypt (missing/rotated encryption key) keeps its label and
    timestamp and gets a placeholder note rather than being dropped
    entirely -- the label itself is still real, useful ground truth even
    if its free-text commentary is temporarily unreadable."""
    path = _labels_path(db_path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}

    try:
        fernet = require_fernet(config)
    except Exception:
        fernet = None

    result: dict[str, LabelEntry] = {}
    for message_hash, entry in raw.items():
        # message_hash needs no isinstance check: JSON's own grammar only
        # permits string object keys, so anything that survived json.loads
        # above already guarantees this -- only entry (a VALUE, which JSON
        # places no type constraint on) needs checking here.
        if not isinstance(entry, dict):
            continue
        label = entry.get("label")
        timestamp = entry.get("timestamp")
        encrypted_note = entry.get("note")
        if (
            label not in VALID_LABELS
            or not isinstance(timestamp, str)
            or not isinstance(encrypted_note, str)
        ):
            continue
        if fernet is None:
            note = _NOTE_UNAVAILABLE_NO_KEY
        else:
            try:
                note = fernet.decrypt(encrypted_note.encode("ascii")).decode("utf-8")
            except Exception:
                note = _NOTE_UNAVAILABLE_UNDECRYPTABLE
        result[message_hash] = LabelEntry(label=label, timestamp=timestamp, note=note)
    return result


def save_label(db_path: str, config: Config, message_hash: str, label: Label, note: str) -> None:
    """[Notes for dev] Deliberately RAISES on any failure, unlike
    save_health_state, which never does. A background heartbeat write
    silently degrading to "try again next cycle" is correct -- nothing is
    waiting on it. A label a human just clicked submit on is different:
    they believe it was recorded the moment they see a result. Silently
    dropping it would be worse than an error, because there would be
    nothing to prompt them to retry. The caller (the web route) is
    expected to catch this and show a clear failure, not redirect as if
    it succeeded.

    Also refuses to write over an existing labels.json it could not
    parse, rather than silently treating a corrupt file as empty and
    overwriting it with a fresh file containing only this one label --
    that would be a silent, irreversible loss of every prior label. This
    is stricter than load_labels' read-path degradation on purpose: a
    read that returns "no labels" is safe (nothing lost, can retry once
    the file is fixed); a write that "successfully" replaces a real file
    it never actually read is not.

    Atomic write: temp file in the same directory, then Path.replace() --
    the same chain as save_calibration_model (which cites
    persist_evidence_record) -- not a new pattern. Guarded by
    _LABELS_LOCK for the whole read-modify-write-rename sequence; see
    that lock's own module-level comment."""
    if label not in VALID_LABELS:
        raise ValueError(f"invalid label {label!r} — must be one of {VALID_LABELS}")
    fernet = require_fernet(config)
    path = _labels_path(db_path)

    with _LABELS_LOCK:
        if path.exists():
            try:
                existing_raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"{path} exists but could not be read as JSON "
                    f"({type(exc).__name__}: {exc}) — refusing to overwrite it, since that "
                    "would silently discard every existing label. Fix or remove the file "
                    "manually, then retry."
                ) from exc
            if not isinstance(existing_raw, dict):
                raise RuntimeError(
                    f"{path} does not contain a JSON object at its top level — refusing to "
                    "overwrite it, since that would silently discard whatever is actually "
                    "in it."
                )
        else:
            existing_raw = {}

        encrypted_note = fernet.encrypt(note.encode("utf-8")).decode("ascii")
        existing_raw[message_hash] = {
            "label": label,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": encrypted_note,
        }

        parent = path.parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f"{path.name}.tmp-{uuid.uuid4().hex}")
        tmp_path.write_text(json.dumps(existing_raw), encoding="utf-8")
        tmp_path.replace(path)
