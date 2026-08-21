from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from sentinel.config import Config, ConfigError
from sentinel.web.labels import VALID_LABELS, load_labels, save_label


@pytest.fixture
def labels_db_path(tmp_path: Path) -> str:
    return str(tmp_path / "evidence.db")


@pytest.fixture
def labels_config() -> Config:
    return Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        evidence_encryption_key=Fernet.generate_key().decode(),
    )


def _labels_file(db_path: str) -> Path:
    return Path(db_path).with_name("labels.json")


# --- load_labels: read-path degradation --------------------------------------


def test_load_labels_missing_file_returns_empty_dict(
    labels_db_path: str, labels_config: Config
) -> None:
    assert load_labels(labels_db_path, labels_config) == {}


def test_load_labels_corrupt_json_returns_empty_dict(
    labels_db_path: str, labels_config: Config
) -> None:
    _labels_file(labels_db_path).parent.mkdir(parents=True, exist_ok=True)
    _labels_file(labels_db_path).write_text("{not valid json", encoding="utf-8")

    assert load_labels(labels_db_path, labels_config) == {}


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        '"just a string"',
        "42",
    ],
)
def test_load_labels_non_object_top_level_returns_empty_dict(
    labels_db_path: str, labels_config: Config, raw: str
) -> None:
    _labels_file(labels_db_path).parent.mkdir(parents=True, exist_ok=True)
    _labels_file(labels_db_path).write_text(raw, encoding="utf-8")

    assert load_labels(labels_db_path, labels_config) == {}


def test_load_labels_malformed_entry_skipped_others_survive(
    labels_db_path: str, labels_config: Config
) -> None:
    """One bad entry (missing required keys, wrong label value, wrong
    types) must not hide every other label -- skipped per-entry, not a
    whole-file failure."""
    fernet = Fernet(labels_config.evidence_encryption_key.encode())  # type: ignore[union-attr]
    good_note = fernet.encrypt(b"a real note").decode("ascii")
    raw = {
        "hash-good": {"label": "confirmed-phishing", "timestamp": "2026-08-21T00:00:00+00:00", "note": good_note},
        "hash-bad-label": {"label": "not-a-real-label", "timestamp": "2026-08-21T00:00:00+00:00", "note": good_note},
        "hash-missing-timestamp": {"label": "unclear", "note": good_note},
        "hash-not-a-dict": "oops",
        "hash-note-not-a-string": {"label": "unclear", "timestamp": "2026-08-21T00:00:00+00:00", "note": 12345},
    }
    _labels_file(labels_db_path).parent.mkdir(parents=True, exist_ok=True)
    _labels_file(labels_db_path).write_text(json.dumps(raw), encoding="utf-8")

    labels = load_labels(labels_db_path, labels_config)

    assert set(labels.keys()) == {"hash-good"}
    assert labels["hash-good"]["label"] == "confirmed-phishing"
    assert labels["hash-good"]["note"] == "a real note"


def test_load_labels_note_decrypt_failure_keeps_label_with_placeholder(
    labels_db_path: str, labels_config: Config
) -> None:
    """A note encrypted under a DIFFERENT key (e.g. the encryption key was
    rotated) must not drop the whole entry -- label and timestamp are
    still real, useful ground truth even if the note is unreadable."""
    wrong_key_fernet = Fernet(Fernet.generate_key())
    undecryptable_note = wrong_key_fernet.encrypt(b"secret note").decode("ascii")
    raw = {
        "hash1": {
            "label": "confirmed-benign",
            "timestamp": "2026-08-21T00:00:00+00:00",
            "note": undecryptable_note,
        }
    }
    _labels_file(labels_db_path).parent.mkdir(parents=True, exist_ok=True)
    _labels_file(labels_db_path).write_text(json.dumps(raw), encoding="utf-8")

    labels = load_labels(labels_db_path, labels_config)

    assert labels["hash1"]["label"] == "confirmed-benign"
    assert labels["hash1"]["timestamp"] == "2026-08-21T00:00:00+00:00"
    assert "unavailable" in labels["hash1"]["note"].lower()


def test_load_labels_no_encryption_key_configured_keeps_label_with_placeholder(
    labels_db_path: str,
) -> None:
    """No SENTINEL_EVIDENCE_KEY at all -- require_fernet raises ConfigError.
    Must still surface label/timestamp with a placeholder note, not
    crash and not drop every label."""
    config_no_key = Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        evidence_encryption_key=None,
    )
    real_fernet = Fernet(Fernet.generate_key())
    raw = {
        "hash1": {
            "label": "unclear",
            "timestamp": "2026-08-21T00:00:00+00:00",
            "note": real_fernet.encrypt(b"note").decode("ascii"),
        }
    }
    _labels_file(labels_db_path).parent.mkdir(parents=True, exist_ok=True)
    _labels_file(labels_db_path).write_text(json.dumps(raw), encoding="utf-8")

    labels = load_labels(labels_db_path, config_no_key)

    assert labels["hash1"]["label"] == "unclear"
    assert "unavailable" in labels["hash1"]["note"].lower()


# --- save_label: write-path behavior ------------------------------------------


def test_save_label_then_load_round_trips(labels_db_path: str, labels_config: Config) -> None:
    save_label(labels_db_path, labels_config, "hash1", "confirmed-phishing", "fake DocuSign link")

    labels = load_labels(labels_db_path, labels_config)

    assert labels["hash1"]["label"] == "confirmed-phishing"
    assert labels["hash1"]["note"] == "fake DocuSign link"
    assert labels["hash1"]["timestamp"]  # non-empty ISO string


def test_save_label_note_is_encrypted_on_disk(labels_db_path: str, labels_config: Config) -> None:
    save_label(labels_db_path, labels_config, "hash1", "confirmed-phishing", "a secret detail")

    raw_disk_content = _labels_file(labels_db_path).read_text(encoding="utf-8")

    assert "a secret detail" not in raw_disk_content
    assert "hash1" in raw_disk_content  # message_hash itself stays plaintext
    assert "confirmed-phishing" in raw_disk_content  # label stays plaintext


def test_save_label_changes_existing_label(labels_db_path: str, labels_config: Config) -> None:
    save_label(labels_db_path, labels_config, "hash1", "confirmed-phishing", "first take")
    save_label(labels_db_path, labels_config, "hash1", "unclear", "actually not sure now")

    labels = load_labels(labels_db_path, labels_config)

    assert len(labels) == 1
    assert labels["hash1"]["label"] == "unclear"
    assert labels["hash1"]["note"] == "actually not sure now"


def test_save_label_preserves_other_entries(labels_db_path: str, labels_config: Config) -> None:
    save_label(labels_db_path, labels_config, "hash1", "confirmed-phishing", "note 1")
    save_label(labels_db_path, labels_config, "hash2", "confirmed-benign", "note 2")

    labels = load_labels(labels_db_path, labels_config)

    assert set(labels.keys()) == {"hash1", "hash2"}


def test_save_label_rejects_invalid_label_value(
    labels_db_path: str, labels_config: Config
) -> None:
    with pytest.raises(ValueError):
        save_label(labels_db_path, labels_config, "hash1", "definitely-phishing", "x")  # type: ignore[arg-type]

    assert not _labels_file(labels_db_path).exists()


def test_save_label_raises_without_encryption_key(labels_db_path: str) -> None:
    config_no_key = Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        evidence_encryption_key=None,
    )
    with pytest.raises(ConfigError):
        save_label(labels_db_path, config_no_key, "hash1", "unclear", "x")


def test_save_label_refuses_to_overwrite_corrupt_existing_file(
    labels_db_path: str, labels_config: Config
) -> None:
    """[Notes for dev] A human just clicked save -- silently treating a
    corrupt existing file as empty and overwriting it would discard every
    prior label without any signal that happened. Must raise instead."""
    _labels_file(labels_db_path).parent.mkdir(parents=True, exist_ok=True)
    _labels_file(labels_db_path).write_text("{not valid json, mid-write", encoding="utf-8")

    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        save_label(labels_db_path, labels_config, "hash1", "unclear", "x")

    # the corrupt file must be left untouched, not silently replaced
    assert _labels_file(labels_db_path).read_text(encoding="utf-8") == "{not valid json, mid-write"


def test_save_label_atomic_write_leaves_no_temp_file_behind(
    labels_db_path: str, labels_config: Config
) -> None:
    save_label(labels_db_path, labels_config, "hash1", "unclear", "x")

    siblings = list(Path(labels_db_path).parent.iterdir())
    tmp_files = [p for p in siblings if ".tmp-" in p.name]

    assert tmp_files == []


def test_save_label_propagates_a_genuine_write_failure(
    labels_db_path: str, labels_config: Config
) -> None:
    """[Review, Edge Case Hunter] Every other test of save_label's "raises
    on failure" claim (invalid label, missing key, corrupt existing file)
    exercises a PRE-write validation path -- none forced an actual OSError
    during the final write_text/replace, the step save_label's own
    docstring says is deliberately never swallowed (unlike save_health_
    state). A mutation test proved this gap empirically: temporarily
    wrapping that write in try/except OSError: pass broke nothing in the
    existing suite, and the route would have redirected as if the save
    succeeded while silently recording nothing -- the exact "human
    believes it worked" failure this design exists to prevent. Forces a
    real OSError from Path.write_text and confirms it propagates,
    unswallowed."""
    with pytest.raises(OSError, match="disk full"):
        with patch.object(Path, "write_text", side_effect=OSError("disk full")):
            save_label(labels_db_path, labels_config, "hash1", "unclear", "x")

    # nothing was recorded -- the failed write must not leave a labels.json
    # behind claiming success
    assert load_labels(labels_db_path, labels_config) == {}


def test_labels_file_is_sibling_of_evidence_db(tmp_path: Path) -> None:
    db_path = str(tmp_path / "evidence.db")
    config = Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        evidence_encryption_key=Fernet.generate_key().decode(),
    )
    save_label(db_path, config, "hash1", "unclear", "x")

    assert (tmp_path / "labels.json").exists()


def test_valid_labels_has_exactly_the_three_documented_values() -> None:
    assert VALID_LABELS == ("confirmed-phishing", "confirmed-benign", "unclear")


# --- concurrent-write safety --------------------------------------------------


def test_concurrent_saves_to_different_hashes_all_survive(
    labels_db_path: str, labels_config: Config
) -> None:
    """[D1/Notes for dev] Multiple label-set requests can genuinely run
    concurrently (Story 10.1's own run_in_executor thread pool proved
    this for reads; the same thread pool serves this write path). Without
    _LABELS_LOCK serializing the read-modify-write-rename sequence, two
    concurrent writers to DIFFERENT hashes could each read the same
    starting file, and the second writer's atomic rename would silently
    discard the first writer's change -- a whole-file race, not a
    per-entry one. 40 concurrent writers, 40 distinct hashes: every one
    must survive."""
    hashes = [f"hash{i}" for i in range(40)]
    with ThreadPoolExecutor(max_workers=40) as pool:
        futures = [
            pool.submit(save_label, labels_db_path, labels_config, h, "unclear", f"note for {h}")
            for h in hashes
        ]
        for f in futures:
            f.result()  # re-raise any exception from the worker thread

    labels = load_labels(labels_db_path, labels_config)

    assert set(labels.keys()) == set(hashes)
    for h in hashes:
        assert labels[h]["note"] == f"note for {h}"
