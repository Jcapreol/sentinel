import subprocess
from pathlib import Path

from sentinel.triage.eval import load_corpus, validate_corpus

_PROVENANCE_TEXT = (
    "Sourced from a synthetic test fixture generated for unit testing purposes. "
    "This is not real harvested data; see tests/triage/test_eval.py."
)


_PLAIN_BODY = "Hi, just checking in about our meeting tomorrow. Thanks!"
_PHISHING_ADJACENT_BODY = (
    "URGENT ACTION REQUIRED: Please verify your account within 24 hours or it "
    "will be suspended. Click here to confirm your identity."
)


def _write_eml(path: Path, subject: str, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = f"From: test@example.com\r\nSubject: {subject}\r\n"
    path.write_bytes((headers + "\r\n" + body).encode())


def _write_class(
    root: Path,
    cls: str,
    tuning_count: int,
    held_out_count: int,
    bodies: list[str] | None = None,
    include_provenance: bool = True,
    provenance_text: str | None = _PROVENANCE_TEXT,
    duplicate_across_splits: bool = False,
) -> None:
    """Writes `tuning_count` + `held_out_count` uniquely-content .eml files into
    root/cls/tuning and root/cls/held_out. `bodies` (if given) is cycled across
    all files in order to control content-level diversity (see
    _PHISHING_ADJACENT_PATTERN); defaults to a plain, non-phishing-adjacent
    body. `duplicate_across_splits=True` makes the first held_out file byte-
    identical to the first tuning file (to test overlap detection)."""
    if include_provenance:
        (root / cls).mkdir(parents=True, exist_ok=True)
        (root / cls / "PROVENANCE.md").write_text(provenance_text or "", encoding="utf-8")

    body_choices = bodies or [_PLAIN_BODY]
    counter = 0
    for i in range(tuning_count):
        body = f"{body_choices[i % len(body_choices)]} (unique marker {counter})"
        _write_eml(root / cls / "tuning" / f"{cls}-tuning-{i}.eml", f"Subject {counter}", body)
        counter += 1
    for i in range(held_out_count):
        if duplicate_across_splits and i == 0 and tuning_count > 0:
            # Byte-identical to tuning's first file -> same content hash.
            first_tuning = (root / cls / "tuning" / f"{cls}-tuning-0.eml").read_bytes()
            path = root / cls / "held_out" / f"{cls}-held_out-{i}.eml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(first_tuning)
            continue
        body = f"{body_choices[i % len(body_choices)]} (unique marker {counter})"
        _write_eml(root / cls / "held_out" / f"{cls}-held_out-{i}.eml", f"Subject {counter}", body)
        counter += 1


def _write_valid_corpus(root: Path) -> None:
    """40 samples per class (comfortably above the 30-sample minimum), split
    20/20 tuning/held_out, both classes present, PROVENANCE.md present for
    both, and benign diversity comfortably above the 10% minimum (half of
    benign samples use phishing-adjacent content, half plain)."""
    _write_class(
        root,
        "benign",
        tuning_count=20,
        held_out_count=20,
        bodies=[_PLAIN_BODY, _PHISHING_ADJACENT_BODY],
    )
    _write_class(
        root,
        "malicious",
        tuning_count=20,
        held_out_count=20,
        bodies=[_PHISHING_ADJACENT_BODY],
    )


def test_valid_corpus_passes_with_no_reasons(tmp_path: Path) -> None:
    _write_valid_corpus(tmp_path)

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is True
    assert result["reasons"] == []


def test_missing_benign_class_is_rejected(tmp_path: Path) -> None:
    _write_valid_corpus(tmp_path)
    import shutil

    shutil.rmtree(tmp_path / "benign")

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("no benign samples" in r.lower() for r in result["reasons"])


def test_missing_malicious_class_is_rejected(tmp_path: Path) -> None:
    _write_valid_corpus(tmp_path)
    import shutil

    shutil.rmtree(tmp_path / "malicious")

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("no malicious samples" in r.lower() for r in result["reasons"])


def test_undersized_class_is_rejected(tmp_path: Path) -> None:
    _write_valid_corpus(tmp_path)
    import shutil

    shutil.rmtree(tmp_path / "benign")
    _write_class(tmp_path, "benign", tuning_count=5, held_out_count=5)

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("only 10 unique benign samples" in r.lower() for r in result["reasons"])


def test_missing_held_out_split_is_rejected(tmp_path: Path) -> None:
    _write_valid_corpus(tmp_path)
    import shutil

    shutil.rmtree(tmp_path / "benign" / "held_out")

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("held_out" in r.lower() and "benign" in r.lower() for r in result["reasons"])


def test_missing_tuning_split_is_rejected(tmp_path: Path) -> None:
    _write_valid_corpus(tmp_path)
    import shutil

    shutil.rmtree(tmp_path / "malicious" / "tuning")

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("tuning" in r.lower() and "malicious" in r.lower() for r in result["reasons"])


def test_overlapping_content_between_splits_is_rejected(tmp_path: Path) -> None:
    _write_valid_corpus(tmp_path)
    import shutil

    shutil.rmtree(tmp_path / "malicious")
    _write_class(
        tmp_path,
        "malicious",
        tuning_count=20,
        held_out_count=20,
        bodies=[_PHISHING_ADJACENT_BODY],
        duplicate_across_splits=True,
    )

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("tuning split and a" in r.lower() and "held_out split" in r.lower() for r in result["reasons"])


def test_missing_provenance_file_is_rejected(tmp_path: Path) -> None:
    _write_valid_corpus(tmp_path)
    (tmp_path / "benign" / "PROVENANCE.md").unlink()

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("provenance" in r.lower() for r in result["reasons"])


def test_empty_provenance_file_is_rejected(tmp_path: Path) -> None:
    _write_valid_corpus(tmp_path)
    (tmp_path / "malicious" / "PROVENANCE.md").write_text("", encoding="utf-8")

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("provenance" in r.lower() and "short" in r.lower() for r in result["reasons"])


def test_insufficient_benign_diversity_is_rejected(tmp_path: Path) -> None:
    """All benign samples are plain, non-phishing-adjacent content -- only
    easy negatives, none of the realistic false-positive-prone traffic
    FR31 requires."""
    _write_valid_corpus(tmp_path)
    import shutil

    shutil.rmtree(tmp_path / "benign")
    _write_class(
        tmp_path,
        "benign",
        tuning_count=20,
        held_out_count=20,
        bodies=[_PLAIN_BODY],
    )

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("easy negatives" in r.lower() or "diversity" in r.lower() or "phishing-adjacent" in r.lower() for r in result["reasons"])


def test_multiple_simultaneous_failures_are_all_reported(tmp_path: Path) -> None:
    """Missing malicious class AND missing benign provenance at once -- both
    reasons must appear, not just the first one encountered."""
    _write_valid_corpus(tmp_path)
    import shutil

    shutil.rmtree(tmp_path / "malicious")
    (tmp_path / "benign" / "PROVENANCE.md").unlink()

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("no malicious samples" in r.lower() for r in result["reasons"])
    assert any("provenance" in r.lower() for r in result["reasons"])
    assert len(result["reasons"]) >= 2


def test_validate_corpus_never_raises_on_unparseable_eml_files(tmp_path: Path) -> None:
    _write_valid_corpus(tmp_path)
    garbage_path = tmp_path / "benign" / "tuning" / "garbage.eml"
    garbage_path.write_bytes(b"\xff\xfe\x00\x01 not a valid email at all")

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)  # must not raise

    assert isinstance(result["is_valid"], bool)


def test_load_corpus_never_raises_on_missing_directory(tmp_path: Path) -> None:
    corpus = load_corpus(str(tmp_path / "does-not-exist"))
    result = validate_corpus(corpus)  # must not raise

    assert result["is_valid"] is False


def test_load_corpus_computes_content_hash_per_file(tmp_path: Path) -> None:
    _write_eml(tmp_path / "benign" / "tuning" / "a.eml", "test subject", "hello world")

    corpus = load_corpus(str(tmp_path))

    assert len(corpus["benign_tuning"]) == 1
    assert len(corpus["benign_tuning"][0]["content_hash"]) == 64  # sha256 hex digest length


def test_benign_corpus_raw_default_location_is_gitignored() -> None:
    """Mirrors test_ingest.py's test_gmail_credential_default_location_is_gitignored
    -- don't rely on a human remembering to keep real corpus data out of git.
    benign_corpus_raw/ (1000 real harvested .eml files, see harvest_own_inbox.py)
    is the actual, known corpus-data location that exists today; EVAL_CORPUS_PATH
    itself is a user-configurable path with no default, so it can't be tested the
    same way -- this test protects the one concrete location this project
    actually has real data sitting in."""
    repo_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        ["git", "check-ignore", "benign_corpus_raw/"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "expected benign_corpus_raw/ to be gitignored — "
        f"git check-ignore exited {result.returncode}: {result.stderr}"
    )


# --- Code-review patches (2026-07-23) ---


def test_class_presence_counts_unique_content_not_raw_file_count(tmp_path: Path) -> None:
    """N copies of the identical file must not satisfy the minimum-sample-count
    check -- duplicate content provides no real diversity."""
    _write_valid_corpus(tmp_path)
    import shutil

    shutil.rmtree(tmp_path / "benign")
    (tmp_path / "benign").mkdir(parents=True)
    (tmp_path / "benign" / "PROVENANCE.md").write_text(_PROVENANCE_TEXT, encoding="utf-8")
    # 40 byte-identical copies (same content, different filenames) -- raw file
    # count clears _MIN_SAMPLES_PER_CLASS (30), but unique content does not.
    tuning_dir = tmp_path / "benign" / "tuning"
    tuning_dir.mkdir(parents=True)
    (tmp_path / "benign" / "held_out").mkdir(parents=True)
    identical_content = b"From: t@example.com\r\nSubject: same\r\n\r\nidentical body"
    for i in range(40):
        (tuning_dir / f"dup-{i}.eml").write_bytes(identical_content)

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("unique" in r.lower() and "benign" in r.lower() for r in result["reasons"])


def test_benign_diversity_matches_line_wrapped_phishing_adjacent_text(tmp_path: Path) -> None:
    """A line-wrapped/multi-whitespace phishing-adjacent phrase must still be
    detected -- real plain-text email is routinely line-wrapped."""
    _write_valid_corpus(tmp_path)
    import shutil

    shutil.rmtree(tmp_path / "benign")
    wrapped_body = "Please verify\nyour account   within 24 hours or it will be suspended."
    _write_class(
        tmp_path,
        "benign",
        tuning_count=20,
        held_out_count=20,
        bodies=[wrapped_body],
    )

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is True
    assert result["reasons"] == []


def test_benign_diversity_denominator_excludes_unreadable_files(tmp_path: Path, mocker) -> None:  # type: ignore[no-untyped-def]
    """A file that fails its second, independent read (inside
    _check_benign_diversity) must not count against the diversity fraction's
    denominator -- only successfully-read files should be assessed."""
    _write_valid_corpus(tmp_path)
    # All benign bodies are phishing-adjacent -> should trivially pass 10%.
    import shutil

    shutil.rmtree(tmp_path / "benign")
    _write_class(
        tmp_path,
        "benign",
        tuning_count=20,
        held_out_count=20,
        bodies=[_PHISHING_ADJACENT_BODY],
    )

    corpus = load_corpus(str(tmp_path))

    call_count = {"n": 0}

    def flaky_read_bytes(self):  # type: ignore[no-untyped-def]
        call_count["n"] += 1
        # Fail every read from inside _check_benign_diversity's second pass
        # (load_corpus's own reads already happened before this point).
        raise OSError("simulated transient read failure")

    mocker.patch("pathlib.Path.read_bytes", flaky_read_bytes)

    result = validate_corpus(corpus)

    # If every re-read fails, diverse_count=0 and readable_count=0 -- the fixed
    # denominator bug would instead divide by the original 40-file count,
    # producing a spurious 0% and a false "insufficient diversity" rejection
    # alongside whatever real reasons apply. With the fix, a zero-readable
    # benign set is simply skipped by this specific check (not falsely scored).
    assert not any("phishing-adjacent" in r for r in result["reasons"])
    assert call_count["n"] > 0


def test_cross_class_overlap_between_tuning_and_held_out_is_rejected(tmp_path: Path) -> None:
    """A file mistakenly present in one class's tuning split AND a DIFFERENT
    class's held_out split (e.g. a mislabeling error) must be caught -- not
    just same-class overlap."""
    _write_valid_corpus(tmp_path)

    # Make malicious/held_out's first file byte-identical to benign/tuning's
    # first file -- overlap across classes, not within one.
    benign_tuning_first = sorted((tmp_path / "benign" / "tuning").glob("*.eml"))[0]
    malicious_held_out_first = sorted((tmp_path / "malicious" / "held_out").glob("*.eml"))[0]
    malicious_held_out_first.write_bytes(benign_tuning_first.read_bytes())

    corpus = load_corpus(str(tmp_path))
    result = validate_corpus(corpus)

    assert result["is_valid"] is False
    assert any("tuning" in r.lower() and "held_out" in r.lower() for r in result["reasons"])


def test_load_corpus_never_raises_on_directory_listing_permission_error(tmp_path: Path, mocker) -> None:  # type: ignore[no-untyped-def]
    _write_eml(tmp_path / "benign" / "tuning" / "a.eml", "subj", "body")
    mocker.patch("pathlib.Path.iterdir", side_effect=PermissionError("simulated"))

    corpus = load_corpus(str(tmp_path))  # must not raise
    result = validate_corpus(corpus)  # must not raise

    assert result["is_valid"] is False


def test_load_corpus_matches_eml_extension_case_insensitively(tmp_path: Path) -> None:
    tuning_dir = tmp_path / "benign" / "tuning"
    tuning_dir.mkdir(parents=True)
    _write_eml(tuning_dir / "lower.eml", "s", "b1")
    (tuning_dir / "upper.EML").write_bytes(b"From: t@example.com\r\nSubject: s2\r\n\r\nb2")

    corpus = load_corpus(str(tmp_path))

    assert len(corpus["benign_tuning"]) == 2
