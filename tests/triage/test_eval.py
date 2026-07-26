import json
import subprocess
from pathlib import Path

import pytest

from sentinel.triage.eval import (
    apply_isotonic,
    apply_platt,
    fit_calibration_mapping,
    fit_isotonic_regression,
    fit_platt_scaling,
    load_calibration_model,
    load_corpus,
    save_calibration_model,
    validate_corpus,
)

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


# --- Calibration fitting (Story 3.2) --------------------------------------------


def test_fit_isotonic_regression_is_monotonically_non_decreasing() -> None:
    """The fitted step function must never decrease as raw_score increases,
    by definition of isotonic regression."""
    pairs = [
        (0.1, 0.0), (0.15, 1.0), (0.2, 0.0), (0.3, 0.0), (0.4, 1.0),
        (0.5, 0.0), (0.6, 1.0), (0.7, 1.0), (0.8, 0.0), (0.9, 1.0), (0.95, 1.0),
    ]
    breakpoints = fit_isotonic_regression(pairs)

    swept = [i / 100 for i in range(0, 101)]
    calibrated = [apply_isotonic(x, breakpoints) for x in swept]
    assert calibrated == sorted(calibrated)


def test_fit_isotonic_regression_ties_average_regardless_of_input_order() -> None:
    """[Review][Patch] Code review (Blind Hunter + Edge Case Hunter): two
    pairs sharing the same raw_score but different labels must be pooled
    into a single block (the average of their labels), not left as two
    separate same-x blocks whose merge depends on input order -- confirmed
    a real bug where reversing the input order changed apply_isotonic(0.5)
    from 0.0 to 0.5 for the identical training set."""
    order_a = [(0.5, 0.0), (0.5, 1.0)]
    order_b = [(0.5, 1.0), (0.5, 0.0)]

    breakpoints_a = fit_isotonic_regression(order_a)
    breakpoints_b = fit_isotonic_regression(order_b)

    assert breakpoints_a == breakpoints_b
    assert apply_isotonic(0.5, breakpoints_a) == 0.5
    assert apply_isotonic(0.5, breakpoints_b) == 0.5


def test_fit_isotonic_regression_ties_with_surrounding_points_average_correctly() -> None:
    # Two tied points (0.5, 0.0) and (0.5, 1.0) must average to 0.5, not
    # silently drop one label -- verified alongside distinct-x neighbors so
    # the fix doesn't disturb ordinary (non-tied) pooling behavior.
    pairs = [(0.1, 0.0), (0.5, 0.0), (0.5, 1.0), (0.9, 1.0)]
    breakpoints = fit_isotonic_regression(pairs)

    assert apply_isotonic(0.5, breakpoints) == 0.5
    assert apply_isotonic(0.1, breakpoints) <= 0.5
    assert apply_isotonic(0.9, breakpoints) >= 0.5


def test_fit_isotonic_regression_separable_data_produces_step_near_boundary() -> None:
    """A perfectly-separable synthetic dataset (all low scores benign, all
    high scores malicious) must isotonic-fit to something close to a step
    function at the separation point."""
    pairs = [(x / 100, 0.0) for x in range(0, 50)] + [(x / 100, 1.0) for x in range(50, 100)]
    breakpoints = fit_isotonic_regression(pairs)

    assert apply_isotonic(0.1, breakpoints) < 0.2
    assert apply_isotonic(0.9, breakpoints) > 0.8


def test_apply_isotonic_never_raises_on_out_of_range_input() -> None:
    breakpoints = fit_isotonic_regression([(0.3, 0.0), (0.5, 0.5), (0.7, 1.0)])

    below = apply_isotonic(-5.0, breakpoints)
    above = apply_isotonic(5.0, breakpoints)

    assert 0.0 <= below <= 1.0
    assert 0.0 <= above <= 1.0


def test_apply_isotonic_handles_empty_breakpoints_without_raising() -> None:
    assert apply_isotonic(0.5, []) == 0.5


def test_fit_platt_scaling_is_directionally_correct_on_separable_data() -> None:
    """Higher raw scores in a perfectly-separable synthetic dataset must
    calibrate to higher probabilities -- getting the sign convention
    backwards would silently invert the calibration, not crash."""
    pairs = [(x / 100, 0.0) for x in range(0, 50)] + [(x / 100, 1.0) for x in range(50, 100)]
    a, b = fit_platt_scaling(pairs)

    low = apply_platt(0.1, a, b)
    high = apply_platt(0.9, a, b)
    assert high > low
    assert low < 0.5
    assert high > 0.5


def test_fit_platt_scaling_output_stays_within_unit_interval() -> None:
    pairs = [(x / 100, 0.0) for x in range(0, 50)] + [(x / 100, 1.0) for x in range(50, 100)]
    a, b = fit_platt_scaling(pairs)

    for x in [-100.0, -1.0, 0.0, 0.5, 1.0, 100.0]:
        result = apply_platt(x, a, b)
        assert 0.0 <= result <= 1.0


def test_apply_platt_never_raises_on_extreme_inputs() -> None:
    # Extreme A/B/x combinations must not overflow math.exp.
    # a*x = +1e20 in both cases below -- exercises only the +500 exponent
    # clamp (p -> 0). [Review][Patch] Blind Hunter: the -500 clamp branch
    # (p -> 1, via a very NEGATIVE a*x product) was never exercised despite
    # this test's name/comment claiming bidirectional "extreme" coverage.
    assert 0.0 <= apply_platt(1e10, a=1e10, b=1e10) <= 1.0
    assert 0.0 <= apply_platt(-1e10, a=-1e10, b=-1e10) <= 1.0
    # a*x = -1e20 here -- exercises the -500 clamp branch (p -> 1), and
    # asserts the actual direction, not just "didn't crash".
    assert apply_platt(1e10, a=-1e10, b=0.0) > 0.999
    assert apply_platt(-1e10, a=1e10, b=0.0) > 0.999


# --- fit_calibration_mapping orchestration + JSON I/O (Story 3.2, Task 3) -------


def _separable_pairs(count: int) -> list[tuple[float, float]]:
    half = count // 2
    return [(x / count, 0.0) for x in range(0, half)] + [(x / count, 1.0) for x in range(half, count)]


def test_fit_calibration_mapping_rejects_empty_pairs() -> None:
    with pytest.raises(ValueError, match="zero"):
        fit_calibration_mapping([])


def test_fit_calibration_mapping_rejects_all_benign_pairs() -> None:
    # A real corpus with zero malicious samples (Story 3.1's current state,
    # pending a phishing_pot license reply) must not silently produce a
    # degenerate "always benign" calibration -- fitting requires both
    # outcome classes to be present, per AC1's "validated corpus" precondition.
    pairs = [(x / 100, 0.0) for x in range(0, 100)]
    with pytest.raises(ValueError, match=r"\{0\.0, 1\.0\}"):
        fit_calibration_mapping(pairs)


def test_fit_calibration_mapping_rejects_all_malicious_pairs() -> None:
    pairs = [(x / 100, 1.0) for x in range(0, 100)]
    with pytest.raises(ValueError, match=r"\{0\.0, 1\.0\}"):
        fit_calibration_mapping(pairs)


def test_fit_calibration_mapping_rejects_non_binary_labels() -> None:
    # [Review][Patch] Blind Hunter: the old "at least 2 distinct labels" check
    # accepted e.g. {0.0, 2.0} -- labels must be exactly {0.0, 1.0}.
    pairs = [(0.1, 0.0), (0.2, 2.0)]
    with pytest.raises(ValueError, match=r"\{0\.0, 1\.0\}"):
        fit_calibration_mapping(pairs)


def test_fit_calibration_mapping_deferral_threshold_derived_is_caller_supplied() -> None:
    # [Review][Patch] Blind Hunter + Acceptance Auditor (AC2): previously
    # hardcoded to 0.05 inside fit_calibration_mapping regardless of what the
    # caller wanted, directly contradicting the function's own docstring
    # claim that callers "are expected to set it explicitly". Now an actual
    # parameter -- both the caller-supplied value and the default are proven.
    pairs = _separable_pairs(99)

    default_model = fit_calibration_mapping(pairs)
    assert default_model["deferral_threshold_derived"] == 0.05

    custom_model = fit_calibration_mapping(pairs, deferral_threshold_derived=0.12)
    assert custom_model["deferral_threshold_derived"] == 0.12


def test_fit_calibration_mapping_chooses_platt_below_isotonic_threshold() -> None:
    pairs = _separable_pairs(99)  # one below _MIN_SAMPLES_FOR_ISOTONIC (100)
    model = fit_calibration_mapping(pairs)

    assert model["method"] == "platt"
    assert model["platt_params"] is not None
    assert model["isotonic_breakpoints"] is None


def test_fit_calibration_mapping_chooses_isotonic_at_threshold() -> None:
    pairs = _separable_pairs(100)  # exactly _MIN_SAMPLES_FOR_ISOTONIC
    model = fit_calibration_mapping(pairs)

    assert model["method"] == "isotonic"
    assert model["isotonic_breakpoints"] is not None
    assert model["platt_params"] is None


def test_fit_calibration_mapping_records_sample_count_and_version() -> None:
    pairs = _separable_pairs(99)
    model = fit_calibration_mapping(pairs)

    assert model["sample_count"] == 99
    assert model["version"] == 1
    assert model["fitted_at"] is not None


def test_save_and_load_calibration_model_round_trips(tmp_path: Path) -> None:
    pairs = _separable_pairs(100)
    model = fit_calibration_mapping(pairs)
    path = tmp_path / "calibration_model_v1.json"

    save_calibration_model(model, str(path))
    loaded = load_calibration_model(str(path))

    assert loaded == model


def test_save_and_load_identity_placeholder_round_trips(tmp_path: Path) -> None:
    model = {
        "version": 1,
        "method": "identity",
        "fitted_at": None,
        "sample_count": 0,
        "isotonic_breakpoints": None,
        "platt_params": None,
        "deferral_threshold_derived": 0.05,
        "note": "PLACEHOLDER",
    }
    path = tmp_path / "calibration_model_v1.json"

    save_calibration_model(model, str(path))  # type: ignore[arg-type]
    loaded = load_calibration_model(str(path))

    assert loaded == model


def test_save_calibration_model_leaves_existing_file_untouched_on_replace_failure(
    tmp_path: Path, mocker  # type: ignore[no-untyped-def]
) -> None:
    """[Review][Patch] Edge Case Hunter: save_calibration_model previously
    wrote directly to the target path with no atomic swap -- a reader (e.g.
    another process importing scoring.py) opening the file mid-write could
    observe a truncated/partial JSON document. Now writes to a temp file in
    the same directory and os.replace()s it into place; if the final rename
    step itself fails, the target must still hold its ORIGINAL content --
    proving the new data was staged separately and never touched the target
    directly. (Mocking pathlib.Path.replace specifically, not
    Path.write_text, so this test only passes if save_calibration_model
    actually routes through a Path.replace atomic rename -- the old
    direct-write implementation never calls it at all, so this would
    incorrectly succeed with no exception raised under the pre-patch code.)
    """
    path = tmp_path / "calibration_model_v1.json"
    original_model = fit_calibration_mapping(_separable_pairs(100))
    save_calibration_model(original_model, str(path))
    original_content = path.read_text(encoding="utf-8")

    mocker.patch(
        "pathlib.Path.replace", side_effect=OSError("simulated failure during atomic rename")
    )
    broken_model = fit_calibration_mapping(_separable_pairs(200))
    with pytest.raises(OSError):
        save_calibration_model(broken_model, str(path))

    assert path.read_text(encoding="utf-8") == original_content


def test_save_calibration_model_does_not_leave_stray_temp_file_on_success(tmp_path: Path) -> None:
    model = fit_calibration_mapping(_separable_pairs(100))
    path = tmp_path / "calibration_model_v1.json"

    save_calibration_model(model, str(path))

    assert {p.name for p in tmp_path.iterdir()} == {"calibration_model_v1.json"}


def test_load_calibration_model_rejects_unsorted_isotonic_breakpoints(tmp_path: Path) -> None:
    """[Review][Patch] Edge Case Hunter: apply_isotonic assumes its
    breakpoints list is ascending (true only because fit_isotonic_regression
    always produces sorted output) -- a hand-edited or corrupted file with
    out-of-order breakpoints previously loaded without error and produced
    silently non-monotonic calibrated output."""
    path = tmp_path / "calibration_model_v1.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "method": "isotonic",
                "fitted_at": "2026-01-01T00:00:00+00:00",
                "sample_count": 2,
                # deliberately out of order: second block's x_min < first block's x_max
                "isotonic_breakpoints": [[0.5, 1.0, 0.9], [0.0, 0.4, 0.1]],
                "platt_params": None,
                "deferral_threshold_derived": 0.05,
                "note": None,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sorted"):
        load_calibration_model(str(path))
