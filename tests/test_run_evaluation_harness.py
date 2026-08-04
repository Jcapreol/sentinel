"""Tests for the repo-root run_evaluation_harness.py orchestration script
(Story 3.4). The script lives outside src/ (matches fit_real_calibration_
model.py's repo-root, standalone-script convention), so it is imported here
via a sys.path insertion rather than pytest's normal pythonpath=["src"]
resolution -- an explicit, documented choice (see this story's Dev Notes),
not an accident.

No real API calls anywhere in this file: WatchmanAgent/CipherAgent are
replaced with MagicMock doubles at the SentinelAgent Protocol boundary,
matching this project's established "mock at the SDK/client boundary"
testing convention.
"""

import ast
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import run_evaluation_harness as script  # noqa: E402

from sentinel.triage.eval import CalibrationModel, Corpus, load_corpus  # noqa: E402
from sentinel.triage.script_guard import (  # noqa: E402
    ApiCallBudgetExceededError,
    acquire_run_lock,
)
from sentinel.triage.worker import gather_evidence_and_raw_score  # noqa: E402

_PLAIN_BODY = "Hi, just checking in about our meeting tomorrow. Thanks!"
_PHISHING_ADJACENT_BODY = (
    "URGENT ACTION REQUIRED: Please verify your account within 24 hours or it "
    "will be suspended. Click here to confirm your identity."
)
_PROVENANCE_TEXT = (
    "Sourced from a synthetic test fixture generated for unit testing purposes. "
    "This is not real harvested data; see tests/test_run_evaluation_harness.py."
)

_IDENTITY_MODEL = CalibrationModel(
    version=1,
    method="identity",
    fitted_at=None,
    sample_count=0,
    isotonic_breakpoints=None,
    platt_params=None,
    deferral_threshold_derived=0.05,
    note=None,
)
_REAL_ISOTONIC_MODEL = CalibrationModel(
    version=1,
    method="isotonic",
    fitted_at="2026-01-01T00:00:00+00:00",
    sample_count=100,
    isotonic_breakpoints=[[0.0, 1.0, 0.5]],
    platt_params=None,
    deferral_threshold_derived=0.05,
    note=None,
)


def _write_eml(path: Path, subject: str, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = f"From: test@example.com\r\nSubject: {subject}\r\n"
    path.write_bytes((headers + "\r\n" + body).encode())


def _write_class(root: Path, cls: str, tuning_count: int, held_out_count: int) -> None:
    """Deliberately different tuning/held_out counts (8 vs 35 -- the mirror
    image of fit_real_calibration_model.py's fixture) so an off-by-split-
    name bug is detectable -- if this script ever accidentally reads
    tuning, the resulting pair/call count would visibly not match what
    sampling from held_out alone predicts."""
    (root / cls).mkdir(parents=True, exist_ok=True)
    (root / cls / "PROVENANCE.md").write_text(_PROVENANCE_TEXT, encoding="utf-8")

    bodies = [_PHISHING_ADJACENT_BODY] + [_PLAIN_BODY] * 9

    for i in range(tuning_count):
        body = f"{bodies[i % len(bodies)]} (unique marker {cls}-t{i})"
        _write_eml(root / cls / "tuning" / f"{cls}-tuning-{i}.eml", f"Subject {cls} t{i}", body)
    for i in range(held_out_count):
        body = f"{bodies[i % len(bodies)]} (unique marker {cls}-h{i})"
        _write_eml(root / cls / "held_out" / f"{cls}-held_out-{i}.eml", f"Subject {cls} h{i}", body)


@pytest.fixture
def valid_corpus(tmp_path: Path):  # type: ignore[no-untyped-def]
    """A corpus large enough to clear validate_corpus's checks (>=30 unique
    samples/class, provenance, benign diversity, no cross-split overlap).
    held_out counts (35) deliberately larger than tuning (8) -- the mirror
    of fit_real_calibration_model.py's fixture -- since THIS script samples
    from held_out."""
    _write_class(tmp_path, "benign", tuning_count=8, held_out_count=35)
    _write_class(tmp_path, "malicious", tuning_count=8, held_out_count=35)
    return load_corpus(str(tmp_path))


def _mock_agent() -> MagicMock:
    agent = MagicMock()
    agent.analyze.return_value = {"evidence": []}
    return agent


def test_run_never_calls_analyze_for_tuning_files(valid_corpus) -> None:  # type: ignore[no-untyped-def]
    watchman = _mock_agent()
    cipher = _mock_agent()

    script.run(
        valid_corpus,
        _REAL_ISOTONIC_MODEL,
        sample_size_per_class=3,
        deferral_band=0.05,
        watchman=watchman,
        cipher=cipher,
    )

    # 3 benign + 3 malicious held_out files sampled -> exactly 6 pipeline
    # runs. tuning has 8+8=16 files; if the script ever touched them, this
    # count would be higher than 6, proving tuning is never fed through the
    # pipeline -- a call-count assertion on the mock, not an I/O spy.
    assert watchman.analyze.call_count == 6
    assert cipher.analyze.call_count == 6


def test_run_produces_an_evaluation_report_from_sampled_pairs(valid_corpus) -> None:  # type: ignore[no-untyped-def]
    watchman = _mock_agent()
    cipher = _mock_agent()

    report = script.run(
        valid_corpus,
        _REAL_ISOTONIC_MODEL,
        sample_size_per_class=3,
        deferral_band=0.05,
        watchman=watchman,
        cipher=cipher,
    )

    assert report["sample_count"] == 6
    assert 0.0 <= report["auc_roc"] <= 1.0
    assert 0.0 <= report["deferral_rate"] <= 1.0
    assert report["is_identity_placeholder"] is False
    assert report["gate_met"] in (True, False)


def test_collect_pairs_assigns_correct_labels_to_each_class(valid_corpus) -> None:  # type: ignore[no-untyped-def]
    """The label assignment (0.0 benign / 1.0 malicious) is the single most
    safety-critical line in this script -- a swapped label would silently
    invert the measured calibration quality, making a broken system look
    fine (or a fine system look broken). Mirrors fit_real_calibration_
    model.py's identical test for its own collect_pairs."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    sampled_benign = valid_corpus["benign_held_out"][:2]
    sampled_malicious = valid_corpus["malicious_held_out"][:3]

    pairs = script.collect_pairs(sampled_benign, sampled_malicious, watchman, cipher)

    labels = [label for _confidence, label in pairs]
    assert labels == [0.0, 0.0, 1.0, 1.0, 1.0]


def test_run_rejects_invalid_corpus(tmp_path: Path) -> None:
    # Only benign written -- malicious class entirely missing -> is_valid=False.
    _write_class(tmp_path, "benign", tuning_count=8, held_out_count=35)
    invalid_corpus = load_corpus(str(tmp_path))
    watchman = _mock_agent()
    cipher = _mock_agent()

    with pytest.raises(ValueError, match="failed validation"):
        script.run(
            invalid_corpus,
            _REAL_ISOTONIC_MODEL,
            sample_size_per_class=3,
            deferral_band=0.05,
            watchman=watchman,
            cipher=cipher,
        )

    watchman.analyze.assert_not_called()
    cipher.analyze.assert_not_called()


def test_run_rejects_invalid_deferral_band_before_running_the_pipeline(  # type: ignore[no-untyped-def]
    valid_corpus,
) -> None:
    """[Review] config.deferral_threshold is validated lazily "at first
    actual use" per config.py's own documented contract -- but this
    harness's first actual use (compute_deferral_rate) previously ran only
    AFTER collect_pairs had already made every sampled file's real
    Watchman/Cipher call, unlike worker.py's process_message, which
    validates as literally its first line, before any pipeline work.
    Must now fail fast, before the pipeline runs at all."""
    watchman = _mock_agent()
    cipher = _mock_agent()

    with pytest.raises(ValueError, match="deferral_band"):
        script.run(
            valid_corpus,
            _REAL_ISOTONIC_MODEL,
            sample_size_per_class=3,
            deferral_band=1.5,  # out of [0.0, 1.0]
            watchman=watchman,
            cipher=cipher,
        )

    # The real proof: the pipeline was never touched.
    watchman.analyze.assert_not_called()
    cipher.analyze.assert_not_called()


def test_run_raises_clear_error_when_every_sampled_file_fails(  # type: ignore[no-untyped-def]
    valid_corpus, mocker
) -> None:
    watchman = _mock_agent()
    cipher = _mock_agent()
    mocker.patch("pathlib.Path.read_bytes", side_effect=OSError("simulated: every file unreadable"))

    with pytest.raises(ValueError, match="zero"):
        script.run(
            valid_corpus,
            _REAL_ISOTONIC_MODEL,
            sample_size_per_class=3,
            deferral_band=0.05,
            watchman=watchman,
            cipher=cipher,
        )


def test_collect_pairs_skips_unreadable_file_without_aborting(  # type: ignore[no-untyped-def]
    valid_corpus, mocker
) -> None:
    watchman = _mock_agent()
    cipher = _mock_agent()
    sampled_benign = valid_corpus["benign_held_out"][:2]
    sampled_malicious = valid_corpus["malicious_held_out"][:2]

    real_read_bytes = Path.read_bytes
    call_count = {"n": 0}

    def flaky_read_bytes(self: Path, *args: object, **kwargs: object) -> bytes:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise OSError("simulated read failure")
        return real_read_bytes(self, *args, **kwargs)

    mocker.patch("pathlib.Path.read_bytes", flaky_read_bytes)

    pairs = script.collect_pairs(sampled_benign, sampled_malicious, watchman, cipher)

    assert len(pairs) == 3


def test_collect_pairs_warns_when_one_class_contributes_zero_pairs(  # type: ignore[no-untyped-def]
    valid_corpus, mocker, capsys
) -> None:
    """[Review] Without a per-class breakdown, a total dropout of one
    class's samples (e.g. a systemic extraction issue affecting only that
    class's file encoding) is silently indistinguishable in the report from
    genuinely poor discrimination -- both just show a low/degenerate
    AUC-ROC with no explanation. `apply_calibration` is patched to fail for
    every malicious-labeled file specifically (identified by path), while
    benign files succeed."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    sampled_benign = valid_corpus["benign_held_out"][:3]
    sampled_malicious = valid_corpus["malicious_held_out"][:3]

    # Patch the pipeline call itself so ALL malicious files fail regardless
    # of content, while benign files go through the real (mocked-agent)
    # path untouched.
    def selective_gather(  # type: ignore[no-untyped-def]
        auth_header, email_content, watchman, cipher
    ):
        if "malicious" in email_content:
            raise RuntimeError("simulated: this class always fails")
        return gather_evidence_and_raw_score(auth_header, email_content, watchman, cipher)

    mocker.patch("run_evaluation_harness.gather_evidence_and_raw_score", side_effect=selective_gather)

    pairs = script.collect_pairs(sampled_benign, sampled_malicious, watchman, cipher)

    assert len(pairs) == 3  # only benign succeeded
    assert all(label == 0.0 for _confidence, label in pairs)
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "malicious" in captured.err.lower()


def test_collect_pairs_skips_file_when_content_extraction_raises(  # type: ignore[no-untyped-def]
    valid_corpus, mocker
) -> None:
    watchman = _mock_agent()
    cipher = _mock_agent()
    sampled_benign = valid_corpus["benign_held_out"][:2]
    sampled_malicious = valid_corpus["malicious_held_out"][:2]

    mocker.patch(
        "run_evaluation_harness.extract_email_content",
        side_effect=RuntimeError("simulated extraction failure"),
    )

    pairs = script.collect_pairs(sampled_benign, sampled_malicious, watchman, cipher)

    assert pairs == []


def test_collect_pairs_skips_file_when_apply_calibration_raises(  # type: ignore[no-untyped-def]
    valid_corpus, mocker
) -> None:
    """[Review] _score_one_file's docstring promises "None on any failure",
    but apply_calibration was called outside the try block -- if it ever
    raised (e.g. an unrecognized `method` in a hand-edited/corrupted
    calibration_model_v1.json), the exception would propagate out of
    collect_pairs's loop uncaught, aborting the whole run.

    [Fix] check_structural_deferral is patched to False here -- this
    fixture's synthetic .eml files carry no Authentication-Results header
    and the mocked agents contribute zero evidence, so every sampled file is
    genuinely all-neutral and would otherwise be structurally deferred
    before apply_calibration is ever reached, defeating this test's actual
    point (the exception-handling path around apply_calibration itself, not
    structural deferral -- that has its own dedicated test below)."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    sampled_benign = valid_corpus["benign_held_out"][:2]
    sampled_malicious = valid_corpus["malicious_held_out"][:2]

    mocker.patch("run_evaluation_harness.check_structural_deferral", return_value=False)
    mocker.patch(
        "run_evaluation_harness.apply_calibration",
        side_effect=RuntimeError("simulated: unrecognized calibration method"),
    )

    pairs = script.collect_pairs(sampled_benign, sampled_malicious, watchman, cipher)

    assert pairs == []


def test_collect_pairs_defers_structurally_for_all_neutral_evidence_even_if_calibration_saturates(  # type: ignore[no-untyped-def]
    valid_corpus, mocker
) -> None:
    """[Fix] Regression test for the exact gap that just caused this harness
    to report a bit-for-bit identical ECE/AUC-ROC/deferral rate before and
    after tonight's structural deferral fix in process_message: this harness
    called apply_calibration/gather_evidence_and_raw_score directly,
    bypassing process_message entirely, so it never exercised either
    structural pre-calibration deferral gate. Both gates are now extracted
    into check_structural_deferral (src/sentinel/triage/worker.py) and
    called from _score_one_file too, in the same order process_message uses
    (before apply_calibration).

    This fixture's synthetic .eml files carry no Authentication-Results
    header, and the mocked watchman/cipher agents contribute zero evidence
    (see _mock_agent) -- every sampled file is genuinely all-neutral
    evidence, a real held_out sample this structural gate is meant to catch.
    Mocking apply_calibration to always return 1.0 (the same worst-case
    pattern as worker.py's own regression tests -- maximally
    "confident"-looking saturation) proves the harness now reports these
    files as Deferred (calibrated_confidence 0.5, process_message's own
    convention) rather than whatever apply_calibration alone would have
    said."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    sampled_benign = valid_corpus["benign_held_out"][:2]
    sampled_malicious = valid_corpus["malicious_held_out"][:2]
    apply_calibration_spy = mocker.patch(
        "run_evaluation_harness.apply_calibration", return_value=1.0
    )

    pairs = script.collect_pairs(
        sampled_benign, sampled_malicious, watchman, cipher, deferral_band=0.05
    )

    assert len(pairs) == 4
    assert all(confidence == 0.5 for confidence, _label in pairs)
    apply_calibration_spy.assert_not_called()
    # The deferral rate this harness reports must move off 0.0000 for a
    # sample like this -- the exact number CI caught as suspiciously
    # unchanged before this fix.
    assert (
        script.compute_deferral_rate([c for c, _label in pairs], deferral_band=0.05) == 1.0
    )


def test_run_reports_gate_met_for_well_calibrated_high_discrimination_data(  # type: ignore[no-untyped-def]
    valid_corpus, mocker
) -> None:
    """Constructs a controlled scenario via a patched apply_calibration:
    benign files get low confidence (0.05), malicious files get high
    confidence (0.95) -- perfect separation, near-zero ECE, AUC ~= 1.0.
    Gate must be MET.

    [Fix] check_structural_deferral is patched to False -- this fixture's
    synthetic files are genuinely all-neutral evidence and would otherwise
    be structurally deferred to confidence 0.5 before the patched
    apply_calibration is ever reached, collapsing this controlled scenario
    into a degenerate one. This test is about calibration/gate logic, not
    structural deferral -- that has its own dedicated test below."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    mocker.patch("run_evaluation_harness.check_structural_deferral", return_value=False)
    confidences = iter([0.05] * 5 + [0.95] * 5)
    mocker.patch(
        "run_evaluation_harness.apply_calibration", side_effect=lambda raw_score: next(confidences)
    )

    report = script.run(
        valid_corpus,
        _REAL_ISOTONIC_MODEL,
        sample_size_per_class=5,
        deferral_band=0.05,
        watchman=watchman,
        cipher=cipher,
    )

    assert report["gate_met"] is True


def test_run_never_reports_gate_met_when_every_ece_bin_is_inconclusive(  # type: ignore[no-untyped-def]
    valid_corpus, mocker
) -> None:
    """[Review] compute_ece's zero-conclusive-data fallback (ece=0.0, a
    divide-by-zero degradation, not a real measurement) must never be
    trusted by the release gate. Reproduced directly: 1 benign + 1
    malicious sample (sample_size_per_class=1), correctly ordered, lands
    both in singleton (inconclusive, count=1 < _MIN_SAMPLES_PER_ECE_BIN=5)
    bins -- ece=0.0 and auc_roc=1.0 from just 2 samples, which without this
    guard would report "Release gate: MET" from essentially zero evidence.

    [Fix] check_structural_deferral is patched to False -- see the identical
    note on test_run_reports_gate_met_for_well_calibrated_high_discrimination_data."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    mocker.patch("run_evaluation_harness.check_structural_deferral", return_value=False)
    confidences = iter([0.2, 0.8])  # 1 benign (low), 1 malicious (high)
    mocker.patch(
        "run_evaluation_harness.apply_calibration", side_effect=lambda raw_score: next(confidences)
    )

    report = script.run(
        valid_corpus,
        _REAL_ISOTONIC_MODEL,
        sample_size_per_class=1,
        deferral_band=0.05,
        watchman=watchman,
        cipher=cipher,
    )

    assert report["ece_result"]["ece"] == 0.0  # the degenerate fallback value
    assert report["gate_met"] is False  # but the gate must NOT be MET from this


def test_run_reports_gate_not_met_for_anti_correlated_data(  # type: ignore[no-untyped-def]
    valid_corpus, mocker
) -> None:
    """The mirror scenario: benign files get HIGH confidence, malicious
    files get LOW confidence -- perfectly anti-correlated with the true
    label, AUC-ROC ~= 0.0, well below _MIN_AUC_FOR_NON_FLAT. Gate must be
    NOT MET.

    [Fix] check_structural_deferral is patched to False -- see the identical
    note on test_run_reports_gate_met_for_well_calibrated_high_discrimination_data."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    mocker.patch("run_evaluation_harness.check_structural_deferral", return_value=False)
    confidences = iter([0.95] * 5 + [0.05] * 5)
    mocker.patch(
        "run_evaluation_harness.apply_calibration", side_effect=lambda raw_score: next(confidences)
    )

    report = script.run(
        valid_corpus,
        _REAL_ISOTONIC_MODEL,
        sample_size_per_class=5,
        deferral_band=0.05,
        watchman=watchman,
        cipher=cipher,
    )

    assert report["gate_met"] is False


def _mock_main_dependencies(
    mocker: MockerFixture,
    valid_corpus: Corpus,
    calibration_model: CalibrationModel,
    watchman: MagicMock,
    cipher: MagicMock,
    tmp_path: Path,
) -> None:
    mocker.patch("run_evaluation_harness.WatchmanAgent", return_value=watchman)
    mocker.patch("run_evaluation_harness.CipherAgent", return_value=cipher)
    mocker.patch("run_evaluation_harness.load_corpus", return_value=valid_corpus)
    mocker.patch("run_evaluation_harness.load_calibration_model", return_value=calibration_model)
    mocker.patch(
        "run_evaluation_harness.load_config",
        return_value=mocker.Mock(eval_corpus_path=None, deferral_threshold=0.05),
    )
    # Story 4.2: redirect the run lock + shared cache/budget state DB into
    # tmp_path -- without this, main() would touch real files at the repo
    # root (a transient calibration_model_v1.json.lock plus, once any test
    # actually exercises the cache/budget, .sentinel_script_state.db).
    mocker.patch(
        "run_evaluation_harness._CALIBRATION_MODEL_PATH", str(tmp_path / "calibration_model_v1.json")
    )
    mocker.patch("run_evaluation_harness._STATE_DB_PATH", str(tmp_path / "state.db"))


def test_warns_and_exits_2_when_calibration_model_is_identity(  # type: ignore[no-untyped-def]
    valid_corpus, mocker, capsys, tmp_path
) -> None:
    watchman = _mock_agent()
    cipher = _mock_agent()
    _mock_main_dependencies(mocker, valid_corpus, _IDENTITY_MODEL, watchman, cipher, tmp_path)
    mocker.patch("sys.argv", ["run_evaluation_harness.py", "--sample-size-per-class", "3"])

    with pytest.raises(SystemExit) as exc:
        script.main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "identity placeholder" in captured.err
    assert "WARNING" in captured.err
    assert "Release gate: N/A" in captured.out
    assert "Release gate: MET" not in captured.out
    assert "Release gate: NOT MET" not in captured.out


def test_no_placeholder_warning_when_calibration_model_is_a_real_fit(  # type: ignore[no-untyped-def]
    valid_corpus, mocker, capsys, tmp_path
) -> None:
    watchman = _mock_agent()
    cipher = _mock_agent()
    _mock_main_dependencies(mocker, valid_corpus, _REAL_ISOTONIC_MODEL, watchman, cipher, tmp_path)
    mocker.patch("sys.argv", ["run_evaluation_harness.py", "--sample-size-per-class", "3"])

    with pytest.raises(SystemExit) as exc:
        script.main()

    assert exc.value.code in (0, 1)
    captured = capsys.readouterr()
    assert "identity placeholder" not in captured.err
    assert "WARNING" not in captured.err
    assert "Release gate: N/A" not in captured.out


def test_main_exits_0_when_gate_is_met(  # type: ignore[no-untyped-def]
    valid_corpus, mocker, capsys, tmp_path
) -> None:
    """[Review] Task 4's original gate-met/not-met tests only asserted on
    report["gate_met"] via script.run() directly -- never through main()'s
    actual sys.exit mapping. This proves the real, end-to-end exit code.

    [Fix] check_structural_deferral is patched to False -- see the identical
    note on test_run_reports_gate_met_for_well_calibrated_high_discrimination_data."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    _mock_main_dependencies(mocker, valid_corpus, _REAL_ISOTONIC_MODEL, watchman, cipher, tmp_path)
    mocker.patch("run_evaluation_harness.check_structural_deferral", return_value=False)
    # 5 per class -- exactly _MIN_SAMPLES_PER_ECE_BIN, so both bins are
    # conclusive (not just correctly separated, per Patch 1's new guard).
    confidences = iter([0.05] * 5 + [0.95] * 5)
    mocker.patch(
        "run_evaluation_harness.apply_calibration", side_effect=lambda raw_score: next(confidences)
    )
    mocker.patch("sys.argv", ["run_evaluation_harness.py", "--sample-size-per-class", "5"])

    with pytest.raises(SystemExit) as exc:
        script.main()

    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Release gate: MET" in captured.out


def test_main_exits_1_when_gate_is_not_met(  # type: ignore[no-untyped-def]
    valid_corpus, mocker, capsys, tmp_path
) -> None:
    """[Fix] check_structural_deferral is patched to False -- see the
    identical note on test_run_reports_gate_met_for_well_calibrated_high_discrimination_data."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    _mock_main_dependencies(mocker, valid_corpus, _REAL_ISOTONIC_MODEL, watchman, cipher, tmp_path)
    mocker.patch("run_evaluation_harness.check_structural_deferral", return_value=False)
    # 5 per class (conclusive bins) so this genuinely tests "anti-correlated
    # data fails the gate", not merely "inconclusive data can't pass".
    confidences = iter([0.95] * 5 + [0.05] * 5)  # anti-correlated
    mocker.patch(
        "run_evaluation_harness.apply_calibration", side_effect=lambda raw_score: next(confidences)
    )
    mocker.patch("sys.argv", ["run_evaluation_harness.py", "--sample-size-per-class", "5"])

    with pytest.raises(SystemExit) as exc:
        script.main()

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Release gate: NOT MET" in captured.out


def test_main_exits_3_not_1_when_corpus_is_invalid(  # type: ignore[no-untyped-def]
    tmp_path: Path, mocker, capsys
) -> None:
    """[Review] Exit code 1 previously meant both "gate genuinely not met"
    and "couldn't measure at all" -- an automated caller checking only the
    exit code couldn't tell a real quality regression apart from a bad
    --corpus-path. Now distinct: 3, not 1, and no "Release gate" line is
    printed at all (no measurement happened)."""
    _write_class(tmp_path, "benign", tuning_count=8, held_out_count=35)  # malicious missing
    invalid_corpus = load_corpus(str(tmp_path))
    watchman = _mock_agent()
    cipher = _mock_agent()
    _mock_main_dependencies(mocker, invalid_corpus, _REAL_ISOTONIC_MODEL, watchman, cipher, tmp_path)
    mocker.patch("sys.argv", ["run_evaluation_harness.py", "--sample-size-per-class", "3"])

    with pytest.raises(SystemExit) as exc:
        script.main()

    assert exc.value.code == 3
    captured = capsys.readouterr()
    assert "Release gate" not in captured.out


# --- Story 4.2: run lock, cache/budget wiring, budget-exceeded exit code -----


def test_main_passes_temperature_cache_budget_to_agents(  # type: ignore[no-untyped-def]
    valid_corpus, mocker, tmp_path
) -> None:
    watchman_cls = mocker.patch(
        "run_evaluation_harness.WatchmanAgent", return_value=_mock_agent()
    )
    cipher_cls = mocker.patch(
        "run_evaluation_harness.CipherAgent", return_value=_mock_agent()
    )
    mocker.patch("run_evaluation_harness.load_corpus", return_value=valid_corpus)
    mocker.patch(
        "run_evaluation_harness.load_calibration_model", return_value=_REAL_ISOTONIC_MODEL
    )
    mocker.patch(
        "run_evaluation_harness.load_config",
        return_value=mocker.Mock(eval_corpus_path=None, deferral_threshold=0.05),
    )
    mocker.patch(
        "run_evaluation_harness._CALIBRATION_MODEL_PATH", str(tmp_path / "calibration_model_v1.json")
    )
    mocker.patch("run_evaluation_harness._STATE_DB_PATH", str(tmp_path / "state.db"))
    mocker.patch("sys.argv", ["run_evaluation_harness.py", "--sample-size-per-class", "3"])

    with pytest.raises(SystemExit):
        script.main()

    _config, watchman_kwargs = watchman_cls.call_args
    assert watchman_kwargs["temperature"] == 0
    assert watchman_kwargs["budget"] is not None
    _config, cipher_kwargs = cipher_cls.call_args
    assert cipher_kwargs["cache"] is not None
    assert cipher_kwargs["budget"] is not None
    assert watchman_kwargs["budget"] is cipher_kwargs["budget"]


def test_main_second_concurrent_invocation_fails_before_load_corpus_or_load_calibration_model(  # type: ignore[no-untyped-def]
    valid_corpus, mocker, tmp_path
) -> None:
    """This script only ever READS calibration_model_v1.json (never
    writes it) -- the 2026-07-30 incident this closes was two concurrent
    invocations of this exact read-only script. Proves the lock fires
    before EITHER load_corpus OR load_calibration_model is reached, not
    just before run()."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    load_corpus_spy = mocker.patch(
        "run_evaluation_harness.load_corpus", return_value=valid_corpus
    )
    load_calibration_model_spy = mocker.patch(
        "run_evaluation_harness.load_calibration_model", return_value=_REAL_ISOTONIC_MODEL
    )
    mocker.patch("run_evaluation_harness.WatchmanAgent", return_value=watchman)
    mocker.patch("run_evaluation_harness.CipherAgent", return_value=cipher)
    mocker.patch(
        "run_evaluation_harness.load_config",
        return_value=mocker.Mock(eval_corpus_path=None, deferral_threshold=0.05),
    )
    resource_path = str(tmp_path / "calibration_model_v1.json")
    mocker.patch("run_evaluation_harness._CALIBRATION_MODEL_PATH", resource_path)
    mocker.patch("run_evaluation_harness._STATE_DB_PATH", str(tmp_path / "state.db"))
    mocker.patch("sys.argv", ["run_evaluation_harness.py"])

    with acquire_run_lock(resource_path):
        with pytest.raises(SystemExit) as exc:
            script.main()

    assert exc.value.code == 4
    load_corpus_spy.assert_not_called()
    load_calibration_model_spy.assert_not_called()
    watchman.analyze.assert_not_called()
    cipher.analyze.assert_not_called()


def test_main_budget_exceeded_exits_three_with_no_report_printed(  # type: ignore[no-untyped-def]
    valid_corpus, mocker, capsys, tmp_path
) -> None:
    watchman = _mock_agent()
    watchman.analyze.side_effect = ApiCallBudgetExceededError("ceiling reached")
    cipher = _mock_agent()
    _mock_main_dependencies(mocker, valid_corpus, _REAL_ISOTONIC_MODEL, watchman, cipher, tmp_path)
    mocker.patch("sys.argv", ["run_evaluation_harness.py", "--sample-size-per-class", "3"])

    with pytest.raises(SystemExit) as exc:
        script.main()

    assert exc.value.code == 3
    captured = capsys.readouterr()
    assert "Release gate" not in captured.out
    # The lock must still be released even though the run aborted.
    assert not Path(f"{tmp_path / 'calibration_model_v1.json'}.lock").exists()


def _tuning_key_references(tree: ast.AST) -> list[str]:
    """Mirror of fit_real_calibration_model.py's test suite's
    _held_out_key_references, inverted to scan for 'tuning' instead of
    'held_out' -- same subscript-OR-.get() detection logic, same reasoning
    for why it must be AST-based (the module docstring and a progress-log
    message both legitimately say 'tuning' as prose).

    [Review] Known limitation, accepted (same as the held_out guard this
    mirrors): only matches literal ast.Constant string keys. A computed key
    -- an f-string, a variable, or a loop over eval.py's own
    _SPLITS = ("tuning", "held_out") tuple (a pattern eval.py already uses
    internally, e.g. _check_split_integrity's corpus[f"benign_{split_name}"])
    -- would slip past undetected. Not fixed: catching arbitrary string
    construction is disproportionate complexity for a guard whose job is
    catching the two idiomatic literal-access forms a straightforward future
    edit would actually write, not defeating deliberate evasion."""
    violations: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
            and "tuning" in node.slice.value
        ):
            violations.append(node.slice.value)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and "tuning" in node.args[0].value
        ):
            violations.append(node.args[0].value)
    return violations


def test_script_never_reads_a_tuning_dict_key() -> None:
    """[AC5's mirror invariant] Permanent structural guard: run_evaluation_
    harness.py must never read a tuning key (benign_tuning/malicious_tuning)
    from any dict, by subscript OR .get(). Evaluating against data the fit
    has already seen would overstate real-world calibration quality,
    silently invalidating the release-gate check this script exists to
    make trustworthy."""
    source_path = Path(__file__).resolve().parents[1] / "run_evaluation_harness.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))

    violations = _tuning_key_references(tree)

    assert violations == [], (
        f"run_evaluation_harness.py reads a tuning dict key: {violations!r} -- "
        "tuning must never be read by the evaluation harness"
    )


def test_tuning_guard_detects_subscript_access() -> None:
    poisoned = ast.parse('x = corpus["benign_tuning"]')
    assert _tuning_key_references(poisoned) == ["benign_tuning"]


def test_tuning_guard_detects_get_style_access() -> None:
    poisoned = ast.parse('x = corpus.get("malicious_tuning")')
    assert _tuning_key_references(poisoned) == ["malicious_tuning"]
