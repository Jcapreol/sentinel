"""Tests for the repo-root fit_real_calibration_model.py orchestration
script (Story 3.3). The script lives outside src/ (matches harvest_own_
inbox.py/harvest_phishing_pot.py's repo-root, standalone-script convention),
so it is imported here via a sys.path insertion rather than pytest's
normal pythonpath=["src"] resolution -- an explicit, documented choice
(see this story's Dev Notes), not an accident.

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

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import fit_real_calibration_model as script  # noqa: E402

from sentinel.triage.eval import load_corpus  # noqa: E402
from sentinel.triage.script_guard import (  # noqa: E402
    ApiCallBudgetExceededError,
    acquire_run_lock,
)

_PLAIN_BODY = "Hi, just checking in about our meeting tomorrow. Thanks!"
_PHISHING_ADJACENT_BODY = (
    "URGENT ACTION REQUIRED: Please verify your account within 24 hours or it "
    "will be suspended. Click here to confirm your identity."
)
_PROVENANCE_TEXT = (
    "Sourced from a synthetic test fixture generated for unit testing purposes. "
    "This is not real harvested data; see tests/test_fit_real_calibration_model.py."
)


def _write_eml(path: Path, subject: str, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = f"From: test@example.com\r\nSubject: {subject}\r\n"
    path.write_bytes((headers + "\r\n" + body).encode())


def _write_class(root: Path, cls: str, tuning_count: int, held_out_count: int) -> None:
    """Deliberately different tuning/held_out counts (35 vs 8) so an
    off-by-split-name bug is detectable -- if the script ever accidentally
    reads held_out, the resulting pair/call count would visibly not match
    what sampling from tuning alone predicts."""
    (root / cls).mkdir(parents=True, exist_ok=True)
    (root / cls / "PROVENANCE.md").write_text(_PROVENANCE_TEXT, encoding="utf-8")

    # >=10% phishing-adjacent content keeps the benign-diversity check happy
    # regardless of which class this is called for.
    bodies = [_PHISHING_ADJACENT_BODY] + [_PLAIN_BODY] * 9

    # [Review][Patch] Marker includes `cls`, not just t{i}/h{i} -- without it,
    # calling this twice (once per class) with the same per-class-local index
    # produces byte-identical files across classes whenever they land on the
    # same cycled body text, which validate_corpus's same-split cross-class
    # overlap check (added in this same review round) correctly rejects.
    for i in range(tuning_count):
        body = f"{bodies[i % len(bodies)]} (unique marker {cls}-t{i})"
        _write_eml(root / cls / "tuning" / f"{cls}-tuning-{i}.eml", f"Subject {cls} t{i}", body)
    for i in range(held_out_count):
        body = f"{bodies[i % len(bodies)]} (unique marker {cls}-h{i})"
        _write_eml(root / cls / "held_out" / f"{cls}-held_out-{i}.eml", f"Subject {cls} h{i}", body)


@pytest.fixture
def valid_corpus(tmp_path: Path):  # type: ignore[no-untyped-def]
    """A corpus large enough to clear validate_corpus's checks (>=30 unique
    samples/class, provenance, benign diversity, no cross-split overlap)."""
    _write_class(tmp_path, "benign", tuning_count=35, held_out_count=8)
    _write_class(tmp_path, "malicious", tuning_count=35, held_out_count=8)
    return load_corpus(str(tmp_path))


def _mock_agent() -> MagicMock:
    agent = MagicMock()
    agent.analyze.return_value = {"evidence": []}
    return agent


def test_run_never_calls_analyze_for_held_out_files(valid_corpus) -> None:  # type: ignore[no-untyped-def]
    watchman = _mock_agent()
    cipher = _mock_agent()

    script.run(valid_corpus, sample_size_per_class=3, watchman=watchman, cipher=cipher)

    # 3 benign + 3 malicious tuning files sampled -> exactly 6 pipeline runs.
    # held_out has 8+8=16 files; if the script ever touched them, this count
    # would be higher than 6, proving held_out is never fed through the
    # pipeline -- a call-count assertion on the mock, not an I/O spy.
    assert watchman.analyze.call_count == 6
    assert cipher.analyze.call_count == 6


def test_run_produces_a_calibration_model_from_sampled_pairs(valid_corpus) -> None:  # type: ignore[no-untyped-def]
    watchman = _mock_agent()
    cipher = _mock_agent()

    model = script.run(valid_corpus, sample_size_per_class=3, watchman=watchman, cipher=cipher)

    assert model["sample_count"] == 6
    assert model["method"] in ("isotonic", "platt")


def test_collect_pairs_assigns_correct_labels_to_each_class(valid_corpus) -> None:  # type: ignore[no-untyped-def]
    """[Review][Patch] The label assignment (0.0 benign / 1.0 malicious) in
    collect_pairs's `targets` construction is the single most safety-critical
    line in this script -- a swapped label would silently invert the fitted
    calibration model, making it confidently wrong. Every other test in this
    file only asserts call/pair counts, never the actual label values, so a
    regression that swapped the two list comprehensions (or reordered them)
    would have passed every one of them. This test would catch it directly."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    sampled_benign = valid_corpus["benign_tuning"][:2]
    sampled_malicious = valid_corpus["malicious_tuning"][:3]

    pairs = script.collect_pairs(sampled_benign, sampled_malicious, watchman, cipher)

    labels = [label for _raw_score, label in pairs]
    assert labels == [0.0, 0.0, 1.0, 1.0, 1.0]


def test_run_rejects_invalid_corpus(tmp_path: Path) -> None:
    # Only benign written -- malicious class entirely missing -> is_valid=False.
    _write_class(tmp_path, "benign", tuning_count=35, held_out_count=8)
    invalid_corpus = load_corpus(str(tmp_path))
    watchman = _mock_agent()
    cipher = _mock_agent()

    with pytest.raises(ValueError, match="failed validation"):
        script.run(invalid_corpus, sample_size_per_class=3, watchman=watchman, cipher=cipher)

    # Never even attempted the pipeline against an unvalidated corpus.
    watchman.analyze.assert_not_called()
    cipher.analyze.assert_not_called()


def test_run_raises_clear_error_when_every_sampled_file_fails(
    valid_corpus, mocker  # type: ignore[no-untyped-def]
) -> None:
    """[Review][Patch] Traced by hand during code review, now proven by an
    actual test: if every sampled file's pipeline call fails (e.g. all
    unreadable), collect_pairs returns [], and fit_calibration_mapping
    (Story 3.2) already raises a clear ValueError on empty pairs -- this
    must propagate through run() as a clean, actionable error, not a
    confusing crash deeper in the stack."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    mocker.patch("pathlib.Path.read_bytes", side_effect=OSError("simulated: every file unreadable"))

    with pytest.raises(ValueError, match="zero"):
        script.run(valid_corpus, sample_size_per_class=3, watchman=watchman, cipher=cipher)


def test_collect_pairs_skips_unreadable_file_without_aborting(
    valid_corpus, mocker  # type: ignore[no-untyped-def]
) -> None:
    watchman = _mock_agent()
    cipher = _mock_agent()
    sampled_benign = valid_corpus["benign_tuning"][:2]
    sampled_malicious = valid_corpus["malicious_tuning"][:2]

    real_read_bytes = Path.read_bytes
    call_count = {"n": 0}

    def flaky_read_bytes(self: Path, *args: object, **kwargs: object) -> bytes:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise OSError("simulated read failure")
        return real_read_bytes(self, *args, **kwargs)

    mocker.patch("pathlib.Path.read_bytes", flaky_read_bytes)

    pairs = script.collect_pairs(sampled_benign, sampled_malicious, watchman, cipher)

    # 4 files sampled, 1 unreadable -> 3 pairs collected, not a crash.
    assert len(pairs) == 3


def test_collect_pairs_skips_file_when_content_extraction_raises(
    valid_corpus, mocker  # type: ignore[no-untyped-def]
) -> None:
    """[Review][Patch] _score_one_file's docstring promises "None on any
    failure", but extract_auth_results_header_from_eml/extract_email_content
    were previously unguarded -- currently non-exploitable only because
    those two functions independently document themselves as "never
    raises", making the code accidentally safe rather than structurally
    safe (inconsistent with this exact codebase's own established
    discipline of not trusting even documented "never raises" contracts at
    this kind of per-item processing boundary -- see
    gather_evidence_and_raw_score's own docstring on the SentinelAgent
    Protocol). This test proves a failure in extract_email_content is
    skipped, not fatal to the whole run."""
    watchman = _mock_agent()
    cipher = _mock_agent()
    sampled_benign = valid_corpus["benign_tuning"][:2]
    sampled_malicious = valid_corpus["malicious_tuning"][:2]

    mocker.patch(
        "fit_real_calibration_model.extract_email_content",
        side_effect=RuntimeError("simulated extraction failure"),
    )

    pairs = script.collect_pairs(sampled_benign, sampled_malicious, watchman, cipher)

    assert pairs == []


def test_main_dry_run_does_not_write_output(
    valid_corpus, tmp_path: Path, mocker  # type: ignore[no-untyped-def]
) -> None:
    output_path = tmp_path / "would_be_written.json"
    watchman = _mock_agent()
    cipher = _mock_agent()

    mocker.patch("fit_real_calibration_model.WatchmanAgent", return_value=watchman)
    mocker.patch("fit_real_calibration_model.CipherAgent", return_value=cipher)
    mocker.patch("fit_real_calibration_model.load_corpus", return_value=valid_corpus)
    mocker.patch(
        "fit_real_calibration_model.load_config",
        return_value=mocker.Mock(eval_corpus_path=None),
    )
    # Story 4.2: redirect the shared cache/budget state DB into tmp_path --
    # without this, main() would touch a real file at the repo root.
    mocker.patch("fit_real_calibration_model._STATE_DB_PATH", str(tmp_path / "state.db"))
    mocker.patch(
        "sys.argv",
        [
            "fit_real_calibration_model.py",
            "--sample-size-per-class",
            "3",
            "--output",
            str(output_path),
            "--dry-run",
        ],
    )

    script.main()

    assert not output_path.exists()


def test_main_writes_output_without_dry_run(
    valid_corpus, tmp_path: Path, mocker  # type: ignore[no-untyped-def]
) -> None:
    output_path = tmp_path / "calibration_model_v1.json"
    watchman = _mock_agent()
    cipher = _mock_agent()

    mocker.patch("fit_real_calibration_model.WatchmanAgent", return_value=watchman)
    mocker.patch("fit_real_calibration_model.CipherAgent", return_value=cipher)
    mocker.patch("fit_real_calibration_model.load_corpus", return_value=valid_corpus)
    mocker.patch(
        "fit_real_calibration_model.load_config",
        return_value=mocker.Mock(eval_corpus_path=None),
    )
    mocker.patch("fit_real_calibration_model._STATE_DB_PATH", str(tmp_path / "state.db"))
    mocker.patch(
        "sys.argv",
        [
            "fit_real_calibration_model.py",
            "--sample-size-per-class",
            "3",
            "--output",
            str(output_path),
        ],
    )

    script.main()

    assert output_path.exists()


def test_main_passes_temperature_cache_budget_to_agents(  # type: ignore[no-untyped-def]
    valid_corpus, tmp_path: Path, mocker
) -> None:
    output_path = tmp_path / "calibration_model_v1.json"
    watchman_cls = mocker.patch(
        "fit_real_calibration_model.WatchmanAgent", return_value=_mock_agent()
    )
    cipher_cls = mocker.patch(
        "fit_real_calibration_model.CipherAgent", return_value=_mock_agent()
    )
    mocker.patch("fit_real_calibration_model.load_corpus", return_value=valid_corpus)
    mocker.patch(
        "fit_real_calibration_model.load_config",
        return_value=mocker.Mock(eval_corpus_path=None),
    )
    mocker.patch("fit_real_calibration_model._STATE_DB_PATH", str(tmp_path / "state.db"))
    mocker.patch(
        "sys.argv",
        [
            "fit_real_calibration_model.py",
            "--sample-size-per-class",
            "3",
            "--output",
            str(output_path),
            "--cache-ttl-seconds",
            "120",
        ],
    )

    script.main()

    _config, watchman_kwargs = watchman_cls.call_args
    assert watchman_kwargs["temperature"] == 0
    assert watchman_kwargs["budget"] is not None
    _config, cipher_kwargs = cipher_cls.call_args
    assert cipher_kwargs["cache"] is not None
    assert cipher_kwargs["budget"] is not None
    # The two agents must share the SAME budget object -- AC3's "Watchman +
    # Cipher combined" ceiling only holds if both report to one instance.
    assert watchman_kwargs["budget"] is cipher_kwargs["budget"]


def test_main_second_concurrent_invocation_fails_before_any_pipeline_work(  # type: ignore[no-untyped-def]
    valid_corpus, tmp_path: Path, mocker
) -> None:
    output_path = tmp_path / "calibration_model_v1.json"
    load_corpus_spy = mocker.patch(
        "fit_real_calibration_model.load_corpus", return_value=valid_corpus
    )
    mocker.patch(
        "fit_real_calibration_model.load_config",
        return_value=mocker.Mock(eval_corpus_path=None),
    )
    mocker.patch("fit_real_calibration_model._STATE_DB_PATH", str(tmp_path / "state.db"))
    mocker.patch(
        "sys.argv",
        ["fit_real_calibration_model.py", "--output", str(output_path)],
    )

    with acquire_run_lock(str(output_path)):
        with pytest.raises(SystemExit) as exc:
            script.main()

    assert exc.value.code == 1
    load_corpus_spy.assert_not_called()


def test_main_writes_output_while_lock_is_still_held(
    valid_corpus, tmp_path: Path, mocker  # type: ignore[no-untyped-def]
) -> None:
    """Regression test for code review finding 2026-08-03:
    save_calibration_model previously ran AFTER the lock's `with` block had
    already exited, so the actual file write wasn't protected by the lock at
    all -- defeating the lock's stated purpose for this script. Proven by
    asserting the lock file still exists at the exact moment
    save_calibration_model is called, not just that it's gone afterward."""
    output_path = tmp_path / "calibration_model_v1.json"
    lock_path = Path(f"{output_path}.lock")
    watchman = _mock_agent()
    cipher = _mock_agent()
    mocker.patch("fit_real_calibration_model.WatchmanAgent", return_value=watchman)
    mocker.patch("fit_real_calibration_model.CipherAgent", return_value=cipher)
    mocker.patch("fit_real_calibration_model.load_corpus", return_value=valid_corpus)
    mocker.patch(
        "fit_real_calibration_model.load_config",
        return_value=mocker.Mock(eval_corpus_path=None),
    )
    mocker.patch("fit_real_calibration_model._STATE_DB_PATH", str(tmp_path / "state.db"))
    mocker.patch(
        "sys.argv",
        ["fit_real_calibration_model.py", "--sample-size-per-class", "3", "--output", str(output_path)],
    )
    lock_existed_at_write_time = {}
    real_save = script.save_calibration_model

    def spy_save(model, path):  # type: ignore[no-untyped-def]
        lock_existed_at_write_time["value"] = lock_path.exists()
        return real_save(model, path)

    mocker.patch("fit_real_calibration_model.save_calibration_model", side_effect=spy_save)

    script.main()

    assert lock_existed_at_write_time["value"] is True
    assert not lock_path.exists()  # released once main() fully completes


def test_main_resolves_output_path_before_acquiring_the_lock(
    valid_corpus, tmp_path: Path, mocker  # type: ignore[no-untyped-def]
) -> None:
    """Regression test for code review finding 2026-08-03: the lock was
    previously keyed on the raw, unresolved args.output CLI value, so two
    invocations targeting the same real file via different path spellings
    would compute different lock file names and both succeed -- defeating
    Design Decision 2's "resolved path" requirement and the cross-script
    race protection it exists to provide."""
    output_path = tmp_path / "calibration_model_v1.json"
    unresolved_output = str(tmp_path / "subdir" / ".." / "calibration_model_v1.json")
    watchman = _mock_agent()
    cipher = _mock_agent()
    mocker.patch("fit_real_calibration_model.WatchmanAgent", return_value=watchman)
    mocker.patch("fit_real_calibration_model.CipherAgent", return_value=cipher)
    mocker.patch("fit_real_calibration_model.load_corpus", return_value=valid_corpus)
    mocker.patch(
        "fit_real_calibration_model.load_config",
        return_value=mocker.Mock(eval_corpus_path=None),
    )
    mocker.patch("fit_real_calibration_model._STATE_DB_PATH", str(tmp_path / "state.db"))
    lock_spy = mocker.patch(
        "fit_real_calibration_model.acquire_run_lock", side_effect=acquire_run_lock
    )
    mocker.patch(
        "sys.argv",
        [
            "fit_real_calibration_model.py",
            "--sample-size-per-class",
            "3",
            "--output",
            unresolved_output,
        ],
    )

    script.main()

    lock_spy.assert_called_once_with(str(Path(unresolved_output).resolve()))
    assert str(Path(unresolved_output).resolve()) == str(output_path)
    assert output_path.exists()


def test_main_prints_cost_warning_when_sample_size_exceeds_default(
    valid_corpus, tmp_path: Path, mocker, capsys  # type: ignore[no-untyped-def]
) -> None:
    """valid_corpus's tuning pools are only 35 files/class, so the default
    (200) always fully covers them regardless of --sample-size-per-class --
    _DEFAULT_SAMPLE_SIZE_PER_CLASS is patched down here purely to prove
    main() actually wires the warning through with the real args, matching
    print_sample_size_cost_warning's own already-covered capping logic
    (see test_script_guard.py) rather than re-testing that logic here."""
    output_path = tmp_path / "calibration_model_v1.json"
    watchman = _mock_agent()
    cipher = _mock_agent()
    mocker.patch("fit_real_calibration_model.WatchmanAgent", return_value=watchman)
    mocker.patch("fit_real_calibration_model.CipherAgent", return_value=cipher)
    mocker.patch("fit_real_calibration_model.load_corpus", return_value=valid_corpus)
    mocker.patch(
        "fit_real_calibration_model.load_config",
        return_value=mocker.Mock(eval_corpus_path=None),
    )
    mocker.patch("fit_real_calibration_model._STATE_DB_PATH", str(tmp_path / "state.db"))
    mocker.patch("fit_real_calibration_model._DEFAULT_SAMPLE_SIZE_PER_CLASS", 5)
    mocker.patch(
        "sys.argv",
        [
            "fit_real_calibration_model.py",
            "--sample-size-per-class",
            "30",
            "--output",
            str(output_path),
        ],
    )

    script.main()

    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "30" in captured.err


def test_main_silent_when_sample_size_is_default(
    valid_corpus, tmp_path: Path, mocker, capsys  # type: ignore[no-untyped-def]
) -> None:
    output_path = tmp_path / "calibration_model_v1.json"
    watchman = _mock_agent()
    cipher = _mock_agent()
    mocker.patch("fit_real_calibration_model.WatchmanAgent", return_value=watchman)
    mocker.patch("fit_real_calibration_model.CipherAgent", return_value=cipher)
    mocker.patch("fit_real_calibration_model.load_corpus", return_value=valid_corpus)
    mocker.patch(
        "fit_real_calibration_model.load_config",
        return_value=mocker.Mock(eval_corpus_path=None),
    )
    mocker.patch("fit_real_calibration_model._STATE_DB_PATH", str(tmp_path / "state.db"))
    mocker.patch(
        "sys.argv",
        ["fit_real_calibration_model.py", "--sample-size-per-class", "3", "--output", str(output_path)],
    )

    script.main()

    assert "WARNING" not in capsys.readouterr().err


def test_main_budget_exceeded_exits_one_with_no_output_written(  # type: ignore[no-untyped-def]
    valid_corpus, tmp_path: Path, mocker
) -> None:
    output_path = tmp_path / "calibration_model_v1.json"
    watchman = _mock_agent()
    watchman.analyze.side_effect = ApiCallBudgetExceededError("ceiling reached")
    mocker.patch("fit_real_calibration_model.WatchmanAgent", return_value=watchman)
    mocker.patch("fit_real_calibration_model.CipherAgent", return_value=_mock_agent())
    mocker.patch("fit_real_calibration_model.load_corpus", return_value=valid_corpus)
    mocker.patch(
        "fit_real_calibration_model.load_config",
        return_value=mocker.Mock(eval_corpus_path=None),
    )
    mocker.patch("fit_real_calibration_model._STATE_DB_PATH", str(tmp_path / "state.db"))
    mocker.patch(
        "sys.argv",
        ["fit_real_calibration_model.py", "--sample-size-per-class", "3", "--output", str(output_path)],
    )

    with pytest.raises(SystemExit) as exc:
        script.main()

    assert exc.value.code == 1
    assert not output_path.exists()
    # The lock must still be released even though the run aborted.
    assert not Path(f"{output_path}.lock").exists()


def _held_out_key_references(tree: ast.AST) -> list[str]:
    """Scans an AST for any dict access keyed by a string containing
    'held_out' -- both literal subscript access (corpus["...held_out..."])
    and .get()-style access (corpus.get("...held_out...")), the two
    idiomatic ways Python code reads a dict key at runtime. Extracted as its
    own function (not inlined in the test below) so the SAME detection
    logic that guards the real script can also be proven non-vacuous
    against poisoned snippets -- see test_held_out_guard_detects_*."""
    violations: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
            and "held_out" in node.slice.value
        ):
            violations.append(node.slice.value)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and "held_out" in node.args[0].value
        ):
            violations.append(node.args[0].value)
    return violations


def test_script_never_reads_a_held_out_dict_key() -> None:
    """[Review] Permanent structural guard for Epic 3's single most
    important invariant: fit_real_calibration_model.py must never read a
    held_out key (benign_held_out/malicious_held_out) from any dict, by
    subscript OR .get(). If tuning and held_out ever leak together, Story
    3.4's eventual evaluation numbers become meaningless -- this must fail
    loudly if that invariant is ever violated by a future code change, not
    rely solely on the call-count proxy in
    test_run_never_calls_analyze_for_held_out_files above.

    AST-based (matching this project's existing test_scoring_never_imports_
    confidence/test_triage_imports_no_remediation_capable_library
    guardrail-test pattern), not a plain text/string scan: the module
    docstring and a progress-log message both legitimately contain the word
    "held_out" as prose (explaining/confirming the invariant to a human
    reader) -- a naive substring check across the whole file would
    false-positive on those.

    [Review][Patch] Originally scanned ast.Subscript only -- both Blind
    Hunter and Edge Case Hunter independently found and reproduced the same
    gap: corpus.get("malicious_held_out") is a semantically identical,
    entirely idiomatic way a future "defensive" edit could read held_out
    data (Corpus is a plain TypedDict/dict at runtime), and it slipped past
    a subscript-only scan completely undetected. _held_out_key_references
    now checks both forms."""
    source_path = Path(__file__).resolve().parents[1] / "fit_real_calibration_model.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))

    violations = _held_out_key_references(tree)

    assert violations == [], (
        f"fit_real_calibration_model.py reads a held_out dict key: "
        f"{violations!r} -- held_out must never be read by calibration fitting"
    )


def test_held_out_guard_detects_subscript_access() -> None:
    """Proves the guard is not vacuous for the subscript form."""
    poisoned = ast.parse('x = corpus["benign_held_out"]')
    assert _held_out_key_references(poisoned) == ["benign_held_out"]


def test_held_out_guard_detects_get_style_access() -> None:
    """[Review][Patch] Proves the guard now also catches
    corpus.get("...held_out...") -- the exact gap both review layers found
    in the original subscript-only implementation."""
    poisoned = ast.parse('x = corpus.get("malicious_held_out")')
    assert _held_out_key_references(poisoned) == ["malicious_held_out"]
