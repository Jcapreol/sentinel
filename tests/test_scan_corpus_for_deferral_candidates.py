"""Tests for the repo-root scan_corpus_for_deferral_candidates.py script
(Story 4.1). Free, local, zero-API-cost classification of corpus files
against check_structural_deferral's two gates, using header-only evidence.

Follows fit_real_calibration_model.py/run_evaluation_harness.py's existing
repo-root-standalone-script test convention: imported via a sys.path
insertion, not pytest's normal pythonpath=["src"] resolution.

No real corpus, no EVAL_CORPUS_PATH, no network -- matches Story 3.1's
established CI/manual boundary (this logic is pure and free, so it gets
normal CI coverage; the real corpus scan itself is a manual step).
"""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import scan_corpus_for_deferral_candidates as script  # noqa: E402

from sentinel.triage.eval import CorpusFile  # noqa: E402

# --- classify_header_only_evidence -------------------------------------------


def test_classify_all_neutral_header_combo_when_every_mechanism_uninformative() -> None:
    header = "mx.google.com; spf=none smtp.mailfrom=example.com; dkim=none; dmarc=none"

    classification, raw_score = script.classify_header_only_evidence(header, deferral_band=0.05)

    assert classification == "all_neutral"
    assert raw_score == 0.5


def test_classify_no_header_at_all_is_all_neutral() -> None:
    """No Authentication-Results header at all is evidentially identical to a
    header present but every mechanism uninformative -- both hit
    headers.py's _UNINFORMATIVE_WEIGHT/neutral path for all 3 mechanisms."""
    classification, raw_score = script.classify_header_only_evidence(None, deferral_band=0.05)

    assert classification == "all_neutral"
    assert raw_score == 0.5


def test_classify_real_near_cancelling_combo_is_conflicting_band() -> None:
    """The exact worked example from this story's Dev Notes: spf=fail
    (weight 0.40, malicious) + dkim=pass (weight 0.35, benign) + dmarc=none
    (weight 0.10, neutral) -- signed_sum=0.05, total_weight=0.85,
    raw_score=9/17≈0.5294, within the default 0.05 deferral_band of 0.5."""
    header = "mx.google.com; spf=fail smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=none"

    classification, raw_score = script.classify_header_only_evidence(header, deferral_band=0.05)

    assert classification == "conflicting_band"
    assert raw_score == 9 / 17


def test_classify_clear_cut_all_pass_is_neither() -> None:
    header = "mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"

    classification, _raw_score = script.classify_header_only_evidence(header, deferral_band=0.05)

    assert classification == "neither"


def test_classify_clear_cut_all_fail_is_neither() -> None:
    header = "mx.google.com; spf=fail smtp.mailfrom=example.com; dkim=fail header.d=example.com; dmarc=fail"

    classification, _raw_score = script.classify_header_only_evidence(header, deferral_band=0.05)

    assert classification == "neither"


def test_classify_boundary_is_strict_less_than_matching_check_structural_deferral() -> None:
    """check_structural_deferral (src/sentinel/triage/worker.py) uses a
    STRICT `<` for the deferral_band comparison, not `<=` -- this proves
    classify_header_only_evidence mirrors that exactly, using the same
    near-cancelling combo as the conflicting-band test above (raw_score=9/17,
    |raw_score - 0.5| = 1/34 exactly)."""
    header = "mx.google.com; spf=fail smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=none"
    exact_diff = abs(9 / 17 - 0.5)  # 1/34

    at_boundary, _ = script.classify_header_only_evidence(header, deferral_band=exact_diff)
    just_inside, _ = script.classify_header_only_evidence(header, deferral_band=exact_diff + 0.001)

    assert at_boundary == "neither"  # strict < excludes the exact boundary
    assert just_inside == "conflicting_band"


# --- scan_bucket / scan_corpus -------------------------------------------------


def _corpus_file(path: str, content_hash: str) -> CorpusFile:
    return CorpusFile(path=path, content_hash=content_hash)


def _write_eml(path: Path, auth_header: str | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = "From: test@example.com\r\nSubject: test\r\n"
    if auth_header is not None:
        headers += f"Authentication-Results: {auth_header}\r\n"
    path.write_bytes((headers + "\r\nbody").encode())


def test_scan_bucket_separates_all_neutral_and_conflicting_band_files(tmp_path: Path) -> None:
    all_neutral_path = tmp_path / "all_neutral.eml"
    conflicting_path = tmp_path / "conflicting.eml"
    clear_cut_path = tmp_path / "clear_cut.eml"
    _write_eml(all_neutral_path, "mx.google.com; spf=none; dkim=none; dmarc=none")
    _write_eml(conflicting_path, "mx.google.com; spf=fail; dkim=pass; dmarc=none")
    _write_eml(clear_cut_path, "mx.google.com; spf=pass; dkim=pass; dmarc=pass")

    files = [
        _corpus_file(str(all_neutral_path), "hash-all-neutral"),
        _corpus_file(str(conflicting_path), "hash-conflicting"),
        _corpus_file(str(clear_cut_path), "hash-clear-cut"),
    ]

    report = script.scan_bucket(files, deferral_band=0.05)

    assert [f["content_hash"] for f in report["all_neutral"]] == ["hash-all-neutral"]
    assert [f["content_hash"] for f in report["conflicting_band"]] == ["hash-conflicting"]


def test_scan_bucket_skips_unreadable_file_without_aborting(tmp_path: Path) -> None:
    missing_path = tmp_path / "does_not_exist.eml"
    files = [_corpus_file(str(missing_path), "hash-missing")]

    report = script.scan_bucket(files, deferral_band=0.05)

    assert report["all_neutral"] == []
    assert report["conflicting_band"] == []


def test_scan_corpus_reports_all_four_buckets_separately(tmp_path: Path) -> None:
    """Task 2 depends on knowing which split a candidate is already sitting
    in -- an existing file's split cannot be moved (see this story's Dev
    Notes), so the report must never merge buckets together."""
    benign_tuning_path = tmp_path / "bt.eml"
    benign_held_out_path = tmp_path / "bh.eml"
    malicious_tuning_path = tmp_path / "mt.eml"
    malicious_held_out_path = tmp_path / "mh.eml"
    for p in (benign_tuning_path, benign_held_out_path, malicious_tuning_path, malicious_held_out_path):
        _write_eml(p, "mx.google.com; spf=none; dkim=none; dmarc=none")

    corpus = {
        "root": str(tmp_path),
        "benign_tuning": [_corpus_file(str(benign_tuning_path), "h-bt")],
        "benign_held_out": [_corpus_file(str(benign_held_out_path), "h-bh")],
        "malicious_tuning": [_corpus_file(str(malicious_tuning_path), "h-mt")],
        "malicious_held_out": [_corpus_file(str(malicious_held_out_path), "h-mh")],
    }

    report = script.scan_corpus(corpus, deferral_band=0.05)  # type: ignore[arg-type]

    assert [f["content_hash"] for f in report["benign_tuning"]["all_neutral"]] == ["h-bt"]
    assert [f["content_hash"] for f in report["benign_held_out"]["all_neutral"]] == ["h-bh"]
    assert [f["content_hash"] for f in report["malicious_tuning"]["all_neutral"]] == ["h-mt"]
    assert [f["content_hash"] for f in report["malicious_held_out"]["all_neutral"]] == ["h-mh"]
