"""
Free, local, zero-API-cost scan of the eval corpus for real files whose
HEADER-ONLY evidence already looks like a candidate for one of
check_structural_deferral's two structural pre-calibration deferral gates
(src/sentinel/triage/worker.py) -- Story 4.1.

WHY THIS EXISTS
----------------
The 2026-07-28 calibration saturation incident's "zero real samples exercise
either structural deferral gate" finding was only ever measured against the
default --sample-size-per-class 200 cap -- most of the corpus was never
checked. This script scans the WHOLE corpus (all four class/split buckets)
using only pure, free functions (no Watchman/Cipher calls) to narrow down
real candidates before spending real API budget confirming them via
fit_real_calibration_model.py / run_evaluation_harness.py.

This is header-only evidence -- a NECESSARY BUT NOT SUFFICIENT filter. The
full combined evidence (header + Watchman + Cipher) can still differ once
those two agents are actually run; this script only narrows the candidate
pool cheaply, it does not itself prove a gate fires.

NOT under src/sentinel/triage/ -- deliberately. This script doesn't fit or
evaluate against the corpus, it only classifies/reports, so the "never touch
held_out/tuning" AST-based structural guards (test_script_never_reads_a_
held_out_dict_key / test_script_never_reads_a_tuning_dict_key, which apply
to fit_real_calibration_model.py / run_evaluation_harness.py specifically)
do not apply here. This script legitimately reads all four class/split
buckets -- that is its whole purpose, not a guard violation.

USAGE
-----
    python scan_corpus_for_deferral_candidates.py

Run with --help for all options.
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Literal, TypedDict

from sentinel.config import load as load_config
from sentinel.triage.eval import Corpus, CorpusFile, load_corpus
from sentinel.triage.headers import investigate_header_authentication
from sentinel.triage.ingest import extract_auth_results_header_from_eml
from sentinel.triage.scoring import compute_raw_score

Classification = Literal["all_neutral", "conflicting_band", "neither"]


def classify_header_only_evidence(
    auth_results_header: str | None, deferral_band: float
) -> tuple[Classification, float]:
    """Mirrors check_structural_deferral's exact two-gate logic (worker.py),
    operating on HEADER-ONLY evidence instead of the full combined evidence
    a real pipeline run would produce. Gate order and conditions (including
    the strict `<` on deferral_band) are copied verbatim -- do not
    reimplement differently, or this scan's predictions could diverge from
    what a real run actually does."""
    evidence = investigate_header_authentication(auth_results_header)
    raw_score = compute_raw_score(evidence)
    if all(item["direction"] == "neutral" for item in evidence):
        return "all_neutral", raw_score
    if math.isclose(raw_score, 0.5, abs_tol=1e-9) or abs(raw_score - 0.5) < deferral_band:
        return "conflicting_band", raw_score
    return "neither", raw_score


class ClassifiedFile(TypedDict):
    path: str
    content_hash: str
    classification: Classification
    raw_score: float


def classify_corpus_file(corpus_file: CorpusFile, deferral_band: float) -> ClassifiedFile | None:
    """Reads one file's raw bytes, extracts its header, classifies it.
    Returns None on any read failure (skip, don't abort the whole scan) --
    matches this codebase's established per-file failure-isolation
    discipline (fit_real_calibration_model.py's _score_one_file)."""
    try:
        raw_bytes = Path(corpus_file["path"]).read_bytes()
    except OSError:
        return None
    auth_header = extract_auth_results_header_from_eml(raw_bytes)
    classification, raw_score = classify_header_only_evidence(auth_header, deferral_band)
    return ClassifiedFile(
        path=corpus_file["path"],
        content_hash=corpus_file["content_hash"],
        classification=classification,
        raw_score=raw_score,
    )


class BucketReport(TypedDict):
    all_neutral: list[ClassifiedFile]
    conflicting_band: list[ClassifiedFile]


def scan_bucket(files: list[CorpusFile], deferral_band: float) -> BucketReport:
    """`neither`-classified files are intentionally not collected -- they
    aren't candidates for anything this story needs."""
    all_neutral: list[ClassifiedFile] = []
    conflicting_band: list[ClassifiedFile] = []
    for corpus_file in files:
        classified = classify_corpus_file(corpus_file, deferral_band)
        if classified is None:
            continue
        if classified["classification"] == "all_neutral":
            all_neutral.append(classified)
        elif classified["classification"] == "conflicting_band":
            conflicting_band.append(classified)
    return BucketReport(all_neutral=all_neutral, conflicting_band=conflicting_band)


class CorpusScanReport(TypedDict):
    benign_tuning: BucketReport
    benign_held_out: BucketReport
    malicious_tuning: BucketReport
    malicious_held_out: BucketReport


def scan_corpus(corpus: Corpus, deferral_band: float) -> CorpusScanReport:
    """Reports each of the four class/split buckets SEPARATELY -- an
    existing file's tuning/held_out assignment is fixed at harvest time and
    cannot be moved (see this story's Dev Notes), so a caller must know
    exactly which bucket a candidate came from."""
    return CorpusScanReport(
        benign_tuning=scan_bucket(corpus["benign_tuning"], deferral_band),
        benign_held_out=scan_bucket(corpus["benign_held_out"], deferral_band),
        malicious_tuning=scan_bucket(corpus["malicious_tuning"], deferral_band),
        malicious_held_out=scan_bucket(corpus["malicious_held_out"], deferral_band),
    )


def _print_bucket(name: str, bucket: BucketReport) -> None:
    print(
        f"{name}: {len(bucket['all_neutral'])} all_neutral, "
        f"{len(bucket['conflicting_band'])} conflicting_band"
    )
    for classified in bucket["all_neutral"]:
        print(
            f"  [all_neutral] {classified['content_hash'][:12]} "
            f"raw_score={classified['raw_score']:.4f} {classified['path']}"
        )
    for classified in bucket["conflicting_band"]:
        print(
            f"  [conflicting_band] {classified['content_hash'][:12]} "
            f"raw_score={classified['raw_score']:.4f} {classified['path']}"
        )


def _default_corpus_path(config: object) -> str:
    eval_corpus_path = getattr(config, "eval_corpus_path", None)
    return eval_corpus_path or "benign_corpus_raw"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--corpus-path",
        default=None,
        help="path to the eval corpus root (default: EVAL_CORPUS_PATH if set, else 'benign_corpus_raw')",
    )
    args = parser.parse_args()

    config = load_config()
    corpus_path = args.corpus_path or _default_corpus_path(config)
    corpus = load_corpus(corpus_path)
    report = scan_corpus(corpus, config.deferral_threshold)

    print("=== Corpus Deferral-Candidate Scan (header-only, zero API cost) ===")
    print(f"deferral_band (config.deferral_threshold): {config.deferral_threshold}")
    print()
    _print_bucket("benign_tuning", report["benign_tuning"])
    _print_bucket("benign_held_out", report["benign_held_out"])
    _print_bucket("malicious_tuning", report["malicious_tuning"])
    _print_bucket("malicious_held_out", report["malicious_held_out"])


if __name__ == "__main__":
    main()
