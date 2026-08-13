"""
Run Sentinel's triage pipeline against a sample of the real eval corpus's
`held_out` split and report Expected Calibration Error (10-bin), AUC-ROC
discrimination, and deferral rate as one combined result set -- the
release-gate proof this project's PRD requires (FR12, FR13, FR17, FR28,
FR29).

WHY THIS EXISTS
----------------
Story 3.2/3.3 built and (separately, manually) run the calibration-FITTING
side (`fit_real_calibration_model.py`, `triage/eval.py`'s
`fit_calibration_mapping`). Fitting alone proves nothing about real-world
quality -- a fit measured against the same data it was fit on is not a
release-gate proof, it's circular. This script is the EVALUATION side: it
runs the pipeline against `held_out` data the fit has never seen, and
reports whether the release gate (ECE <= 0.10, AUC-ROC confirms a
non-flat predictor) is actually met. See Story 3.4
(`triage-3-4-evaluation-harness-ece-discrimination-deferral-rate`).

COST WARNING -- READ BEFORE RUNNING
-------------------------------------
Each sampled file is run through the FULL triage pipeline: a real Watchman
(Anthropic LLM) call and a real Cipher (VirusTotal/AbuseIPDB/URLhaus)
lookup. This is NOT free or instant. `--sample-size-per-class` (default
200) bounds the cost -- see `fit_real_calibration_model.py`'s own COST
WARNING for the exact same reasoning; it applies identically here.

DO NOT RUN CONCURRENTLY WITH fit_real_calibration_model.py
----------------------------------------------------------
This script's own identity-placeholder check and `scoring.py`'s
`apply_calibration` singleton each read `calibration_model_v1.json`
independently. If the file changes mid-run (e.g. `fit_real_calibration_
model.py` is running at the same time and overwrites it), the two reads
can disagree -- the printed verdict could describe a different model than
the one actually used to compute the reported confidences. See
`deferred-work.md`'s entry on this. Run the two scripts sequentially, not
concurrently.

WHAT THIS SCRIPT NEVER TOUCHES
--------------------------------
The corpus's `tuning` split (`benign_tuning`/`malicious_tuning`) is never
referenced anywhere in this file. Evaluating against data the fit has
already seen would overstate real-world calibration quality, silently
invalidating the release-gate check this script exists to make trustworthy
-- the exact mirror image of `fit_real_calibration_model.py`'s "never
touches `held_out`" invariant. Only `benign_held_out`/`malicious_held_out`
are ever sampled.

IF calibration_model_v1.json IS STILL THE IDENTITY PLACEHOLDER
------------------------------------------------------------------
This script still runs and reports numbers, but they are NOT a real
release-gate proof -- an unmissable warning is printed before anything
else, and the release-gate line is never an unqualified MET/NOT MET (see
`_print_report`). Exit code `2` signals this distinctly from a real `0`
(met) / `1` (not met) result, so an automated caller checking only the
exit code cannot mistake a placeholder run for a real verdict. Run
`fit_real_calibration_model.py` for real first if you want a real answer.

EXIT CODES
-----------
    0  Release gate MET (a real, non-placeholder measurement)
    1  Release gate NOT MET (a real, non-placeholder measurement)
    2  Ran against the identity placeholder -- no real verdict possible
    3  Could not measure at all (invalid corpus, misconfigured
       deferral_threshold, every sampled file's pipeline call failed, or
       the configured --api-call-ceiling was reached mid-run) -- distinct
       from 1 so an automated caller can tell "infra/setup problem" apart
       from "the model's calibration genuinely regressed"
    4  Could not acquire the run lock -- another invocation of this script,
       or of fit_real_calibration_model.py, is already running against the
       same calibration_model_v1.json (Story 4.2)

USAGE
-----
    python run_evaluation_harness.py
    python run_evaluation_harness.py --sample-size-per-class 200

Run with --help for all options.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TypedDict

from sentinel.cipher import CipherAgent
from sentinel.config import Config
from sentinel.config import load as load_config
from sentinel.triage.eval import (
    CalibrationModel,
    Corpus,
    CorpusFile,
    ECEResult,
)
from sentinel.triage.eval import _MIN_AUC_FOR_NON_FLAT as MIN_AUC_FOR_NON_FLAT
from sentinel.triage.eval import (
    compute_auc_roc,
    compute_ece,
    load_calibration_model,
    load_corpus,
    sample_corpus_files,
    validate_corpus,
)
from sentinel.triage.ingest import extract_auth_results_header_from_eml, extract_email_content
from sentinel.triage.script_guard import (
    DEFAULT_API_CEILING_WINDOW_HOURS,
    DEFAULT_CACHE_TTL_SECONDS,
    ApiCallBudget,
    ApiCallBudgetExceededError,
    LockAlreadyHeldError,
    LookupCache,
    acquire_run_lock,
    print_sample_size_cost_warning,
)
from sentinel.triage.scoring import InconclusiveScoreError, apply_calibration, determine_verdict
from sentinel.triage.worker import check_structural_deferral, gather_evidence_and_raw_score
from sentinel.verdict import SentinelAgent
from sentinel.watchman import WatchmanAgent

_DEFAULT_SAMPLE_SIZE_PER_CLASS = 200
# Same absolute-path-anchored-at-this-script's-own-location reasoning as
# fit_real_calibration_model.py's _DEFAULT_OUTPUT_PATH -- a CWD-dependent
# path would be a real footgun here too.
_CALIBRATION_MODEL_PATH = str(Path(__file__).resolve().parent / "calibration_model_v1.json")
# Story 4.2: shared with fit_real_calibration_model.py's identical constant
# -- both real-corpus scripts benefit from the same Cipher-lookup cache
# across separate invocations.
_STATE_DB_PATH = str(Path(__file__).resolve().parent / ".sentinel_script_state.db")
# [Story 4.1 follow-up, 2026-08-05] Per-file identity was previously
# discarded entirely once the process exited -- only aggregate ECE bins/
# AUC-ROC/deferral-rate survived, so no past or future result could be
# traced back to a specific file (see deferred-work.md). This is that fix's
# output path; same absolute-path-anchored convention as every other
# script-owned state file above.
_RESULTS_PATH = str(Path(__file__).resolve().parent / "results.json")
# [Review][Patch] Shared with fit_real_calibration_model.py via
# script_guard.py -- previously duplicated verbatim in both scripts (code
# review 2026-08-03).
_DEFAULT_CACHE_TTL_SECONDS = DEFAULT_CACHE_TTL_SECONDS
_DEFAULT_API_CEILING_WINDOW_HOURS = DEFAULT_API_CEILING_WINDOW_HOURS

# PROVISIONAL, not calibrated -- matches AC3's own "or the provisional
# figure in effect at the time" wording.
_PROVISIONAL_ECE_THRESHOLD = 0.10

_IDENTITY_PLACEHOLDER_WARNING = (
    "WARNING: calibration_model_v1.json is the identity placeholder, not a real "
    "fitted model. The numbers below do NOT represent a real release-gate proof. "
    "Run fit_real_calibration_model.py for real first, then re-run this harness."
)


def _default_corpus_path(config: Config) -> str:
    return config.eval_corpus_path or "benign_corpus_raw"


class ScoreOutcome(TypedDict):
    """[Story 6.1, AC7] Distinguishes WHY a file didn't produce a
    calibrated_confidence, not just whether it did. is_coverage_gap=True
    means the file itself could not be read at all -- this offline
    harness's analog of a live Gmail fetch failure (there is no network
    fetch here; a corpus file that cannot be read is the closest
    equivalent to "the message could not be fetched," structurally the
    same "nothing was analyzed" situation worker.py's CoverageGap verdict
    represents). is_coverage_gap=False with calibrated_confidence=None
    means the file WAS read but something else in the pipeline failed
    (extraction, Watchman/Cipher, calibration) -- unchanged "skip"
    behavior from before this story, still excluded from ECE/AUC-ROC
    either way, but not conflated with a coverage gap in reporting."""
    calibrated_confidence: float | None
    is_coverage_gap: bool


def _score_one_file(
    corpus_file: CorpusFile, watchman: SentinelAgent, cipher: SentinelAgent, deferral_band: float
) -> ScoreOutcome:
    """Runs one file through the pipeline, returning its calibrated_confidence
    (None on any failure EXCEPT ApiCallBudgetExceededError, which propagates
    uncaught to abort the whole run instead -- Story 4.2, AC3, see the
    dedicated except clause below) and whether that failure was specifically
    a coverage gap (Story 6.1, AC7 -- see ScoreOutcome). [Review][Patch]
    This docstring previously claimed "None on any failure" unconditionally,
    which was stale even at the time it was written -- the
    ApiCallBudgetExceededError carve-out already existed a few lines down
    (code review 2026-08-03). Otherwise identical per-file failure-isolation
    discipline to fit_real_calibration_model.py's (post-code-review)
    _score_one_file: both extraction calls AND the pipeline call are
    guarded, not just the pipeline call.

    [Fix] Now calls check_structural_deferral (src/sentinel/triage/worker.py)
    before apply_calibration, matching process_message's real order --
    previously this function called apply_calibration directly, bypassing
    process_message entirely, so it never exercised either structural
    pre-calibration deferral gate even after both were added to the live
    pipeline (2026-07-30 incident). A structurally-deferred file returns 0.5,
    matching process_message's own calibrated_confidence convention for a
    Deferred report, instead of whatever apply_calibration alone would have
    said."""
    try:
        raw_bytes = Path(corpus_file["path"]).read_bytes()
    except OSError as e:
        print(
            f"  WARNING: failed to read {corpus_file['path']}: {e} -- coverage gap "
            "(file unavailable; nothing was analyzed) -- excluded from ECE/AUC-ROC",
            file=sys.stderr,
        )
        return ScoreOutcome(calibrated_confidence=None, is_coverage_gap=True)

    try:
        auth_header = extract_auth_results_header_from_eml(raw_bytes)
        email_content = extract_email_content(raw_bytes)
        evidence, raw_score = gather_evidence_and_raw_score(
            auth_header, email_content, watchman, cipher
        )
        if check_structural_deferral(evidence, raw_score, deferral_band):
            return ScoreOutcome(calibrated_confidence=0.5, is_coverage_gap=False)
        # [Review] apply_calibration is now inside this try too -- it only
        # raises for an unrecognized `method` (a hand-edited/corrupted
        # calibration_model_v1.json), but this function's own docstring
        # promises "None on any failure" unconditionally.
        return ScoreOutcome(calibrated_confidence=apply_calibration(raw_score), is_coverage_gap=False)
    except ApiCallBudgetExceededError:
        # Story 4.2: must propagate uncaught, never treated as "this one
        # file failed, skip it and keep going" -- a budget-exceeded run
        # aborts entirely (AC3).
        raise
    except Exception as e:
        print(
            f"  WARNING: pipeline failed for {corpus_file['path']}: "
            f"{type(e).__name__}: {e} -- skipping",
            file=sys.stderr,
        )
        return ScoreOutcome(calibrated_confidence=None, is_coverage_gap=False)


class ScoredFile(TypedDict):
    content_hash: str
    path: str
    calibrated_confidence: float
    label: float


def collect_pairs(
    sampled_benign: list[CorpusFile],
    sampled_malicious: list[CorpusFile],
    watchman: SentinelAgent,
    cipher: SentinelAgent,
    deferral_band: float = 0.0,
) -> tuple[list[ScoredFile], int]:
    """Runs the triage pipeline against each sampled file, pairing its
    calibrated_confidence with its class label (0.0 benign, 1.0 malicious)
    AND the file's own identity (content_hash, path). Only ever called with
    *_held_out lists -- see this file's module docstring.

    [Story 4.1 follow-up, 2026-08-05] Previously returned bare
    `list[tuple[float, float]]` with no file identity attached -- once this
    function returned, there was no way to trace an aggregate result back
    to a specific file (see deferred-work.md). `run()` still derives the
    plain (confidence, label) pairs `compute_ece`/`compute_auc_roc`/
    `compute_deferral_rate` expect via a simple projection, so none of
    those three functions' own behavior changes.

    [Story 6.1, AC7] Now returns (scored_files, coverage_gap_count) instead
    of a bare list -- coverage-gap-equivalent files (unreadable, see
    ScoreOutcome) were ALREADY excluded from scored_files before this story
    (they always returned None, same bucket as any other failure); what's
    new is tracking and reporting that subset distinctly, not a change to
    what feeds ECE/AUC-ROC.

    [Fix] deferral_band defaults to 0.0 (only the all-neutral structural
    gate applies; the conflicting-but-uncertain gate never fires) rather
    than being required, so existing direct callers of this function that
    don't care about the deferral band keep working unchanged -- run()
    always passes its own validated deferral_band explicitly."""
    targets: list[tuple[CorpusFile, float]] = [(f, 0.0) for f in sampled_benign] + [
        (f, 1.0) for f in sampled_malicious
    ]
    total = len(targets)
    scored: list[ScoredFile] = []
    coverage_gap_count = 0
    # [Story 6.1 follow-up] Split per class purely for the zero-collected
    # warning messages below -- coverage_gap_count itself (combined) is
    # still the only count returned/reported elsewhere, matching AC7's
    # single "analyzed N of N+M" metric.
    benign_coverage_gaps = 0
    malicious_coverage_gaps = 0
    benign_collected = 0
    malicious_collected = 0
    for index, (corpus_file, label) in enumerate(targets, start=1):
        print(
            f"[{index}/{total}] processing {corpus_file['content_hash'][:12]}...",
            file=sys.stderr,
        )
        outcome = _score_one_file(corpus_file, watchman, cipher, deferral_band)
        if outcome["is_coverage_gap"]:
            coverage_gap_count += 1
            if label == 0.0:
                benign_coverage_gaps += 1
            else:
                malicious_coverage_gaps += 1
            continue
        calibrated_confidence = outcome["calibrated_confidence"]
        if calibrated_confidence is not None:
            scored.append(
                ScoredFile(
                    content_hash=corpus_file["content_hash"],
                    path=corpus_file["path"],
                    calibrated_confidence=calibrated_confidence,
                    label=label,
                )
            )
            if label == 0.0:
                benign_collected += 1
            else:
                malicious_collected += 1
    other_failures = total - len(scored) - coverage_gap_count
    print(
        f"Collected {len(scored)} pairs ({other_failures} skipped for other reasons, "
        f"{coverage_gap_count} coverage gap(s))",
        file=sys.stderr,
    )
    # [Story 6.1, AC7] Exact "analyzed N of N+M" form, M = coverage_gap_count
    # specifically -- distinct from the line above, which also folds in
    # other-reason failures. "N+M" here means "how many files were even
    # available to analyze," a different denominator than `total` (which
    # also includes files whose content WAS available but failed for an
    # unrelated pipeline reason).
    analyzed = len(scored)
    print(
        f"Coverage: analyzed {analyzed} of {analyzed + coverage_gap_count} "
        f"({coverage_gap_count} coverage gap(s) excluded from ECE/AUC-ROC)",
        file=sys.stderr,
    )

    # [Review] Without this, a total dropout of one class's samples (e.g. a
    # systemic extraction issue affecting only that class's file encoding)
    # is silently indistinguishable in the final report from genuinely poor
    # discrimination -- both just show a low/degenerate AUC-ROC with no
    # explanation of the actual root cause.
    if sampled_benign and benign_collected == 0:
        # [Story 6.1 follow-up] benign_coverage_gaps is already in scope here
        # -- if it accounts for the whole shortfall, say so; a maintainer
        # reading "pipeline call failed" when the real cause is "the files
        # were never readable" chases the wrong root cause.
        cause = (
            f"all {benign_coverage_gaps} were coverage gap(s) (files unreadable)"
            if benign_coverage_gaps == len(sampled_benign)
            else (
                f"every sampled benign file's pipeline call failed or was a coverage gap "
                f"({benign_coverage_gaps} of {len(sampled_benign)} were coverage gaps)"
            )
        )
        print(
            f"WARNING: zero benign pairs collected -- {cause}. AUC-ROC/ECE below reflect "
            "malicious-only data, not a real discrimination measurement.",
            file=sys.stderr,
        )
    if sampled_malicious and malicious_collected == 0:
        cause = (
            f"all {malicious_coverage_gaps} were coverage gap(s) (files unreadable)"
            if malicious_coverage_gaps == len(sampled_malicious)
            else (
                f"every sampled malicious file's pipeline call failed or was a coverage gap "
                f"({malicious_coverage_gaps} of {len(sampled_malicious)} were coverage gaps)"
            )
        )
        print(
            f"WARNING: zero malicious pairs collected -- {cause}. AUC-ROC/ECE below reflect "
            "benign-only data, not a real discrimination measurement.",
            file=sys.stderr,
        )
    return scored, coverage_gap_count


def _bin_range_for_confidence(
    confidence: float, num_bins: int = 10
) -> tuple[float, float] | None:
    """Mirrors compute_ece's own bin-boundary logic exactly
    (src/sentinel/triage/eval.py) -- deliberately NOT calling into
    compute_ece itself or modifying it (out of scope for this fix, and
    compute_ece's own output/behavior must stay unchanged), so a per-file
    report can say which bin a file landed in without touching compute_ece
    at all. If this boundary rule ever changes there, it must change here
    too. Returns None for a confidence outside [0.0, 1.0], mirroring
    compute_ece's own excluded_sample_count handling for the same case."""
    for i in range(num_bins):
        bin_min = i / num_bins
        bin_max = (i + 1) / num_bins
        if (bin_min <= confidence < bin_max) or (i == num_bins - 1 and confidence == bin_max):
            return (bin_min, bin_max)
    return None


def write_per_file_results(scored_files: list[ScoredFile], output_path: str) -> None:
    """Writes one JSON record per file (identity, calibrated_confidence,
    label, which ECE bin it landed in) -- additive to the existing console
    aggregate output, never replacing it. Direct fix for a real gap found
    during Story 4.1 (2026-08-04): once a real run's process exited, there
    was no way -- free or paid -- to trace an aggregate result back to a
    specific file. See deferred-work.md."""
    records = []
    for sf in scored_files:
        bin_range = _bin_range_for_confidence(sf["calibrated_confidence"])
        records.append(
            {
                "content_hash": sf["content_hash"],
                "path": sf["path"],
                "calibrated_confidence": sf["calibrated_confidence"],
                "label": sf["label"],
                "ece_bin": list(bin_range) if bin_range is not None else None,
            }
        )
    Path(output_path).write_text(json.dumps(records, indent=2), encoding="utf-8")


def compute_deferral_rate(calibrated_confidences: list[float], deferral_band: float) -> float:
    """Reuses determine_verdict's REAL deferral-band logic (not a
    reimplemented threshold check) -- calling it per sample and catching
    InconclusiveScoreError measures exactly what the live triage pipeline
    does, avoiding silent drift between what this harness measures and what
    the system actually does."""
    if not calibrated_confidences:
        return 0.0
    deferred = 0
    for confidence in calibrated_confidences:
        try:
            determine_verdict(confidence, deferral_band=deferral_band)
        except InconclusiveScoreError:
            deferred += 1
    return deferred / len(calibrated_confidences)


class EvaluationReport(TypedDict):
    sample_count: int
    ece_result: ECEResult
    auc_roc: float
    deferral_rate: float
    is_identity_placeholder: bool
    gate_met: bool | None  # None iff is_identity_placeholder (N/A, not a real verdict)
    # [Story 6.1, AC7] Files that could not be read at all (this offline
    # harness's analog of a live Gmail fetch failure) -- already excluded
    # from sample_count/ece_result/auc_roc/deferral_rate (unchanged from
    # before this story), exposed here as a first-class report field so a
    # caller doesn't have to scrape stderr to know the coverage-gap count.
    coverage_gap_count: int


def run(
    corpus: Corpus,
    calibration_model: CalibrationModel,
    sample_size_per_class: int | None,
    deferral_band: float,
    watchman: SentinelAgent,
    cipher: SentinelAgent,
    results_path: str | None = None,
) -> EvaluationReport:
    """Orchestrates validate -> identity-check -> sample -> collect pairs ->
    measure. Raises ValueError (never measures against unvalidated data, or
    against zero collected pairs) if the corpus fails validate_corpus or
    every sampled file's pipeline call fails.

    [Story 4.1 follow-up, 2026-08-05] `results_path` is optional and
    defaults to None (no file written) -- every existing caller of run()
    that doesn't pass it keeps working completely unchanged. When given,
    the per-file results (identity + confidence + label + ECE bin) are
    written there via write_per_file_results, additive to the existing
    EvaluationReport this function has always returned -- that return
    shape, and compute_ece/compute_auc_roc/compute_deferral_rate's own
    inputs and outputs, are all unchanged by this parameter.

    [Review] deferral_band is validated FIRST, before anything else --
    matching worker.py's process_message, which calls
    _require_valid_deferral_threshold as literally its first line, before
    any Watchman/Cipher call. compute_deferral_rate (via determine_verdict)
    already raised ValueError for an out-of-range deferral_band, but only
    after collect_pairs had already made every sampled file's real,
    paid pipeline call -- exactly the cost --sample-size-per-class exists
    to bound. A misconfigured SENTINEL_DEFERRAL_THRESHOLD (e.g. a typo like
    1.5, which parses fine as a float) must fail before burning that
    budget, not after."""
    if not (0.0 <= deferral_band <= 1.0):
        raise ValueError(f"deferral_band must be within [0.0, 1.0], got {deferral_band!r}")

    validation = validate_corpus(corpus)
    if not validation["is_valid"]:
        reasons = "\n".join(f"  - {r}" for r in validation["reasons"])
        raise ValueError(f"Corpus failed validation, refusing to evaluate:\n{reasons}")

    # Checked immediately after corpus validation, BEFORE any sampling or
    # pipeline calls (cheap check, done first) -- a maintainer who
    # accidentally runs this against the still-unfitted placeholder finds
    # out in seconds, not after burning real API calls on every sampled file.
    is_identity_placeholder = calibration_model["method"] == "identity"
    if is_identity_placeholder:
        print(_IDENTITY_PLACEHOLDER_WARNING, file=sys.stderr)

    sampled_benign = sample_corpus_files(corpus["benign_held_out"], sample_size_per_class)
    sampled_malicious = sample_corpus_files(corpus["malicious_held_out"], sample_size_per_class)
    print(
        f"Sampled {len(sampled_benign)} benign, {len(sampled_malicious)} malicious "
        "held_out files (tuning never touched)",
        file=sys.stderr,
    )

    scored_files, coverage_gap_count = collect_pairs(
        sampled_benign, sampled_malicious, watchman, cipher, deferral_band
    )
    if not scored_files:
        total_sampled = len(sampled_benign) + len(sampled_malicious)
        # [Story 6.1 follow-up] Name coverage gaps explicitly when they
        # explain the whole shortfall -- "every sampled file's pipeline call
        # failed" is misleading when the real cause is "every file was
        # unreadable and never reached the pipeline at all."
        if total_sampled > 0 and coverage_gap_count == total_sampled:
            raise ValueError(
                f"Collected zero (confidence, label) pairs -- all {coverage_gap_count} "
                "sampled file(s) were coverage gaps (unreadable); none reached the pipeline"
            )
        raise ValueError(
            "Collected zero (confidence, label) pairs -- either zero files were sampled "
            "(check --sample-size-per-class and the corpus's held_out split sizes), every "
            f"sampled file's pipeline call failed, or it was a coverage gap "
            f"({coverage_gap_count} of {total_sampled} sampled file(s) were coverage gaps)"
        )

    # Plain (confidence, label) pairs, projected from scored_files --
    # compute_ece/compute_auc_roc/compute_deferral_rate's own inputs and
    # outputs are completely unchanged by carrying file identity upstream.
    pairs = [(sf["calibrated_confidence"], sf["label"]) for sf in scored_files]
    ece_result = compute_ece(pairs)
    auc_roc = compute_auc_roc(pairs)
    deferral_rate = compute_deferral_rate(
        [sf["calibrated_confidence"] for sf in scored_files], deferral_band
    )

    if results_path is not None:
        # [Review][Patch] Guarded, not left to propagate -- this write is
        # purely additive/diagnostic and happens AFTER ece_result/auc_roc/
        # deferral_rate are already computed from real, paid pipeline calls.
        # An unguarded OSError here (full disk, locked file, permissions)
        # previously aborted the whole run uncaught, discarding an
        # already-computed report main() never got the chance to print.
        try:
            write_per_file_results(scored_files, results_path)
        except OSError as e:
            print(
                f"WARNING: failed to write per-file results to {results_path}: {e} -- "
                "continuing without it (the aggregate report below is unaffected)",
                file=sys.stderr,
            )

    # [Review] compute_ece's zero-conclusive-data fallback (ece=0.0) is a
    # divide-by-zero degradation, not a real measurement -- if every bin
    # ended up with fewer than _MIN_SAMPLES_PER_ECE_BIN samples (trivially
    # reachable with a small --sample-size-per-class), that 0.0 must never
    # be trusted as "perfect calibration" by the release gate.
    has_conclusive_ece_data = any(not b["inconclusive"] for b in ece_result["bins"])

    gate_met: bool | None
    if is_identity_placeholder:
        gate_met = None
    else:
        gate_met = (
            has_conclusive_ece_data
            and ece_result["ece"] <= _PROVISIONAL_ECE_THRESHOLD
            and auc_roc >= MIN_AUC_FOR_NON_FLAT
        )

    return EvaluationReport(
        sample_count=len(pairs),
        ece_result=ece_result,
        auc_roc=auc_roc,
        deferral_rate=deferral_rate,
        is_identity_placeholder=is_identity_placeholder,
        gate_met=gate_met,
        coverage_gap_count=coverage_gap_count,
    )


def _print_report(report: EvaluationReport) -> None:
    print()
    print("=== Evaluation Harness Report ===")
    print(f"Sample count: {report['sample_count']}")
    # [Story 6.1, AC7] Same "analyzed N of N+M" form collect_pairs already
    # printed as it ran; repeated here in the final summary block so it
    # isn't scrolled past in a long run's stderr output.
    analyzed = report["sample_count"]
    print(
        f"Coverage: analyzed {analyzed} of {analyzed + report['coverage_gap_count']} "
        f"({report['coverage_gap_count']} coverage gap(s) excluded from ECE/AUC-ROC)"
    )
    print()
    print(f"ECE (10-bin): {report['ece_result']['ece']:.4f}")
    for b in report["ece_result"]["bins"]:
        flag = " [INCONCLUSIVE]" if b["inconclusive"] else ""
        print(
            f"  bin {b['bin_range']}: n={b['count']} avg_conf={b['avg_confidence']:.3f} "
            f"actual_pos={b['actual_positive_fraction']:.3f}{flag}"
        )
    if report["ece_result"]["excluded_sample_count"]:
        print(
            f"  ({report['ece_result']['excluded_sample_count']} sample(s) excluded from "
            "ECE -- inconclusive bins)"
        )
    if report["ece_result"]["bins"] and not any(
        not b["inconclusive"] for b in report["ece_result"]["bins"]
    ):
        print(
            "  NOTE: every bin is inconclusive (too few samples per bin) -- ECE=0.0 above is "
            "a fallback, NOT a real measurement, and cannot contribute to a MET gate."
        )
    print()
    print(f"AUC-ROC: {report['auc_roc']:.4f}")
    print()
    print(f"Deferral rate: {report['deferral_rate']:.4f}")
    print()
    if report["is_identity_placeholder"]:
        print(
            "Release gate: N/A (MEANINGLESS -- evaluated against the identity placeholder, "
            "not a real fit; see warning above)"
        )
    elif report["gate_met"]:
        print("Release gate: MET")
    else:
        print("Release gate: NOT MET")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--corpus-path",
        default=None,
        help="path to the eval corpus root (default: EVAL_CORPUS_PATH if set, else 'benign_corpus_raw')",
    )
    parser.add_argument(
        "--sample-size-per-class",
        type=int,
        default=_DEFAULT_SAMPLE_SIZE_PER_CLASS,
        help=(
            "files sampled from EACH class's held_out split (default: "
            f"{_DEFAULT_SAMPLE_SIZE_PER_CLASS})"
        ),
    )
    parser.add_argument(
        "--cache-ttl-seconds",
        type=float,
        default=_DEFAULT_CACHE_TTL_SECONDS,
        help=(
            "how long a cached Cipher lookup stays valid, shared with "
            f"fit_real_calibration_model.py (default: {_DEFAULT_CACHE_TTL_SECONDS:.0f}s / 24h)"
        ),
    )
    parser.add_argument(
        "--api-call-ceiling",
        type=int,
        default=None,
        help="combined Watchman+Cipher external API call ceiling per window (default: disabled)",
    )
    parser.add_argument(
        "--api-ceiling-window-hours",
        type=float,
        default=_DEFAULT_API_CEILING_WINDOW_HOURS,
        help=f"rolling window in hours --api-call-ceiling applies to (default: {_DEFAULT_API_CEILING_WINDOW_HOURS})",
    )
    args = parser.parse_args()

    # Story 4.2: the lock is acquired as the first real action -- before
    # load_config, before load_corpus, before load_calibration_model, before
    # anything else -- keyed by _CALIBRATION_MODEL_PATH. This script only
    # ever READS that file (never writes it), but the lock must still fire:
    # the 2026-07-30 incident this closes was two concurrent invocations of
    # this exact read-only script, burning real API spend redundantly.
    try:
        with acquire_run_lock(_CALIBRATION_MODEL_PATH):
            config = load_config()
            corpus_path = args.corpus_path or _default_corpus_path(config)
            corpus = load_corpus(corpus_path)
            print_sample_size_cost_warning(
                args.sample_size_per_class,
                _DEFAULT_SAMPLE_SIZE_PER_CLASS,
                {
                    "benign_held_out": len(corpus["benign_held_out"]),
                    "malicious_held_out": len(corpus["malicious_held_out"]),
                },
            )
            calibration_model = load_calibration_model(_CALIBRATION_MODEL_PATH)
            cache = LookupCache(_STATE_DB_PATH, ttl_seconds=args.cache_ttl_seconds)
            budget = ApiCallBudget(
                _STATE_DB_PATH,
                ceiling=args.api_call_ceiling,
                window_seconds=args.api_ceiling_window_hours * 3600,
            )
            watchman: SentinelAgent = WatchmanAgent(config, temperature=0, budget=budget)
            cipher: SentinelAgent = CipherAgent(config, cache=cache, budget=budget)

            report = run(
                corpus,
                calibration_model,
                args.sample_size_per_class,
                config.deferral_threshold,
                watchman,
                cipher,
                results_path=_RESULTS_PATH,
            )
    except LockAlreadyHeldError as e:
        print(str(e), file=sys.stderr)
        sys.exit(4)
    except (ValueError, ApiCallBudgetExceededError) as e:
        print(str(e), file=sys.stderr)
        # [Review] Exit code 3, NOT 1 -- distinct from "measured, gate
        # genuinely not met" (see the EXIT CODES docstring above). This
        # branch fires when run() raised before ever RETURNING A REPORT
        # (invalid corpus, bad deferral_band, zero collected pairs, or a
        # budget-ceiling abort mid-run, Story 4.2). [Review][Patch] Fixed
        # self-contradictory phrasing (code review 2026-08-03): a
        # budget-ceiling abort "mid-run" means some files WERE scored before
        # the abort -- what's true is that no REPORT was ever produced or
        # printed (run() aborts before aggregating/returning one), not that
        # zero measurement occurred. Either way this must not be conflated
        # with a real quality failure -- an automated caller checking only
        # the exit code needs to be able to tell "infra/setup problem" apart
        # from "the model's calibration regressed."
        sys.exit(3)

    _print_report(report)

    if report["is_identity_placeholder"]:
        sys.exit(2)
    sys.exit(0 if report["gate_met"] else 1)


if __name__ == "__main__":
    main()
