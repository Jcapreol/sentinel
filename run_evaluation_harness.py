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


def _score_one_file(
    corpus_file: CorpusFile, watchman: SentinelAgent, cipher: SentinelAgent, deferral_band: float
) -> float | None:
    """Runs one file through the pipeline, returning its calibrated_confidence,
    or None on any failure EXCEPT ApiCallBudgetExceededError, which
    propagates uncaught to abort the whole run instead (Story 4.2, AC3 --
    see the dedicated except clause below). [Review][Patch] This docstring
    previously claimed "None on any failure" unconditionally, which was
    stale even at the time it was written -- the ApiCallBudgetExceededError
    carve-out already existed a few lines down (code review 2026-08-03).
    Otherwise identical per-file failure-isolation discipline to
    fit_real_calibration_model.py's (post-code-review) _score_one_file: both
    extraction calls AND the pipeline call are guarded, not just the
    pipeline call.

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
        print(f"  WARNING: failed to read {corpus_file['path']}: {e} -- skipping", file=sys.stderr)
        return None

    try:
        auth_header = extract_auth_results_header_from_eml(raw_bytes)
        email_content = extract_email_content(raw_bytes)
        evidence, raw_score = gather_evidence_and_raw_score(
            auth_header, email_content, watchman, cipher
        )
        if check_structural_deferral(evidence, raw_score, deferral_band):
            return 0.5
        # [Review] apply_calibration is now inside this try too -- it only
        # raises for an unrecognized `method` (a hand-edited/corrupted
        # calibration_model_v1.json), but this function's own docstring
        # promises "None on any failure" unconditionally.
        return apply_calibration(raw_score)
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
        return None


def collect_pairs(
    sampled_benign: list[CorpusFile],
    sampled_malicious: list[CorpusFile],
    watchman: SentinelAgent,
    cipher: SentinelAgent,
    deferral_band: float = 0.0,
) -> list[tuple[float, float]]:
    """Runs the triage pipeline against each sampled file, pairing its
    calibrated_confidence with its class label (0.0 benign, 1.0 malicious).
    Only ever called with *_held_out lists -- see this file's module
    docstring.

    [Fix] deferral_band defaults to 0.0 (only the all-neutral structural
    gate applies; the conflicting-but-uncertain gate never fires) rather
    than being required, so existing direct callers of this function that
    don't care about the deferral band keep working unchanged -- run()
    always passes its own validated deferral_band explicitly."""
    targets: list[tuple[CorpusFile, float]] = [(f, 0.0) for f in sampled_benign] + [
        (f, 1.0) for f in sampled_malicious
    ]
    total = len(targets)
    pairs: list[tuple[float, float]] = []
    benign_collected = 0
    malicious_collected = 0
    for index, (corpus_file, label) in enumerate(targets, start=1):
        print(
            f"[{index}/{total}] processing {corpus_file['content_hash'][:12]}...",
            file=sys.stderr,
        )
        calibrated_confidence = _score_one_file(corpus_file, watchman, cipher, deferral_band)
        if calibrated_confidence is not None:
            pairs.append((calibrated_confidence, label))
            if label == 0.0:
                benign_collected += 1
            else:
                malicious_collected += 1
    print(f"Collected {len(pairs)} pairs ({total - len(pairs)} skipped)", file=sys.stderr)

    # [Review] Without this, a total dropout of one class's samples (e.g. a
    # systemic extraction issue affecting only that class's file encoding)
    # is silently indistinguishable in the final report from genuinely poor
    # discrimination -- both just show a low/degenerate AUC-ROC with no
    # explanation of the actual root cause.
    if sampled_benign and benign_collected == 0:
        print(
            "WARNING: zero benign pairs collected -- every sampled benign file's pipeline "
            "call failed. AUC-ROC/ECE below reflect malicious-only data, not a real "
            "discrimination measurement.",
            file=sys.stderr,
        )
    if sampled_malicious and malicious_collected == 0:
        print(
            "WARNING: zero malicious pairs collected -- every sampled malicious file's "
            "pipeline call failed. AUC-ROC/ECE below reflect benign-only data, not a real "
            "discrimination measurement.",
            file=sys.stderr,
        )
    return pairs


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


def run(
    corpus: Corpus,
    calibration_model: CalibrationModel,
    sample_size_per_class: int | None,
    deferral_band: float,
    watchman: SentinelAgent,
    cipher: SentinelAgent,
) -> EvaluationReport:
    """Orchestrates validate -> identity-check -> sample -> collect pairs ->
    measure. Raises ValueError (never measures against unvalidated data, or
    against zero collected pairs) if the corpus fails validate_corpus or
    every sampled file's pipeline call fails.

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

    pairs = collect_pairs(sampled_benign, sampled_malicious, watchman, cipher, deferral_band)
    if not pairs:
        raise ValueError(
            "Collected zero (confidence, label) pairs -- either zero files were sampled "
            "(check --sample-size-per-class and the corpus's held_out split sizes) or every "
            "sampled file's pipeline call failed"
        )

    ece_result = compute_ece(pairs)
    auc_roc = compute_auc_roc(pairs)
    deferral_rate = compute_deferral_rate([confidence for confidence, _label in pairs], deferral_band)

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
    )


def _print_report(report: EvaluationReport) -> None:
    print()
    print("=== Evaluation Harness Report ===")
    print(f"Sample count: {report['sample_count']}")
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
