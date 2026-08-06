"""
Run Sentinel's triage pipeline against a sample of the real eval corpus's
`tuning` split and fit a real calibration mapping, replacing the identity
placeholder `calibration_model_v1.json` ships with today.

WHY THIS EXISTS
----------------
Story 3.2 built the calibration-fitting MECHANISM (isotonic regression /
Platt scaling, `triage/eval.py`) but shipped an explicit `"identity"`
placeholder artifact, because Story 3.1's real corpus (`benign_corpus_raw/`)
had zero malicious samples at the time -- `validate_corpus` returned
`is_valid=False`, and AC1's "fit against a validated corpus" precondition
could not be satisfied. That corpus is now complete (a `phishing_pot`
honeypot dataset was organized into `benign_corpus_raw/malicious/`), so a
real fit is now possible. This script is that real fit's orchestration --
see Story 3.3 (`triage-3-3-fit-real-calibration-model-against-corpus`).

COST WARNING -- READ BEFORE RUNNING
-------------------------------------
Each sampled file is run through the FULL triage pipeline: a real Watchman
(Anthropic LLM) call and a real Cipher (VirusTotal/AbuseIPDB/URLhaus)
lookup. This is NOT free or instant. `--sample-size-per-class` (default
200) bounds the cost -- 200 benign + 200 malicious = 400 real pipeline
runs. The full corpus (813 benign tuning, 6916 malicious tuning) would mean
thousands of real API calls and likely hours of wall-clock time given rate
limits. Use `--dry-run` first to sanity-check without overwriting the
committed `calibration_model_v1.json`.

WHAT THIS SCRIPT NEVER TOUCHES
--------------------------------
The corpus's `held_out` split (`benign_held_out`/`malicious_held_out`) is
never referenced anywhere in this file. It must remain completely unseen by
calibration fitting -- reserved for a future evaluation harness (Story 3.4)
to measure against honestly. Only `benign_tuning`/`malicious_tuning` are
ever sampled.

USAGE
-----
    python fit_real_calibration_model.py --dry-run
    python fit_real_calibration_model.py --sample-size-per-class 200

Run with --help for all options.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinel.cipher import CipherAgent
from sentinel.config import Config
from sentinel.config import load as load_config
from sentinel.triage.eval import (
    CalibrationModel,
    Corpus,
    CorpusFile,
    fit_calibration_mapping,
    load_corpus,
    sample_corpus_files,
    save_calibration_model,
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
from sentinel.triage.worker import gather_evidence_and_raw_score
from sentinel.verdict import SentinelAgent
from sentinel.watchman import WatchmanAgent

_DEFAULT_SAMPLE_SIZE_PER_CLASS = 200
# [Review][Patch] Shared with run_evaluation_harness.py via script_guard.py --
# previously duplicated verbatim in both scripts (code review 2026-08-03).
_DEFAULT_CACHE_TTL_SECONDS = DEFAULT_CACHE_TTL_SECONDS
_DEFAULT_API_CEILING_WINDOW_HOURS = DEFAULT_API_CEILING_WINDOW_HOURS
# [Review][Patch] Absolute, anchored at this script's own location -- not a
# bare relative "calibration_model_v1.json", which only resolves to repo
# root when invoked from the repo root. Mirrors scoring.py's
# _CALIBRATION_MODEL_PATH pattern (this script lives directly at repo root,
# so no parents[] climb is needed here). A CWD-dependent default is a real
# footgun for the eventual real, consequential, cost-incurring run this
# script exists for -- accidentally writing to (or reading a stale summary
# from) the wrong location should not be possible by default.
_DEFAULT_OUTPUT_PATH = str(Path(__file__).resolve().parent / "calibration_model_v1.json")
# Story 4.2: shared Cipher-lookup-cache + API-call-budget state, same
# absolute-path-anchored-at-this-script's-own-location reasoning as
# _DEFAULT_OUTPUT_PATH. Shared with run_evaluation_harness.py -- both real-
# corpus scripts benefit from the same cache across separate invocations.
_STATE_DB_PATH = str(Path(__file__).resolve().parent / ".sentinel_script_state.db")


def _default_corpus_path(config: Config) -> str:
    # Matches how benign_corpus_raw/ has actually been used throughout
    # Stories 3.1/3.2's manual verification -- EVAL_CORPUS_PATH has never
    # actually been set in this project's .env, despite being wired up.
    return config.eval_corpus_path or "benign_corpus_raw"


def _score_one_file(
    corpus_file: CorpusFile, watchman: SentinelAgent, cipher: SentinelAgent
) -> float | None:
    """Runs one file through the pipeline, returning its raw_score, or None
    on any failure (skip, don't abort the whole run -- matches
    process_message's own Watchman/Cipher crash handling and
    run_poll_cycle's per-message isolation precedent)."""
    try:
        raw_bytes = Path(corpus_file["path"]).read_bytes()
    except OSError as e:
        print(f"  WARNING: failed to read {corpus_file['path']}: {e} -- skipping", file=sys.stderr)
        return None

    # [Review][Patch] extract_auth_results_header_from_eml/extract_email_content
    # are now inside this try too, not just gather_evidence_and_raw_score --
    # this function's own docstring promises "None on any failure", and both
    # extraction calls were previously unguarded. Currently non-exploitable
    # only because those two functions independently document themselves as
    # "never raises" (ingest.py), which made the old code accidentally safe
    # rather than structurally safe -- inconsistent with this exact
    # codebase's own established discipline of not trusting even documented
    # "never raises" contracts at a per-item processing boundary (see
    # gather_evidence_and_raw_score's own docstring on the SentinelAgent
    # Protocol). A single malformed file must never abort a run that may
    # already represent hours of real, paid API calls on prior files.
    try:
        auth_header = extract_auth_results_header_from_eml(raw_bytes)
        email_content = extract_email_content(raw_bytes)
        _evidence, raw_score = gather_evidence_and_raw_score(
            auth_header, email_content, watchman, cipher
        )
    except ApiCallBudgetExceededError:
        # Story 4.2: must propagate uncaught, never treated as "this one
        # file failed, skip it and keep going" -- a budget-exceeded run
        # aborts entirely (AC3), it does not silently continue past the
        # configured ceiling one file at a time.
        raise
    except Exception as e:
        print(
            f"  WARNING: pipeline failed for {corpus_file['path']}: "
            f"{type(e).__name__}: {e} -- skipping",
            file=sys.stderr,
        )
        return None

    return raw_score


def collect_pairs(
    sampled_benign: list[CorpusFile],
    sampled_malicious: list[CorpusFile],
    watchman: SentinelAgent,
    cipher: SentinelAgent,
) -> list[tuple[float, float]]:
    """Runs the triage pipeline against each sampled file, pairing its
    raw_score with its class label (0.0 benign, 1.0 malicious). Only ever
    called with *_tuning lists -- see this file's module docstring."""
    targets: list[tuple[CorpusFile, float]] = [(f, 0.0) for f in sampled_benign] + [
        (f, 1.0) for f in sampled_malicious
    ]
    total = len(targets)
    pairs: list[tuple[float, float]] = []
    for index, (corpus_file, label) in enumerate(targets, start=1):
        print(
            f"[{index}/{total}] processing {corpus_file['content_hash'][:12]}...",
            file=sys.stderr,
        )
        raw_score = _score_one_file(corpus_file, watchman, cipher)
        if raw_score is not None:
            pairs.append((raw_score, label))
    print(f"Collected {len(pairs)} pairs ({total - len(pairs)} skipped)", file=sys.stderr)
    return pairs


def run(
    corpus: Corpus,
    sample_size_per_class: int | None,
    watchman: SentinelAgent,
    cipher: SentinelAgent,
) -> CalibrationModel:
    """Orchestrates validate -> sample -> collect pairs -> fit. Raises
    ValueError (never fits against unvalidated data) if the corpus fails
    validate_corpus."""
    validation = validate_corpus(corpus)
    if not validation["is_valid"]:
        reasons = "\n".join(f"  - {r}" for r in validation["reasons"])
        raise ValueError(f"Corpus failed validation, refusing to fit:\n{reasons}")

    sampled_benign = sample_corpus_files(corpus["benign_tuning"], sample_size_per_class)
    sampled_malicious = sample_corpus_files(corpus["malicious_tuning"], sample_size_per_class)
    print(
        f"Sampled {len(sampled_benign)} benign, {len(sampled_malicious)} malicious "
        "tuning files (held_out never touched)",
        file=sys.stderr,
    )

    pairs = collect_pairs(sampled_benign, sampled_malicious, watchman, cipher)
    return fit_calibration_mapping(pairs)


def _print_summary(model: CalibrationModel) -> None:
    print()
    print("=== Fit complete ===")
    print(f"Method: {model['method']}")
    print(f"Sample count: {model['sample_count']}")
    if model["method"] == "isotonic":
        breakpoints = model["isotonic_breakpoints"] or []
        print(f"Isotonic breakpoints: {len(breakpoints)}")
    elif model["method"] == "platt":
        print(f"Platt params: {model['platt_params']}")
    print(
        f"deferral_threshold_derived: {model['deferral_threshold_derived']} -- NOTE: this is "
        "still the Story 3.2 pass-through default, NOT derived from a real precision/recall "
        "sweep. A real derivation requires evaluation-harness machinery (FR15), out of this "
        "script's scope -- see Story 3.4."
    )


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
            "files sampled from EACH class's tuning split (default: "
            f"{_DEFAULT_SAMPLE_SIZE_PER_CLASS}); note fit_calibration_mapping's isotonic-vs-Platt "
            "threshold is on TOTAL pairs across both classes combined, not per-class"
        ),
    )
    parser.add_argument(
        "--output",
        default=_DEFAULT_OUTPUT_PATH,
        help=f"where to write the fitted model (default: {_DEFAULT_OUTPUT_PATH})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="run the full pipeline and print the fitted model's summary, but do not write --output",
    )
    parser.add_argument(
        "--cache-ttl-seconds",
        type=float,
        default=_DEFAULT_CACHE_TTL_SECONDS,
        help=(
            "how long a cached Cipher lookup stays valid, shared with "
            f"run_evaluation_harness.py (default: {_DEFAULT_CACHE_TTL_SECONDS:.0f}s / 24h)"
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

    # [Review][Patch] Resolved ONCE, up front -- used for both the lock key
    # and the eventual write. Previously the lock was keyed on the raw,
    # unresolved args.output CLI string, so two invocations targeting the
    # same real file via different path spellings (relative vs absolute, a
    # "./x" vs "x") would compute different lock file names and both
    # succeed, defeating Design Decision 2's "resolved path" requirement
    # (code review 2026-08-03).
    resolved_output = str(Path(args.output).resolve())

    # Story 4.2: the lock is acquired as the first real action -- before
    # load_config, before load_corpus, before anything else -- keyed by
    # resolved_output (the resource this script writes). Not just a write
    # guard: it also protects against a second concurrent invocation
    # burning real API spend redundantly, the harm AC1 names first.
    #
    # [Review][Patch] save_calibration_model now runs INSIDE this lock
    # (below) -- previously it ran after the `with` block had already
    # exited, so the actual file write this lock exists to protect wasn't
    # covered by it at all, defeating the lock's purpose for the one
    # operation that matters most (code review 2026-08-03).
    try:
        with acquire_run_lock(resolved_output):
            config = load_config()
            corpus_path = args.corpus_path or _default_corpus_path(config)
            corpus = load_corpus(corpus_path)
            print_sample_size_cost_warning(
                args.sample_size_per_class,
                _DEFAULT_SAMPLE_SIZE_PER_CLASS,
                {
                    "benign_tuning": len(corpus["benign_tuning"]),
                    "malicious_tuning": len(corpus["malicious_tuning"]),
                },
            )
            cache = LookupCache(_STATE_DB_PATH, ttl_seconds=args.cache_ttl_seconds)
            budget = ApiCallBudget(
                _STATE_DB_PATH,
                ceiling=args.api_call_ceiling,
                window_seconds=args.api_ceiling_window_hours * 3600,
            )
            watchman: SentinelAgent = WatchmanAgent(config, temperature=0, budget=budget)
            cipher: SentinelAgent = CipherAgent(config, cache=cache, budget=budget)

            model = run(corpus, args.sample_size_per_class, watchman, cipher)

            if not args.dry_run:
                save_calibration_model(model, resolved_output)
    except (ValueError, LockAlreadyHeldError, ApiCallBudgetExceededError) as e:
        # Reuses this script's one existing failure code (1) for all three --
        # "could not run the pipeline at all," the same class as an invalid
        # corpus. Each exception's own message stays distinct even though
        # the exit code is shared.
        print(str(e), file=sys.stderr)
        sys.exit(1)

    _print_summary(model)

    if args.dry_run:
        print()
        print(f"--dry-run: NOT writing to {resolved_output}")
        return

    print()
    print(f"Written to {resolved_output}")


if __name__ == "__main__":
    main()
