"""Evaluation corpus sourcing & validation (Story 3.1).

Corpus format: a root directory (config.Config.eval_corpus_path /
EVAL_CORPUS_PATH) with `benign/` and `malicious/` subdirectories, each
containing `tuning/` and `held_out/` subdirectories of raw .eml files, plus a
`PROVENANCE.md` documenting sourcing methodology:

    EVAL_CORPUS_PATH/
      benign/
        PROVENANCE.md
        tuning/*.eml
        held_out/*.eml
      malicious/
        PROVENANCE.md
        tuning/*.eml
        held_out/*.eml

Filenames are not semantically meaningful -- only file content and directory
location (class, split) matter. Overlap between `tuning`/`held_out` is
detected by SHA-256 content hash (matching triage/ingest.py's
extract_sender_and_content_hash precedent), not filename.

IMPORTANT for anyone writing a corpus-population script (harvest_own_inbox.py,
harvest_benign_corpus.py, or any future one): `load_corpus` reads files ONLY
from `<root>/<class>/tuning/*.eml` and `<root>/<class>/held_out/*.eml` -- NEVER
from `<root>/<class>/*.eml` directly. A script that writes flat files straight
into the class directory (skipping the tuning/held_out split) produces a
corpus `load_corpus` sees as completely empty for that class, which
`validate_corpus` then rejects with "No <class> samples found" -- a confusing
result if you don't already know files must be one directory level deeper
than the class name suggests. This happened once already during Story 3.1
(see the story file's pre-review follow-up notes) -- if you're about to write
a new harvesting/sourcing script, assign each file to `tuning/` or
`held_out/` yourself (a deterministic split by content hash is the
established pattern -- see harvest_own_inbox.py's `_split_for`), don't leave
it for a human to sort out later.

Standalone-runnable, independent of live Gmail ingestion: reads only from
local disk, never touches the network. The corpus itself is never committed
to the repository (AR12) -- referenced only via EVAL_CORPUS_PATH.
"""

import hashlib
import json
import math
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypedDict

from sentinel.triage.ingest import extract_email_content

_CLASSES = ("benign", "malicious")
_SPLITS = ("tuning", "held_out")

# PROVISIONAL, not calibrated values -- placeholders pending a real corpus of
# known size. Revisit once real sourcing (a future, separate task) determines
# what's actually achievable.
_MIN_SAMPLES_PER_CLASS = 30
_MIN_PROVENANCE_LENGTH = 50  # characters
_MIN_BENIGN_DIVERSITY_FRACTION = 0.10

# PROVISIONAL, not exhaustive -- a representative (not complete) sample of the
# urgency/financial/account-action language and marketing-style phrasing that
# makes legitimate mail resemble phishing surface patterns, per the PRD's own
# framing (prd-phishing-triage.md: "realistic false-positive-prone traffic
# (legitimate marketing/transactional mail resembling phishing patterns)").
# This is deliberately a CONTENT-level heuristic (Subject + body text, via
# extract_email_content), not a header-level one -- investigate_header_
# authentication's SPF/DKIM/DMARC check measures a different property
# (authentication-header ambiguity), which is not what FR31 is asking for
# here. Revisit/expand this list once real corpus sourcing surfaces what
# false-positive-prone traffic actually looks like in practice.
_PHISHING_ADJACENT_PATTERN = re.compile(
    r"\b("
    r"verify your account|urgent action|act now|account (?:has been |will be )?suspended|"
    r"click here|confirm your (?:identity|account|password|payment)|update your payment|"
    r"limited time|unusual activity|security alert|password will expire|"
    r"unsubscribe|special offer|order confirmation|your (?:invoice|receipt|statement)|"
    r"shipping (?:confirmation|notification)|payment (?:failed|declined|due)"
    r")\b",
    re.IGNORECASE,
)


class CorpusFile(TypedDict):
    path: str
    content_hash: str


class Corpus(TypedDict):
    root: str
    benign_tuning: list[CorpusFile]
    benign_held_out: list[CorpusFile]
    malicious_tuning: list[CorpusFile]
    malicious_held_out: list[CorpusFile]


class CorpusValidationResult(TypedDict):
    is_valid: bool
    reasons: list[str]


def _load_one(split_dir: Path) -> list[CorpusFile]:
    if not split_dir.is_dir():
        return []
    try:
        candidates = sorted(split_dir.iterdir())
    except OSError:
        # Matches load_corpus's documented "never raises" contract -- a
        # directory-listing failure (e.g. PermissionError, a subclass of
        # OSError) degrades to "no files found here" rather than propagating.
        return []
    files: list[CorpusFile] = []
    for path in candidates:
        # .suffix.lower() rather than glob("*.eml") -- glob's case-sensitivity
        # is filesystem-dependent (case-insensitive on Windows, case-sensitive
        # on the realistic Linux CI/prod target); matching explicitly here
        # makes the case-insensitivity a deliberate guarantee, not an
        # accident of whichever OS happens to run this.
        if not path.is_file() or path.suffix.lower() != ".eml":
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        files.append(CorpusFile(path=str(path), content_hash=hashlib.sha256(raw).hexdigest()))
    return files


def _load_split(class_dir: Path) -> tuple[list[CorpusFile], list[CorpusFile]]:
    return _load_one(class_dir / _SPLITS[0]), _load_one(class_dir / _SPLITS[1])


def load_corpus(corpus_path: str) -> Corpus:
    """Never raises -- a missing/malformed directory structure produces empty
    file lists for the affected class/split, with rejection happening in
    validate_corpus (a structurally incomplete corpus and a genuinely broken
    path both become specific validation reasons, not a raw traceback)."""
    root = Path(corpus_path)
    benign_tuning, benign_held_out = _load_split(root / "benign")
    malicious_tuning, malicious_held_out = _load_split(root / "malicious")
    return Corpus(
        root=str(root),
        benign_tuning=benign_tuning,
        benign_held_out=benign_held_out,
        malicious_tuning=malicious_tuning,
        malicious_held_out=malicious_held_out,
    )


def sample_corpus_files(
    files: list[CorpusFile], sample_size: int | None
) -> list[CorpusFile]:
    """Deterministic selection by ascending content_hash -- NOT random.sample,
    which would need a seed to be reproducible and adds seed-management
    discipline this project hasn't needed elsewhere. Re-running with the same
    sample_size against the same files always selects the same subset,
    regardless of the input list's order (Story 3.3's `fit_real_calibration_
    model.py` relies on this for a cost-bounded, reproducible-in-*which-
    files-get-sampled* real-corpus fitting run -- NOT a guarantee that the
    resulting fitted CalibrationModel is reproducible: WatchmanAgent's LLM
    call has no temperature pinned, so two runs over the identical sampled
    files can still produce different evidence/raw_scores and therefore a
    different fit).

    Generic over any list[CorpusFile] -- deliberately has no awareness of
    tuning/held_out. Callers are responsible for only ever passing a
    corpus's *_tuning lists here: `held_out` must remain completely unseen
    by calibration fitting (reserved for a future evaluation harness), and
    that guarantee has to be structural at the call site, not enforced
    inside this generic sampling function.

    [Review][Patch] Rejects a negative sample_size (ValueError) rather than
    silently falling through to Python's slice semantics, where e.g.
    `sorted(files, ...)[:-1]` means "all but the last element" -- the
    opposite of what a negative "how many files to sample" input should
    ever produce, and directly reachable via `fit_real_calibration_model.py`'s
    --sample-size-per-class CLI flag with no other validation anywhere."""
    if sample_size is not None and sample_size < 0:
        raise ValueError(f"sample_size must be non-negative or None, got {sample_size!r}")
    sorted_files = sorted(files, key=lambda f: f["content_hash"])
    if sample_size is None or sample_size >= len(files):
        return sorted_files
    return sorted_files[:sample_size]


def _check_class_presence(corpus: Corpus, reasons: list[str]) -> None:
    """Counts unique content, not raw file count -- N copies of the identical
    file (duplicate harvesting, a harvest-script retry bug) must not satisfy
    the minimum-sample-count bar without providing any real diversity."""
    for class_name in _CLASSES:
        all_files = corpus[f"{class_name}_tuning"] + corpus[f"{class_name}_held_out"]  # type: ignore[literal-required]
        unique_count = len({f["content_hash"] for f in all_files})
        if unique_count == 0:
            reasons.append(f"No {class_name} samples found")
        elif unique_count < _MIN_SAMPLES_PER_CLASS:
            reasons.append(
                f"Only {unique_count} unique {class_name} samples found, "
                f"minimum {_MIN_SAMPLES_PER_CLASS} required"
            )


def _check_split_integrity(corpus: Corpus, reasons: list[str]) -> None:
    """Known limitation, accepted for MVP (tracked in deferred-work.md): this
    detects exact-duplicate content only (SHA-256 hash equality), not
    near-duplicates -- e.g. two issues of the same newsletter template with a
    different date/tracking-ID substring would hash differently and pass
    undetected, even though they're not meaningfully independent samples for
    calibration purposes. A real fix (fuzzy/near-duplicate hashing, e.g.
    simhash or MinHash) is out of scope for a corpus-validation MVP and would
    add a new dependency this project doesn't otherwise need."""
    for class_name in _CLASSES:
        tuning = corpus[f"{class_name}_tuning"]  # type: ignore[literal-required]
        held_out = corpus[f"{class_name}_held_out"]  # type: ignore[literal-required]
        if tuning and not held_out:
            reasons.append(f"{class_name}: held_out split is empty (tuning has {len(tuning)} samples)")
        elif held_out and not tuning:
            reasons.append(f"{class_name}: tuning split is empty (held_out has {len(held_out)} samples)")

    # Global tuning-vs-held-out overlap, across ALL classes combined -- not
    # just within one class. AC2 requires zero overlap against "anything
    # reserved for calibration tuning," which a same-class-only check misses:
    # a file mistakenly present in one class's tuning split and a DIFFERENT
    # class's held_out split (e.g. a mislabeling error) is arguably worse
    # contamination than same-class duplication, since a calibration mapping
    # would "see" that exact content during tuning under a different label
    # than it's evaluated under during held-out measurement.
    all_tuning_hashes = {f["content_hash"] for f in corpus["benign_tuning"] + corpus["malicious_tuning"]}
    all_held_out_hashes = {f["content_hash"] for f in corpus["benign_held_out"] + corpus["malicious_held_out"]}
    overlap = all_tuning_hashes & all_held_out_hashes
    if overlap:
        reasons.append(
            f"{len(overlap)} file(s) with identical content appear in a tuning split and a "
            "held_out split (possibly across different classes) -- zero overlap required "
            "between anything reserved for calibration tuning and the held-out evaluation set"
        )

    # [Review][Patch] Same-split cross-class overlap: identical content
    # present in BOTH classes' tuning (or both classes' held_out) is a
    # contradictory-label case the check above never catches (it only
    # compares tuning-vs-held_out, never tuning-vs-tuning). Undetected, this
    # would feed fit_calibration_mapping (Story 3.2/3.3) the identical
    # raw_score twice with opposite labels (0.0 and 1.0), corrupting the fit
    # -- Story 3.3's fit_real_calibration_model.py is the first code path
    # that actually runs validate_corpus -> fit_calibration_mapping against
    # real, human-sourced corpus data end-to-end, making this exploitable.
    for split_name in _SPLITS:
        benign_hashes = {f["content_hash"] for f in corpus[f"benign_{split_name}"]}  # type: ignore[literal-required]
        malicious_hashes = {f["content_hash"] for f in corpus[f"malicious_{split_name}"]}  # type: ignore[literal-required]
        class_overlap = benign_hashes & malicious_hashes
        if class_overlap:
            reasons.append(
                f"{len(class_overlap)} file(s) with identical content appear in BOTH benign/"
                f"{split_name} and malicious/{split_name} -- contradictory labels for the same "
                "content within the same split, which would corrupt a calibration fit"
            )

    # [Story 4.1] Within-class cross-split overlap: identical content present
    # in a SINGLE class's own tuning AND held_out split. The global
    # tuning-vs-held_out check above already catches this structurally (it
    # unions both classes before comparing), but its message deliberately
    # can't name which class is involved ("possibly across different
    # classes") -- a different diagnostic gap from the same-split cross-class
    # check above (which never compares a class against itself). Found via a
    # real corpus incident: a hash-convention mismatch between an older and a
    # newer harvest_own_inbox.py run left real messages assigned to different
    # splits within the SAME class, only traceable via a manual diagnostic
    # script. This check names the class immediately instead.
    for class_name in _CLASSES:
        class_tuning_hashes = {f["content_hash"] for f in corpus[f"{class_name}_tuning"]}  # type: ignore[literal-required]
        class_held_out_hashes = {f["content_hash"] for f in corpus[f"{class_name}_held_out"]}  # type: ignore[literal-required]
        within_class_overlap = class_tuning_hashes & class_held_out_hashes
        if within_class_overlap:
            reasons.append(
                f"{len(within_class_overlap)} {class_name} file(s) have identical content in "
                f"both {class_name}_tuning and {class_name}_held_out -- zero overlap required "
                "within a single class's own tuning/held_out split"
            )


def _check_provenance(root: Path, reasons: list[str]) -> None:
    for class_name in _CLASSES:
        provenance_path = root / class_name / "PROVENANCE.md"
        if not provenance_path.is_file():
            reasons.append(
                f"Missing {provenance_path} — corpus label trustworthiness must be documented"
            )
            continue
        try:
            text = provenance_path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            text = ""
        if len(text) < _MIN_PROVENANCE_LENGTH:
            reasons.append(
                f"{provenance_path} is too short ({len(text)} chars, minimum "
                f"{_MIN_PROVENANCE_LENGTH}) to document sourcing methodology"
            )


_WHITESPACE_RUN = re.compile(r"\s+")


def _check_benign_diversity(corpus: Corpus, reasons: list[str]) -> None:
    """Content-level check (Subject + body text), not header-level -- see the
    module-level comment above _PHISHING_ADJACENT_PATTERN for why."""
    benign_all = corpus["benign_tuning"] + corpus["benign_held_out"]
    if not benign_all:
        return  # already reported by _check_class_presence
    diverse_count = 0
    readable_count = 0
    for corpus_file in benign_all:
        try:
            raw = Path(corpus_file["path"]).read_bytes()
        except OSError:
            # Excluded from the denominator too, not just the numerator --
            # a handful of transient/permission read failures between
            # load_corpus() and this second, independent read must not push
            # a genuinely-diverse corpus below the threshold for reasons
            # unrelated to actual content diversity.
            continue
        readable_count += 1
        content = extract_email_content(raw)
        # Collapse whitespace runs (line wraps, multiple spaces) before
        # matching -- real plain-text email is routinely line-wrapped, and
        # the pattern's literal single-space multi-word phrases must still
        # match "verify\nyour account" the same as "verify your account".
        normalized_content = _WHITESPACE_RUN.sub(" ", content)
        if _PHISHING_ADJACENT_PATTERN.search(normalized_content):
            diverse_count += 1
    if readable_count == 0:
        return  # nothing readable to assess; a genuine gap, not a diversity failure
    fraction = diverse_count / readable_count
    if fraction < _MIN_BENIGN_DIVERSITY_FRACTION:
        reasons.append(
            f"Only {fraction:.1%} of benign samples resemble phishing-adjacent "
            f"content patterns (urgency/financial/account-action language, "
            f"marketing/transactional phrasing) — minimum {_MIN_BENIGN_DIVERSITY_FRACTION:.0%} "
            "required — benign corpus is only easy negatives, not realistic "
            "false-positive-prone traffic (FR31)"
        )


def validate_corpus(corpus: Corpus) -> CorpusValidationResult:
    """Runs every FR31 check and accumulates every failure -- never returns a
    single reason and stops early, so a maintainer fixing a rejected corpus
    doesn't have to re-run validation once per individual problem. Never
    raises: every check is independently exception-guarded against
    unparseable/unreadable files."""
    reasons: list[str] = []
    _check_class_presence(corpus, reasons)
    _check_split_integrity(corpus, reasons)
    _check_provenance(Path(corpus["root"]), reasons)
    _check_benign_diversity(corpus, reasons)
    return CorpusValidationResult(is_valid=not reasons, reasons=reasons)


# --- Calibration mapping fitting (Story 3.2) ------------------------------------
#
# Pure Python, no new dependency (numpy/scikit-learn) -- matches this
# project's consistent zero-new-dependency discipline across every prior
# story. Isotonic regression is fit via the Pool Adjacent Violators Algorithm
# (PAVA); Platt scaling is fit via simple batch gradient descent on a
# 2-parameter logistic. Both operate on synthetic (raw_score, label) pairs in
# this story's own tests -- fitting against a REAL corpus requires running
# the full triage pipeline (network calls to Watchman/Cipher) against real
# email content, which is both explicitly excluded from CI (architecture
# doc's own stated strategy) and currently impossible anyway (Story 3.1's
# real corpus has zero malicious samples). See triage-3-2's Scope Boundary.


def fit_isotonic_regression(pairs: list[tuple[float, float]]) -> list[tuple[float, float, float]]:
    """Pool Adjacent Violators Algorithm (PAVA). `pairs` are (raw_score, label)
    where label is 0.0 (benign) or 1.0 (malicious). Returns a list of
    (x_min, x_max, calibrated_value) breakpoints describing a monotonically
    non-decreasing step function -- the same algorithm scikit-learn's
    IsotonicRegression uses internally, implemented from scratch here.

    [Review][Patch] Pairs are pre-aggregated by exact raw_score before PAVA
    runs: two pairs sharing the same raw_score but different labels are a
    realistic occurrence (compute_raw_score is a coarse weighted sum over a
    small set of evidence-weight combinations, so distinct emails plausibly
    collapse to the same score), and without this aggregation step PAVA's
    strict '>' merge condition does not guarantee same-x points end up in
    one pooled block -- whether they merge depended on input order, and
    when they didn't merge, apply_isotonic's scan silently returned only
    the first of the two same-x_max blocks, permanently hiding the other
    point's label. Aggregating first makes every x value in the PAVA loop
    unique by construction, so this failure mode cannot occur, and the
    result no longer depends on the caller's input order."""
    if not pairs:
        return []

    grouped: dict[float, list[float]] = {}
    for x, y in pairs:
        grouped.setdefault(x, []).append(y)
    aggregated = sorted(
        ((x, sum(ys), float(len(ys))) for x, ys in grouped.items()), key=lambda t: t[0]
    )

    # Stack of pooled blocks: [sum_y, count, x_min, x_max].
    stack: list[list[float]] = []
    for x, sum_y, count in aggregated:
        stack.append([sum_y, count, x, x])
        while len(stack) > 1 and (stack[-2][0] / stack[-2][1]) > (stack[-1][0] / stack[-1][1]):
            last = stack.pop()
            stack[-1][0] += last[0]
            stack[-1][1] += last[1]
            stack[-1][3] = last[3]

    return [(block[2], block[3], block[0] / block[1]) for block in stack]


def apply_isotonic(raw_score: float, breakpoints: list[tuple[float, float, float]]) -> float:
    """Never raises -- an empty breakpoint list (e.g. fit against zero
    samples) or an out-of-range raw_score both degrade to a defined value
    rather than an exception: the neutral prior for no breakpoints at all,
    clamped to the nearest edge block's value when raw_score falls outside
    every fitted block's range.

    Pooled blocks are not contiguous -- PAVA only records the x range of the
    training points actually pooled into each block, so there are gaps
    between one block's x_max and the next block's x_min wherever no training
    point landed. A raw_score falling in such a gap is resolved to the first
    block whose x_max it does not exceed, i.e. the step function is extended
    leftward from each block up to (and including) its x_max -- this keeps
    the output non-decreasing in raw_score, which an exact x_min<=x<=x_max
    membership test (falling through to the last block on a gap miss) does
    not guarantee."""
    if not breakpoints:
        return 0.5
    for _x_min, x_max, value in breakpoints:
        if raw_score <= x_max:
            return value
    return breakpoints[-1][2]


_EXP_ARG_CLAMP = 500.0  # math.exp overflows well before this; keeps apply_platt exception-free


def fit_platt_scaling(
    pairs: list[tuple[float, float]], iterations: int = 1000, learning_rate: float = 0.1
) -> tuple[float, float]:
    """Fits P(malicious) = 1 / (1 + exp(A * raw_score + B)) via batch gradient
    descent on cross-entropy loss. Standard Platt-scaling sign convention
    (matches scikit-learn's): A is typically NEGATIVE for a
    positively-correlated raw score -- higher raw score should mean higher
    P(malicious), which requires exp(A*x+B) to SHRINK as x grows, i.e. A < 0.
    Getting this sign backwards produces an inversely-correlated, silently
    wrong calibration, not a crash -- see this story's directional-sanity
    tests."""
    if not pairs:
        return 0.0, 0.0
    a, b = 0.0, 0.0
    n = float(len(pairs))
    for _ in range(iterations):
        grad_a = 0.0
        grad_b = 0.0
        for x, y in pairs:
            p = _sigmoid_platt(x, a, b)
            grad_a += (p - y) * x
            grad_b += p - y
        # P = 1/(1+exp(a*x+b)) is a DECREASING function of z=a*x+b, unlike the
        # textbook sigmoid(z)=1/(1+exp(-z)); differentiating cross-entropy loss
        # through that sign flip gives dL/da = (y-p)*x, so the descent step is
        # a -= lr*(-grad_a) = a += lr*grad_a (grad_a accumulated as (p-y)*x
        # above). Using "-=" here would climb the loss instead of descending
        # it, inverting the fitted calibration without raising any error.
        a += learning_rate * grad_a / n
        b += learning_rate * grad_b / n
    return a, b


def _sigmoid_platt(x: float, a: float, b: float) -> float:
    exponent = max(-_EXP_ARG_CLAMP, min(_EXP_ARG_CLAMP, a * x + b))
    return 1.0 / (1.0 + math.exp(exponent))


def apply_platt(raw_score: float, a: float, b: float) -> float:
    """Never raises -- the exponent is clamped before calling math.exp,
    guarding against overflow for extreme A/B/raw_score combinations."""
    return _sigmoid_platt(raw_score, a, b)


# PROVISIONAL, not calibrated -- same "not yet grounded in a real corpus"
# framing as this module's other constants. Below this many (raw_score,
# label) pairs, isotonic regression's step function is prone to overfitting
# noise into spurious breakpoints; Platt scaling's 2-parameter logistic is
# the more stable fallback for small samples, per AC1's literal wording.
_MIN_SAMPLES_FOR_ISOTONIC = 100

_CALIBRATION_MODEL_VERSION = 1


class CalibrationModel(TypedDict):
    version: int
    method: Literal["isotonic", "platt", "identity"]
    fitted_at: str | None
    sample_count: int
    isotonic_breakpoints: list[list[float]] | None
    platt_params: dict[str, float] | None
    deferral_threshold_derived: float
    note: str | None


def fit_calibration_mapping(
    pairs: list[tuple[float, float]], deferral_threshold_derived: float = 0.05
) -> CalibrationModel:
    """Chooses isotonic regression when at least `_MIN_SAMPLES_FOR_ISOTONIC`
    pairs are available, else falls back to Platt scaling -- matching AC1's
    "isotonic regression, with Platt scaling as fallback if the corpus is
    too small." `deferral_threshold_derived` is NOT computed by this
    function from `pairs` -- deriving it for real requires a precision/
    recall sweep against a held-out corpus, out of this story's scope per
    its Scope Boundary -- it is a caller-supplied pass-through value, stored
    on the returned model as-is. [Review][Patch] Previously this was a
    hardcoded 0.05 baked directly into both return branches below, which
    directly contradicted this exact docstring paragraph (which already
    claimed "callers ... are expected to set it explicitly") -- callers had
    no way to actually set it, since it wasn't a parameter. The default of
    0.05 here exists only to match `Config.deferral_threshold`'s own
    pre-existing hardcoded default (see `deferred-work.md`'s manual-sync
    tracking entry), not because 0.05 is derived from `pairs` in any way.

    Deliberately fails loudly (ValueError) rather than degrading gracefully
    when `pairs` is empty or contains only one distinct label: with a single
    label, both fit_isotonic_regression and fit_platt_scaling "succeed"
    without raising, but the result is a degenerate constant function (e.g.
    calibrating every raw_score to "definitely benign" regardless of input)
    -- silently wrong, not a crash, the same failure shape this codebase
    already treats as unacceptable elsewhere (see fit_platt_scaling's own
    sign-convention warning). AC1's precondition is a *validated* corpus
    (both classes present, per Story 3.1's validate_corpus); this function
    operates on plain (score, label) pairs, decoupled from Corpus/
    CorpusValidationResult, so it cannot re-run that validation itself --
    but it can and does refuse the one specific failure mode that would
    otherwise let an unvalidated, single-class corpus silently overwrite a
    safe placeholder with an actively harmful calibration."""
    if not pairs:
        raise ValueError("cannot fit a calibration mapping against zero (raw_score, label) pairs")
    labels = {label for _, label in pairs}
    if labels != {0.0, 1.0}:
        raise ValueError(
            f"cannot fit a calibration mapping: labels must be exactly {{0.0, 1.0}} "
            f"(benign, malicious), got {labels!r} -- a real corpus must include both "
            "outcomes, or the fit degrades to a trivial constant function that silently "
            "miscalibrates every future score"
        )
    fitted_at = datetime.now(timezone.utc).isoformat()
    if len(pairs) >= _MIN_SAMPLES_FOR_ISOTONIC:
        breakpoints = fit_isotonic_regression(pairs)
        return CalibrationModel(
            version=_CALIBRATION_MODEL_VERSION,
            method="isotonic",
            fitted_at=fitted_at,
            sample_count=len(pairs),
            isotonic_breakpoints=[list(bp) for bp in breakpoints],
            platt_params=None,
            deferral_threshold_derived=deferral_threshold_derived,
            note=None,
        )
    a, b = fit_platt_scaling(pairs)
    return CalibrationModel(
        version=_CALIBRATION_MODEL_VERSION,
        method="platt",
        fitted_at=fitted_at,
        sample_count=len(pairs),
        isotonic_breakpoints=None,
        platt_params={"a": a, "b": b},
        deferral_threshold_derived=deferral_threshold_derived,
        note=None,
    )


def save_calibration_model(model: CalibrationModel, path: str) -> None:
    """[Review][Patch] Writes to a temp file in the same directory, then
    atomically renames it into place via Path.replace() -- writing directly
    to `path` would let a concurrent reader (e.g. another process's
    scoring.py import-time load) observe a truncated/partial JSON document
    if it opened the file mid-write. Nothing in this codebase currently
    calls this against the live, imported calibration_model_v1.json, but
    the swap is cheap and matches this project's existing atomic-write
    precedent (triage/store.py's persist_evidence_record). Uses
    pathlib.Path.replace() rather than os.replace() -- functionally
    identical (Path.replace() calls os.replace() internally), but avoids an
    `import os` in this file: test_triage_imports_no_remediation_capable_
    library (FR32) bans smtplib/subprocess/os from every file under
    triage/, structurally enforcing "no raw OS-level process control
    capability" -- a file-rename utility method doesn't need to defeat
    that guardrail to get atomicity."""
    target = Path(path)
    tmp_path = target.with_name(f"{target.name}.tmp-{uuid.uuid4().hex}")
    tmp_path.write_text(json.dumps(model, indent=2), encoding="utf-8")
    tmp_path.replace(target)


def load_calibration_model(path: str) -> CalibrationModel:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    isotonic_breakpoints = data["isotonic_breakpoints"]
    if isotonic_breakpoints is not None:
        # [Review][Patch] apply_isotonic assumes an ascending-x_max order --
        # true only because fit_isotonic_regression's own output is always
        # sorted. A hand-edited or corrupted file with out-of-order
        # breakpoints previously loaded without error and produced silently
        # non-monotonic calibrated output rather than a defined failure.
        x_maxes = [bp[1] for bp in isotonic_breakpoints]
        if x_maxes != sorted(x_maxes):
            raise ValueError(
                f"{path}: isotonic_breakpoints must be sorted ascending by x_max, "
                f"got {isotonic_breakpoints!r}"
            )
    return CalibrationModel(
        version=data["version"],
        method=data["method"],
        fitted_at=data["fitted_at"],
        sample_count=data["sample_count"],
        isotonic_breakpoints=isotonic_breakpoints,
        platt_params=data["platt_params"],
        deferral_threshold_derived=data["deferral_threshold_derived"],
        note=data["note"],
    )


# --- Evaluation harness: ECE, AUC-ROC (Story 3.4) -------------------------------
#
# Pure statistics functions, no dependency on scoring.py -- deliberately, to
# avoid a circular import (scoring.py already imports from this module; see
# Story 3.3's Dev Notes for the same reasoning applied to
# gather_evidence_and_raw_score). Tested against synthetic (confidence,
# label) pairs only, per AR13 -- the live-corpus run stays out of CI.

_MIN_SAMPLES_PER_ECE_BIN = 5  # PROVISIONAL, not calibrated -- see this module's other constants


class ECEBin(TypedDict):
    bin_range: tuple[float, float]
    count: int
    avg_confidence: float
    actual_positive_fraction: float
    inconclusive: bool


class ECEResult(TypedDict):
    ece: float
    bins: list[ECEBin]
    excluded_sample_count: int


def compute_ece(
    predictions: list[tuple[float, float]],
    num_bins: int = 10,
    min_bin_size: int = _MIN_SAMPLES_PER_ECE_BIN,
) -> ECEResult:
    """Expected Calibration Error, num_bins equal-width buckets over
    [0.0, 1.0]. `predictions` are (calibrated_confidence, true_label) pairs,
    true_label 0.0 (benign) or 1.0 (malicious) -- same pair convention as
    fit_calibration_mapping.

    A bin with fewer than min_bin_size samples is flagged inconclusive
    (FR30) and EXCLUDED from the `ece` figure -- not silently folded in
    (which would let a handful of noisy samples swing the headline number)
    and not silently dropped without a trace (excluded_sample_count reports
    exactly how many samples were excluded and why). [Review] A confidence
    outside [0.0, 1.0] matches no bin's condition and is likewise counted in
    excluded_sample_count, not silently dropped -- apply_calibration is
    documented to always produce [0.0, 1.0] (a defensive guarantee, not an
    assumption this function trusts blindly)."""
    bins: list[ECEBin] = []
    excluded_sample_count = 0
    weighted_error_sum = 0.0
    conclusive_sample_count = 0
    binned_count = 0

    for i in range(num_bins):
        bin_min = i / num_bins
        bin_max = (i + 1) / num_bins
        in_bin = [
            (conf, label)
            for conf, label in predictions
            if (bin_min <= conf < bin_max) or (i == num_bins - 1 and conf == bin_max)
        ]
        if not in_bin:
            continue
        count = len(in_bin)
        binned_count += count
        avg_confidence = sum(conf for conf, _label in in_bin) / count
        actual_positive_fraction = sum(label for _conf, label in in_bin) / count
        inconclusive = count < min_bin_size
        bins.append(
            ECEBin(
                bin_range=(bin_min, bin_max),
                count=count,
                avg_confidence=avg_confidence,
                actual_positive_fraction=actual_positive_fraction,
                inconclusive=inconclusive,
            )
        )
        if inconclusive:
            excluded_sample_count += count
        else:
            weighted_error_sum += count * abs(avg_confidence - actual_positive_fraction)
            conclusive_sample_count += count

    excluded_sample_count += len(predictions) - binned_count  # out-of-[0,1] confidences
    ece = weighted_error_sum / conclusive_sample_count if conclusive_sample_count else 0.0
    return ECEResult(ece=ece, bins=bins, excluded_sample_count=excluded_sample_count)


# PROVISIONAL, not calibrated -- the threshold run_evaluation_harness.py (Task 3)
# uses to decide "the discrimination metric confirms the system isn't a flat
# predictor" (AC3). A truly random/flat predictor has AUC ~= 0.5; a small
# provisional margin above that (rather than checking > 0.5 exactly) avoids a
# noise-driven false pass on a genuinely uninformative system.
_MIN_AUC_FOR_NON_FLAT = 0.55


def compute_auc_roc(predictions: list[tuple[float, float]]) -> float:
    """AUC-ROC via the Mann-Whitney U statistic: rank all predictions by
    confidence ascending (average rank for ties), AUC = (sum of ranks of the
    positive-class samples - n_pos*(n_pos+1)/2) / (n_pos * n_neg). Never
    raises -- returns 0.5 (chance level, not an error) if predictions is
    empty or only one class is present, since AUC is undefined with a
    single class (matches apply_isotonic/apply_platt's "never raises on
    degenerate input, degrade to a defined value" precedent)."""
    if not predictions:
        return 0.5

    sorted_predictions = sorted(predictions, key=lambda p: p[0])
    n = len(sorted_predictions)
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j < n and sorted_predictions[j][0] == sorted_predictions[i][0]:
            j += 1
        # Tied confidences share the average of their rank positions
        # (1-indexed) -- standard tie-breaking for the Mann-Whitney U /
        # AUC-ROC formula, not an arbitrary/unstable ordering.
        average_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = average_rank
        i = j

    n_pos = sum(1 for _conf, label in sorted_predictions if label == 1.0)
    n_neg = n - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5

    sum_positive_ranks = sum(
        rank for rank, (_conf, label) in zip(ranks, sorted_predictions) if label == 1.0
    )
    u_statistic = sum_positive_ranks - n_pos * (n_pos + 1) / 2.0
    return u_statistic / (n_pos * n_neg)
