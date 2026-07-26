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
import re
from pathlib import Path
from typing import TypedDict

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
