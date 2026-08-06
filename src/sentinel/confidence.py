from enum import Enum
from typing import Literal

from sentinel.source_registry import SOURCE_CATEGORIES
from sentinel.verdict import AgentResult, cipher_findings_show_malicious


class ConfidenceTier(Enum):
    BENIGN = "Benign"
    INVESTIGATING = "Investigating"
    PROBABLE = "Probable"
    CONFIRMED = "Confirmed"


TIER_MAP: dict[ConfidenceTier, tuple[int, str]] = {
    ConfidenceTier.BENIGN: (0, "Benign"),
    ConfidenceTier.INVESTIGATING: (1, "Investigating"),
    ConfidenceTier.PROBABLE: (2, "Probable"),
    ConfidenceTier.CONFIRMED: (3, "Confirmed"),
}


def count_independent_sources(results: list[AgentResult]) -> int:
    categories: set[str] = set()
    for result in results:
        if result["error"] is None:
            cat = SOURCE_CATEGORIES.get(result["source_name"])
            if cat is not None:
                categories.add(cat)
    return len(categories)


def _parse_cipher_severity(result: AgentResult) -> Literal["malicious", "clean", "no_data"]:
    """
    "malicious" — cipher_findings_show_malicious(result["findings"]) is True
                  (verdict.py -- the VT-engines-flagged or AbuseIPDB-score-over-
                  threshold pattern). [2026-08-06] Now surfaced even when `error`
                  is ALSO set (e.g. a later sub-lookup timed out after an earlier
                  one already found something real) -- this IS the actual behavior
                  change in this revision: previously ANY `error` short-circuited
                  to "no_data" before findings were ever inspected, discarding a
                  real threat signal just because part of the overall check didn't
                  complete. Mirrors the reasoning behind cipher.py's own timeout
                  fix (don't throw away evidence already gathered) and the VT-
                  visibility fix (surface degradation, don't hide it). Safe by
                  construction: cipher.py only ever appends a finding string after
                  a full, successfully-parsed lookup response (defensive int casts
                  happen before `findings.append`, every append site) -- a finding
                  present here was never partial/garbled, and `error`, when also
                  set, always originates from a DIFFERENT sub-lookup than the one
                  that produced this finding (append and the error paths are
                  mutually exclusive within one sub-lookup's own try/except).
                  Known gap, pre-existing and NOT addressed here: a URLhaus-only
                  finding never matches cipher_findings_show_malicious's patterns,
                  so a real URLhaus hit would still fall through to "clean"/
                  "no_data" if it's the only finding present -- narrower than this
                  docstring's "malicious" case implies, worth its own look if it
                  matters in practice.
    "clean"     — cipher_findings_show_malicious is False, AND no error.
                  [2026-08-06 clarification, not a behavior change] A finding that
                  matches neither pattern (unparseable, or a source this function
                  doesn't recognize, e.g. URLhaus) is indistinguishable here from a
                  genuine zero-score finding -- both fall through to this branch.
                  A zero-malicious/unrecognized finding alongside a set `error` was
                  ALREADY "no_data", not "clean", before this revision (the old
                  code's unconditional `error is not None` check already caught
                  this case) -- that half of the current behavior is unchanged,
                  restated here only for a single clear picture of all three cases.
    "no_data"   — no findings at all, OR no malicious match alongside an error
                  (rate-limited, timed out, etc. on part of the check) -- an
                  incomplete check must never be presented as a complete,
                  exonerating clean scan.
    Only "clean" is exonerating evidence; "no_data" is inconclusive.

    Consistency note (2026-08-06): the "malicious"/no-error->"clean" split here
    and verdict.py's own cipher_agent_status ("partial" vs "error" display
    label) are two DIFFERENT three-way classifications built on the SAME
    underlying cipher_findings_show_malicious primitive -- deliberately kept as
    two functions (severity feeds the confidence tier; status is a display
    label for methodology/evidence_chain) rather than one, since they answer
    different questions, but neither re-implements the malicious-pattern match
    independently.
    """
    if not result["findings"]:
        return "no_data"
    if cipher_findings_show_malicious(result["findings"]):
        return "malicious"
    return "no_data" if result["error"] is not None else "clean"


def _parse_watchman_severity(result: AgentResult) -> Literal["high", "medium", "low", "no_data"]:
    if result["error"] is not None or result["raw_confidence"] is None:
        return "no_data"
    rc = result["raw_confidence"].strip().lower()
    if rc == "confirmed":
        return "high"
    if rc == "probable":
        return "medium"
    if rc == "investigating":
        return "low"
    return "no_data"


def calculate_tier(watchman_result: AgentResult, cipher_result: AgentResult) -> ConfidenceTier:
    """
    Severity-first tiering:

    Cipher malicious  + Watchman high/medium  → CONFIRMED  (two independent sources agree)
    Cipher malicious  + Watchman low/no_data  → PROBABLE   (single strong signal)
    Cipher clean      + Watchman high         → INVESTIGATING (IOC cleared but LLM suspects)
    Cipher clean      + Watchman low/no_data  → BENIGN     (explicit exoneration)
    Cipher no_data    + Watchman high         → PROBABLE   (LLM signal, no corroboration)
    Cipher no_data    + Watchman medium/low   → INVESTIGATING
    """
    cipher_sev = _parse_cipher_severity(cipher_result)
    watchman_sev = _parse_watchman_severity(watchman_result)

    if cipher_sev == "malicious":
        if watchman_sev in ("high", "medium"):
            return ConfidenceTier.CONFIRMED
        return ConfidenceTier.PROBABLE

    if cipher_sev == "clean":
        if watchman_sev == "high":
            return ConfidenceTier.INVESTIGATING
        return ConfidenceTier.BENIGN

    # no_data — Cipher's silence is not exonerating
    if watchman_sev == "high":
        return ConfidenceTier.PROBABLE
    return ConfidenceTier.INVESTIGATING
