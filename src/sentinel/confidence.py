import re
from enum import Enum
from typing import Literal

from sentinel.source_registry import SOURCE_CATEGORIES
from sentinel.verdict import AgentResult


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

_VT_MALICIOUS_RE = re.compile(r"VirusTotal:.*flagged by (\d+) engines as malicious")
_ABUSE_SCORE_RE = re.compile(r"AbuseIPDB:.*abuse confidence (\d+)%")
_ABUSE_MALICIOUS_THRESHOLD = 25


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
    "malicious" — at least one finding shows VT engines > 0 or AbuseIPDB >= threshold.
    "clean"     — findings present but all scores are zero (Cipher checked and found nothing).
    "no_data"   — error, or no findings at all (no IOC in alert, rate-limited, etc.).
    Only "clean" is exonerating evidence; "no_data" is inconclusive.
    """
    if result["error"] is not None or not result["findings"]:
        return "no_data"
    for finding in result["findings"]:
        m = _VT_MALICIOUS_RE.search(finding)
        if m and int(m.group(1)) > 0:
            return "malicious"
        m = _ABUSE_SCORE_RE.search(finding)
        if m and int(m.group(1)) >= _ABUSE_MALICIOUS_THRESHOLD:
            return "malicious"
    return "clean"


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
