import math
from typing import Literal

from sentinel.triage.evidence import EvidenceItem

_NEUTRAL_PRIOR = 0.5


class InconclusiveScoreError(ValueError):
    """Raised when a score has no directional signal — caller must route to a deferred outcome."""


def compute_raw_score(evidence: list[EvidenceItem]) -> float:
    if not evidence:
        return _NEUTRAL_PRIOR

    signed_sum = 0.0
    total_weight = 0.0
    for item in evidence:
        weight = item["weight"]
        if not math.isfinite(weight) or weight < 0:
            raise ValueError(
                f"invalid weight {weight!r} for evidence item {item['name']!r} — "
                "must be finite and non-negative"
            )
        total_weight += weight
        if item["direction"] == "malicious":
            signed_sum += weight
        elif item["direction"] == "benign":
            signed_sum -= weight
        # "neutral" contributes 0.0 to signed_sum but still counts toward total_weight

    if total_weight == 0.0:
        return _NEUTRAL_PRIOR

    normalized = signed_sum / total_weight  # range [-1.0, 1.0]
    return (normalized + 1.0) / 2.0  # range [0.0, 1.0]


def determine_verdict(
    score: float,
    threshold: float = 0.5,
    deferral_band: float = 0.0,
) -> Literal["Malicious", "Benign"]:
    if not (0.0 <= threshold <= 1.0):
        raise ValueError(f"threshold must be within [0.0, 1.0], got {threshold!r}")
    if not (0.0 <= deferral_band <= 1.0):
        raise ValueError(f"deferral_band must be within [0.0, 1.0], got {deferral_band!r}")

    if (
        math.isclose(score, _NEUTRAL_PRIOR, abs_tol=1e-9)
        or abs(score - _NEUTRAL_PRIOR) < deferral_band
    ):
        raise InconclusiveScoreError(
            "score has no directional signal (evidence was empty, all-neutral, exactly "
            "canceling, or within the configured deferral band around the neutral prior) — "
            "caller must route to a deferred outcome, not a directional verdict"
        )
    return "Malicious" if score >= threshold else "Benign"
