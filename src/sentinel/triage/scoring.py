import math
from pathlib import Path
from typing import Literal

from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.eval import (
    CalibrationModel,
    apply_isotonic,
    apply_platt,
    load_calibration_model,
)

_NEUTRAL_PRIOR = 0.5

# Repo root, sibling to pyproject.toml -- not inside src/ -- per the
# architecture doc's file-tree placement. parents[0]=triage, [1]=sentinel,
# [2]=src, [3]=repo root.
_CALIBRATION_MODEL_PATH = Path(__file__).resolve().parents[3] / "calibration_model_v1.json"

# Loaded once at import time, never re-read per call (NFR7's determinism
# requirement -- a calibration mapping must not change mid-process). A
# missing file here means a broken installation (this file is committed and
# must always exist in a valid checkout), so this is a deliberate fail-fast:
# no try/except, no fallback default.
_CALIBRATION_MODEL: CalibrationModel = load_calibration_model(str(_CALIBRATION_MODEL_PATH))


def apply_calibration(raw_score: float) -> float:
    """Maps a raw score (Story 1.1's compute_raw_score output) to a
    calibrated probability via the calibration model loaded at import time.
    Always returns a value in [0.0, 1.0]."""
    method = _CALIBRATION_MODEL["method"]
    if method == "identity":
        return raw_score
    if method == "isotonic":
        breakpoints = _CALIBRATION_MODEL["isotonic_breakpoints"]
        assert breakpoints is not None
        return apply_isotonic(raw_score, [(bp[0], bp[1], bp[2]) for bp in breakpoints])
    platt_params = _CALIBRATION_MODEL["platt_params"]
    assert platt_params is not None
    return apply_platt(raw_score, platt_params["a"], platt_params["b"])


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
