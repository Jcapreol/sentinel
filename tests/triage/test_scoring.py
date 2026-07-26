import ast
import math
import random
from collections.abc import Callable
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.scoring import (
    InconclusiveScoreError,
    apply_calibration,
    compute_raw_score,
    determine_verdict,
)


def test_compute_raw_score_empty_evidence_returns_neutral_prior() -> None:
    assert compute_raw_score([]) == 0.5


def test_compute_raw_score_single_malicious_item_above_neutral(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    item = make_evidence_item(weight=0.8, direction="malicious")
    assert compute_raw_score([item]) > 0.5


def test_compute_raw_score_single_benign_item_below_neutral(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    item = make_evidence_item(weight=0.8, direction="benign")
    assert compute_raw_score([item]) < 0.5


def test_compute_raw_score_mixed_direction_multi_item_exact_value(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    items = [
        make_evidence_item(name="a", weight=0.6, direction="malicious"),
        make_evidence_item(name="b", weight=0.4, direction="benign"),
        make_evidence_item(name="c", weight=0.2, direction="neutral"),
    ]
    # signed_sum = 0.6 - 0.4 + 0.0 = 0.2; total_weight = 0.6 + 0.4 + 0.2 = 1.2
    # normalized = 0.2 / 1.2 = 0.16666...; score = (0.16666... + 1.0) / 2.0
    expected = ((0.6 - 0.4) / 1.2 + 1.0) / 2.0
    assert math.isclose(compute_raw_score(items), expected)


def test_compute_raw_score_deterministic_under_shuffled_order(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    items = [
        make_evidence_item(name="a", weight=0.6, direction="malicious"),
        make_evidence_item(name="b", weight=0.4, direction="benign"),
        make_evidence_item(name="c", weight=0.9, direction="neutral"),
        make_evidence_item(name="d", weight=0.3, direction="malicious"),
    ]
    original_score = compute_raw_score(items)

    shuffled = items.copy()
    random.Random(42).shuffle(shuffled)
    assert shuffled != items  # sanity check the shuffle actually reordered

    shuffled_score = compute_raw_score(shuffled)
    assert shuffled_score == original_score


def test_compute_raw_score_repeatable_across_calls(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    items = [make_evidence_item(name="a", weight=0.5, direction="malicious")]
    assert compute_raw_score(items) == compute_raw_score(items)


def test_compute_raw_score_rejects_negative_weight(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    item = make_evidence_item(weight=-0.1, direction="malicious")
    with pytest.raises(ValueError, match="invalid weight"):
        compute_raw_score([item])


def test_compute_raw_score_rejects_non_finite_weight(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    item = make_evidence_item(weight=math.inf, direction="malicious")
    with pytest.raises(ValueError, match="invalid weight"):
        compute_raw_score([item])


def test_determine_verdict_above_threshold_is_malicious() -> None:
    assert determine_verdict(0.7) == "Malicious"


def test_determine_verdict_below_threshold_is_benign() -> None:
    assert determine_verdict(0.3) == "Benign"


def test_determine_verdict_respects_custom_threshold() -> None:
    assert determine_verdict(0.6, threshold=0.65) == "Benign"
    assert determine_verdict(0.7, threshold=0.65) == "Malicious"


def test_determine_verdict_at_threshold_boundary_is_malicious() -> None:
    assert determine_verdict(0.65, threshold=0.65) == "Malicious"


def test_determine_verdict_raises_on_empty_evidence_score() -> None:
    score = compute_raw_score([])
    with pytest.raises(InconclusiveScoreError):
        determine_verdict(score)


def test_determine_verdict_raises_on_all_zero_weight_evidence(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    items = [
        make_evidence_item(name="a", weight=0.0, direction="malicious"),
        make_evidence_item(name="b", weight=0.0, direction="benign"),
    ]
    score = compute_raw_score(items)
    with pytest.raises(InconclusiveScoreError):
        determine_verdict(score)


def test_determine_verdict_raises_on_exactly_canceling_evidence(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    items = [
        make_evidence_item(name="a", weight=0.5, direction="malicious"),
        make_evidence_item(name="b", weight=0.5, direction="benign"),
    ]
    score = compute_raw_score(items)
    with pytest.raises(InconclusiveScoreError):
        determine_verdict(score)


def test_determine_verdict_deferral_band_defaults_to_zero_preserves_existing_behavior() -> None:
    # 0.5 + 0.01 is far enough from the neutral prior that only a non-zero
    # deferral_band would catch it — default behavior must NOT raise here.
    assert determine_verdict(0.51) == "Malicious"


def test_determine_verdict_raises_inside_nonzero_deferral_band() -> None:
    with pytest.raises(InconclusiveScoreError):
        determine_verdict(0.52, deferral_band=0.05)


def test_determine_verdict_does_not_raise_at_exact_deferral_band_boundary() -> None:
    # abs(0.55 - 0.5) == 0.05 == deferral_band; boundary is strict '<', not '<='
    assert determine_verdict(0.55, deferral_band=0.05) == "Malicious"


def test_determine_verdict_does_not_raise_just_outside_deferral_band() -> None:
    assert determine_verdict(0.56, deferral_band=0.05) == "Malicious"


def test_determine_verdict_rejects_threshold_out_of_range() -> None:
    with pytest.raises(ValueError, match="threshold"):
        determine_verdict(0.7, threshold=1.5)


def test_determine_verdict_rejects_deferral_band_out_of_range() -> None:
    with pytest.raises(ValueError, match="deferral_band"):
        determine_verdict(0.7, deferral_band=-0.1)


def test_apply_calibration_dispatches_to_identity(mocker: MockerFixture) -> None:
    mocker.patch(
        "sentinel.triage.scoring._CALIBRATION_MODEL",
        {
            "version": 1,
            "method": "identity",
            "fitted_at": None,
            "sample_count": 0,
            "isotonic_breakpoints": None,
            "platt_params": None,
            "deferral_threshold_derived": 0.05,
            "note": None,
        },
    )
    assert apply_calibration(0.37) == 0.37


def test_apply_calibration_dispatches_to_isotonic(mocker: MockerFixture) -> None:
    mocker.patch(
        "sentinel.triage.scoring._CALIBRATION_MODEL",
        {
            "version": 1,
            "method": "isotonic",
            "fitted_at": "2026-01-01T00:00:00+00:00",
            "sample_count": 100,
            "isotonic_breakpoints": [[0.0, 0.4, 0.1], [0.5, 1.0, 0.9]],
            "platt_params": None,
            "deferral_threshold_derived": 0.05,
            "note": None,
        },
    )
    assert apply_calibration(0.2) == 0.1
    assert apply_calibration(0.7) == 0.9


def test_apply_calibration_dispatches_to_platt(mocker: MockerFixture) -> None:
    mocker.patch(
        "sentinel.triage.scoring._CALIBRATION_MODEL",
        {
            "version": 1,
            "method": "platt",
            "fitted_at": "2026-01-01T00:00:00+00:00",
            "sample_count": 50,
            "isotonic_breakpoints": None,
            "platt_params": {"a": -5.0, "b": 2.5},
            "deferral_threshold_derived": 0.05,
            "note": None,
        },
    )
    result = apply_calibration(0.5)
    assert 0.0 <= result <= 1.0


def test_apply_calibration_output_always_within_unit_interval(mocker: MockerFixture) -> None:
    mocker.patch(
        "sentinel.triage.scoring._CALIBRATION_MODEL",
        {
            "version": 1,
            "method": "platt",
            "fitted_at": "2026-01-01T00:00:00+00:00",
            "sample_count": 50,
            "isotonic_breakpoints": None,
            "platt_params": {"a": 1e10, "b": 1e10},
            "deferral_threshold_derived": 0.05,
            "note": None,
        },
    )
    for raw_score in [-1e10, -1.0, 0.0, 0.5, 1.0, 1e10]:
        result = apply_calibration(raw_score)
        assert 0.0 <= result <= 1.0


def test_apply_calibration_against_real_committed_placeholder_is_identity() -> None:
    # No mocking -- proves the actual shipped calibration_model_v1.json behaves
    # as documented (identity), not just that the dispatch logic is correct.
    for raw_score in [0.0, 0.1, 0.37, 0.5, 0.9, 1.0]:
        assert apply_calibration(raw_score) == raw_score


def test_scoring_never_imports_confidence() -> None:
    source_path = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "triage" / "scoring.py"
    tree = ast.parse(source_path.read_text())
    forbidden = {"sentinel.confidence", "confidence"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden, f"scoring.py imports {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden, f"scoring.py imports from {node.module}"
            for alias in node.names:
                assert alias.name not in forbidden, (
                    f"scoring.py imports {alias.name} from {node.module}"
                )
