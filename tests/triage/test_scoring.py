import ast
import math
import random
from collections.abc import Callable
from pathlib import Path

import pytest

from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.scoring import (
    InconclusiveScoreError,
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
