import ast
from pathlib import Path

import pytest

from sentinel.triage.headers import investigate_header_authentication
from sentinel.triage.scoring import compute_raw_score


def _by_name(items: list, name: str) -> dict:
    matches = [i for i in items if i["name"] == name]
    assert len(matches) == 1, f"expected exactly one item named {name!r}, got {len(matches)}"
    return matches[0]


def test_all_pass_returns_three_benign_items_with_per_mechanism_weights() -> None:
    header = "mx.google.com; spf=pass; dkim=pass; dmarc=pass"
    items = investigate_header_authentication(header)
    assert len(items) == 3

    spf = _by_name(items, "spf_check")
    assert spf["direction"] == "benign"
    assert spf["weight"] == 0.25

    dkim = _by_name(items, "dkim_check")
    assert dkim["direction"] == "benign"
    assert dkim["weight"] == 0.35

    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["direction"] == "benign"
    assert dmarc["weight"] == 0.45


def test_all_fail_returns_three_malicious_items_with_per_mechanism_weights() -> None:
    header = "mx.google.com; spf=fail; dkim=fail; dmarc=fail"
    items = investigate_header_authentication(header)
    assert len(items) == 3

    spf = _by_name(items, "spf_check")
    assert spf["direction"] == "malicious"
    assert spf["weight"] == 0.40

    dkim = _by_name(items, "dkim_check")
    assert dkim["direction"] == "malicious"
    assert dkim["weight"] == 0.55

    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["direction"] == "malicious"
    assert dmarc["weight"] == 0.75


def test_dmarc_fail_weighted_higher_than_spf_fail() -> None:
    """DMARC carries alignment+policy context; SPF-alone fail is a known high-FP signal."""
    header = "mx.google.com; spf=fail; dmarc=fail"
    items = investigate_header_authentication(header)
    spf = _by_name(items, "spf_check")
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["weight"] > spf["weight"]


def test_mixed_results_have_correct_per_mechanism_direction_and_weight() -> None:
    header = "mx.google.com; spf=pass; dkim=fail; dmarc=softfail"
    items = investigate_header_authentication(header)
    assert len(items) == 3

    spf = _by_name(items, "spf_check")
    assert spf["direction"] == "benign"
    assert spf["weight"] == 0.25

    dkim = _by_name(items, "dkim_check")
    assert dkim["direction"] == "malicious"
    assert dkim["weight"] == 0.55

    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["direction"] == "malicious"
    assert dmarc["weight"] == 0.30


def test_none_header_returns_three_neutral_gap_items_with_damping_weight() -> None:
    items = investigate_header_authentication(None)
    assert len(items) == 3
    for item in items:
        assert item["direction"] == "neutral"
        assert item["weight"] == 0.10
        assert "No" in item["finding"]


def test_missing_one_mechanism_returns_gap_item_for_it_only() -> None:
    header = "mx.google.com; spf=pass; dkim=pass"
    items = investigate_header_authentication(header)
    assert len(items) == 3

    spf = _by_name(items, "spf_check")
    assert spf["direction"] == "benign"

    dkim = _by_name(items, "dkim_check")
    assert dkim["direction"] == "benign"

    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["direction"] == "neutral"
    assert dmarc["weight"] == 0.10
    assert "DMARC" in dmarc["finding"]


def test_unrecognized_result_keyword_produces_neutral_item_naming_it() -> None:
    header = "mx.google.com; spf=bogus; dkim=pass; dmarc=fail"
    items = investigate_header_authentication(header)
    assert len(items) == 3

    spf = _by_name(items, "spf_check")
    assert spf["direction"] == "neutral"
    assert spf["weight"] == 0.10
    assert "bogus" in spf["finding"]

    # other mechanisms unaffected
    dkim = _by_name(items, "dkim_check")
    assert dkim["direction"] == "benign"
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["direction"] == "malicious"


@pytest.mark.parametrize(
    "garbage",
    ["", "   ", "not a real header at all", "spf dkim dmarc", "====", "spf=", "=pass"],
)
def test_never_raises_on_garbage_input(garbage: str) -> None:
    items = investigate_header_authentication(garbage)
    assert isinstance(items, list)
    assert all(item["direction"] == "neutral" for item in items)


def test_malformed_present_header_uses_distinct_message_from_missing_header() -> None:
    """AC3: a present-but-unparseable header must be distinguishable from a genuinely
    absent one — both are neutral/damped, but the finding text must say which happened."""
    missing_items = investigate_header_authentication(None)
    malformed_items = investigate_header_authentication("not a real header at all")

    missing_finding = _by_name(missing_items, "spf_check")["finding"]
    malformed_finding = _by_name(malformed_items, "spf_check")["finding"]

    assert missing_finding != malformed_finding
    assert "present" in malformed_finding.lower()
    assert "No SPF" in missing_finding


def test_case_insensitive_mechanism_and_result_matching() -> None:
    header = "mx.google.com; SPF=Fail; DKIM=Pass; DMARC=Fail"
    items = investigate_header_authentication(header)
    assert len(items) == 3

    spf = _by_name(items, "spf_check")
    assert spf["direction"] == "malicious"
    assert spf["weight"] == 0.40

    dkim = _by_name(items, "dkim_check")
    assert dkim["direction"] == "benign"


def test_result_inside_comment_is_not_matched() -> None:
    """A parenthesized comment mentioning a result keyword must not be mistaken for
    a real result — comments are stripped before matching."""
    header = "mx.google.com; spf=fail (note: unrelated text says dkim=pass here); dmarc=fail"
    items = investigate_header_authentication(header)

    dkim = _by_name(items, "dkim_check")
    # The comment-embedded "dkim=pass" must NOT have been picked up as real DKIM evidence.
    assert dkim["direction"] == "neutral"
    assert dkim["weight"] == 0.10


def test_duplicate_conflicting_mechanism_flagged_not_silently_overwritten() -> None:
    header = "mx.google.com; spf=fail; spf=pass; dkim=pass; dmarc=fail"
    items = investigate_header_authentication(header)

    spf = _by_name(items, "spf_check")
    assert spf["direction"] == "neutral"
    assert spf["weight"] == 0.10
    assert "onflict" in spf["finding"]

    # unaffected mechanisms still resolve normally
    dkim = _by_name(items, "dkim_check")
    assert dkim["direction"] == "benign"


def test_duplicate_matching_mechanism_is_not_flagged_as_conflict() -> None:
    """Same mechanism appearing twice with the SAME result is not a conflict."""
    header = "mx.google.com; spf=fail; spf=fail; dkim=pass"
    items = investigate_header_authentication(header)
    spf = _by_name(items, "spf_check")
    assert spf["direction"] == "malicious"
    assert "onflict" not in spf["finding"]


def test_sparse_evidence_does_not_produce_certain_score() -> None:
    """Regression guard for the core fix: a lone weak signal must not rail the raw
    score to 0.0 or 1.0 — that false certainty is exactly what this product exists
    to refuse. Missing mechanisms must carry a non-zero damping weight."""
    lone_fail_items = investigate_header_authentication("mx.google.com; spf=fail")
    lone_fail_score = compute_raw_score(lone_fail_items)
    assert lone_fail_score < 1.0
    assert lone_fail_score > 0.5  # still leans malicious, just not with false certainty

    lone_pass_items = investigate_header_authentication("mx.google.com; spf=pass")
    lone_pass_score = compute_raw_score(lone_pass_items)
    assert lone_pass_score > 0.0
    assert lone_pass_score < 0.5  # still leans benign, just not with false certainty


def test_headers_never_imports_scoring_or_confidence() -> None:
    source_path = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "triage" / "headers.py"
    tree = ast.parse(source_path.read_text())
    forbidden = {"sentinel.triage.scoring", "sentinel.confidence", "scoring", "confidence"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden, f"headers.py imports {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden, f"headers.py imports from {node.module}"
            for alias in node.names:
                assert alias.name not in forbidden, (
                    f"headers.py imports {alias.name} from {node.module}"
                )
