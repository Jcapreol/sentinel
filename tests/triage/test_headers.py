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


# --- Story 9.1: DMARC policy strength capture -----------------------------------


def test_real_tsukuba_record_dmarc_policy_captured() -> None:
    """[Story 9.1, AC1/AC2] The exact real header from
    docs/findings/auth-alignment.md's tsukuba record (verbatim quote --
    the three real .eml files themselves are not present in this
    checkout; see the story file for that gap) -- p=NONE, sp=NONE, both
    lowercased in the finding, weight/direction unaffected (AC4)."""
    header = (
        "mx.google.com; "
        "dkim=pass header.i=@u.tsukuba.ac.jp header.s=sel header.b=abc; "
        "spf=pass (google.com: domain of s2240102@u.tsukuba.ac.jp designates "
        "1.2.3.4 as permitted sender) smtp.mailfrom=s2240102@u.tsukuba.ac.jp; "
        "dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=u.tsukuba.ac.jp"
    )
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["finding"] == (
        "DMARC authentication result: pass (policy: none, subdomain policy: none)"
    )
    assert dmarc["weight"] == 0.45
    assert dmarc["direction"] == "benign"


@pytest.mark.parametrize(
    "policy_token,expected_label",
    [("NONE", "none"), ("QUARANTINE", "quarantine"), ("REJECT", "reject")],
)
def test_dmarc_policy_values_captured_and_lowercased(
    policy_token: str, expected_label: str
) -> None:
    """[Story 9.1, AC1/AC2] p=none / p=quarantine / p=reject, each
    distinguishable in the finding string."""
    header = f"mx.google.com; dmarc=pass (p={policy_token})"
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["finding"] == f"DMARC authentication result: pass (policy: {expected_label})"


def test_dmarc_subdomain_policy_captured_when_present() -> None:
    """[Story 9.1, Notes for dev] sp= captured when cheap to do so, parent
    policy remains the priority (still present and first)."""
    header = "mx.google.com; dmarc=pass (p=REJECT sp=QUARANTINE dis=none)"
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["finding"] == (
        "DMARC authentication result: pass (policy: reject, subdomain policy: quarantine)"
    )


def test_dmarc_no_policy_present_recorded_as_unknown() -> None:
    """[Story 9.1, AC3] A dmarc=pass with no parenthetical at all -- policy
    must be explicit "unknown", never silently omitted."""
    header = "mx.google.com; dmarc=pass header.from=example.com"
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["finding"] == "DMARC authentication result: pass (policy: unknown)"


def test_dmarc_malformed_parenthetical_recorded_as_unknown() -> None:
    """[Story 9.1, AC3/AC5] A parenthetical IS present but contains no p=
    token -- still explicit "unknown", not a crash, not a silent omission."""
    header = "mx.google.com; dmarc=pass (some unrelated free text, no policy here)"
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["finding"] == "DMARC authentication result: pass (policy: unknown)"


def test_dmarc_fail_also_carries_policy() -> None:
    """[Story 9.1, AC1] Policy capture isn't pass-only -- a dmarc=fail with
    a p=reject policy is exactly the "enforcement was in place and still
    failed" case a future scoring change would most want to distinguish."""
    header = "mx.google.com; dmarc=fail (p=REJECT sp=REJECT dis=reject)"
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["finding"] == (
        "DMARC authentication result: fail (policy: reject, subdomain policy: reject)"
    )
    assert dmarc["weight"] == 0.75
    assert dmarc["direction"] == "malicious"


def test_dmarc_policy_never_appears_on_spf_or_dkim_findings() -> None:
    """[Story 9.1, AC1] "recorded on the dmarc_check evidence item" --
    scoped to DMARC only, never leaks a "(policy: ...)" suffix onto SPF/
    DKIM findings even though they share the same finding-string format."""
    header = "mx.google.com; spf=pass (p=reject fake); dkim=pass (p=reject fake); dmarc=pass (p=none)"
    items = investigate_header_authentication(header)
    spf = _by_name(items, "spf_check")
    dkim = _by_name(items, "dkim_check")
    assert spf["finding"] == "SPF authentication result: pass"
    assert dkim["finding"] == "DKIM authentication result: pass"
    assert "policy" not in spf["finding"]
    assert "policy" not in dkim["finding"]


def test_dmarc_weight_and_direction_unaffected_by_policy_value() -> None:
    """[Story 9.1, AC4] The single most important property of this story:
    a p=none pass and a p=reject pass must score IDENTICALLY -- this
    story captures the signal, it does not act on it yet."""
    none_items = investigate_header_authentication("mx.google.com; dmarc=pass (p=none)")
    reject_items = investigate_header_authentication("mx.google.com; dmarc=pass (p=reject)")
    unknown_items = investigate_header_authentication("mx.google.com; dmarc=pass")

    none_dmarc = _by_name(none_items, "dmarc_check")
    reject_dmarc = _by_name(reject_items, "dmarc_check")
    unknown_dmarc = _by_name(unknown_items, "dmarc_check")

    assert none_dmarc["weight"] == reject_dmarc["weight"] == unknown_dmarc["weight"] == 0.45
    assert none_dmarc["direction"] == reject_dmarc["direction"] == unknown_dmarc["direction"] == "benign"


def test_dmarc_policy_injection_via_unrelated_comment_is_rejected() -> None:
    """[Story 9.1, Security] A fake "dmarc=<result> (p=...)" sequence
    embedded in a DIFFERENT mechanism's comment (e.g. an SPF comment
    echoing back an attacker-controlled envelope-from) must not be
    trusted if its result doesn't match the real, safely-parsed DMARC
    result -- the real, later occurrence must still be found correctly,
    not reported as unknown just because a mismatched fake appeared
    first."""
    header = (
        "mx.google.com; "
        "spf=pass (google.com: domain of attacker designates "
        "dmarc=pass (p=reject) as permitted sender) smtp.mailfrom=attacker; "
        "dmarc=fail (p=none) header.from=evil.com"
    )
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    # Must reflect the REAL dmarc=fail's own policy (none), never the fake
    # dmarc=pass (p=reject) text hidden in the SPF comment.
    assert dmarc["finding"] == "DMARC authentication result: fail (policy: none)"
    assert dmarc["weight"] == 0.75


def test_dmarc_policy_nested_fake_with_matching_result_does_not_overwrite_real_policy() -> None:
    """[Story 9.1, Security -- adversarial review finding] A fake
    "dmarc=pass (p=reject)" nested inside an EARLIER mechanism's comment
    (SPF's, here) whose result happens to MATCH the real DMARC result
    must not be trusted merely because the result matches: it must not
    silently overwrite the real, DIFFERENT policy that follows later in
    the header. This mirrors Gmail's actual header ordering (SPF, DKIM,
    then DMARC), so this is the default layout, not a contrived one.
    Before the nesting-rejection check existed, this returned "reject"
    (the fake's value) instead of "none" (the real one)."""
    header = (
        "mx.google.com; "
        "spf=pass (dmarc=pass (p=reject) as permitted sender) smtp.mailfrom=x; "
        "dmarc=pass (p=none) header.from=evil.com"
    )
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["finding"] == "DMARC authentication result: pass (policy: none)"


def test_dmarc_policy_unclosed_genuine_comment_does_not_bleed_into_later_mechanism() -> None:
    """[Story 9.1, Security -- adversarial review finding] The GENUINE
    DMARC comment here carries no p=/sp= token at all, but is malformed
    (contains a nested, unrelated "(...)" fragment before its own close
    paren). Before _DMARC_COMMENT_PATTERN excluded "(" from the comment
    body, greedy [^)]* matching would run past the genuine comment's
    intended end and capture "p=REJECT-FAKE" out of a later, unrelated
    mechanism's parenthetical -- reporting "reject" for a comment that
    actually carries no policy information whatsoever. Must be
    "unknown", not a value bled in from elsewhere."""
    header = (
        "mx.google.com; "
        "dmarc=pass (no policy info here at all just prose spf=fail (p=REJECT-FAKE) leftover) "
        "dkim=pass"
    )
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["finding"] == "DMARC authentication result: pass (policy: unknown)"


def test_dmarc_policy_injection_with_matching_result_and_no_real_comment_stays_unknown() -> None:
    """[Story 9.1, Security] If the ONLY "dmarc=<result> (...)" occurrence
    in the header is nested inside an unrelated mechanism's comment (no
    genuine DMARC comment exists at all), the nesting-rejection check (see
    _parse_dmarc_policy's own docstring, point 2) discards it: its
    "dmarc=" token starts inside the earlier SPF comment's span, so it
    never reaches the result-matching stage at all. Correctly "unknown",
    not the fake's "reject" -- this test pins that resolved behavior."""
    header = (
        "mx.google.com; "
        "spf=pass (weird comment containing dmarc=pass (p=reject) by coincidence) smtp.mailfrom=x; "
        "dmarc=pass header.from=x"
    )
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["finding"] == "DMARC authentication result: pass (policy: unknown)"


def test_dmarc_policy_case_insensitive_mixed_case_header() -> None:
    header = "mx.google.com; DMARC=Pass (P=Reject SP=Quarantine)"
    items = investigate_header_authentication(header)
    dmarc = _by_name(items, "dmarc_check")
    assert dmarc["finding"] == (
        "DMARC authentication result: pass (policy: reject, subdomain policy: quarantine)"
    )


def test_real_bizgital_and_sp46_records_have_no_dmarc_result_unaffected_by_story() -> None:
    """[Story 9.1, AC5] The other two records from the auth-alignment
    finding's campaign (docs/findings/auth-alignment.md's table) both show
    DMARC as entirely absent, not present-with-an-unparseable-policy --
    confirming this story's new code is never even reached for them, the
    pre-existing "No DMARC authentication result present" path is
    completely unchanged. (The raw .eml files themselves are not present
    in this checkout to build a byte-exact fixture from -- see the story
    file's AC5 note -- but "DMARC absent" is exactly what the finding
    document's own table records for both, which is what this pins.)"""
    bizgital_header = "mx.google.com; spf=pass; dkim=pass"
    sp46_header = "mx.google.com; spf=softfail; dkim=pass"
    for header in (bizgital_header, sp46_header):
        items = investigate_header_authentication(header)
        dmarc = _by_name(items, "dmarc_check")
        assert dmarc["finding"] == "No DMARC authentication result present in headers"
        assert dmarc["weight"] == 0.10
        assert dmarc["direction"] == "neutral"
