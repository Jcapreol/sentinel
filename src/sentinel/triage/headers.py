"""SPF/DKIM/DMARC evidence extraction from the Authentication-Results header.

Known blind spot (permanent scope boundary, not a gap to close later): this module
trusts the ingesting mail server's own Authentication-Results verdict. It performs no
independent SPF/DKIM/DMARC verification — no DNS record lookups, no cryptographic
signature checks. If the receiving server's authentication check is itself compromised
or bypassed upstream, this module has no way to detect that.
"""

import re
from typing import Literal

from sentinel.triage.evidence import EvidenceItem

_MECHANISMS = ("spf", "dkim", "dmarc")

_RESULT_DIRECTION: dict[str, Literal["malicious", "benign", "neutral"]] = {
    "pass": "benign",
    "fail": "malicious",
    "softfail": "malicious",
    "neutral": "neutral",
    "none": "neutral",
    "temperror": "neutral",
    "permerror": "neutral",
}

# Per-mechanism pass/fail weights — PROVISIONAL PRIORS, not calibrated values.
#
# These fix the raw signal *shape* (stopping a lone weak signal from railing to 0.0/1.0
# certainty) — they do not do calibration's job. DMARC > DKIM > SPF on both fail and
# pass: SPF-alone failure is the weakest, highest-false-positive signal (breaks on any
# forwarding/mailing-list relay); DMARC carries alignment+policy context and is the most
# actionable. Mapping raw scores to empirical probabilities against a labeled corpus is
# Epic 3's job (Story 3.2, the calibration harness) — expect these exact numbers to be
# revisited once that runs against real data.
_MECHANISM_FAIL_WEIGHT: dict[str, float] = {"spf": 0.40, "dkim": 0.55, "dmarc": 0.75}
_MECHANISM_PASS_WEIGHT: dict[str, float] = {"spf": 0.25, "dkim": 0.35, "dmarc": 0.45}

# Shared damping weight for anything that carries no confident directional read: a
# missing mechanism, an unrecognized result keyword, or a low-signal/ambiguous result
# (none/neutral/temperror/conflicting occurrences). This is the load-bearing fix: these
# must stay non-zero so sparse evidence damps toward uncertainty in compute_raw_score's
# normalization (which divides only by *present* weight) instead of railing a single
# weak signal to a certain 0.0 or 1.0 score — the exact false-certainty this product
# exists to refuse.
_UNINFORMATIVE_WEIGHT = 0.10
_PERMERROR_WEIGHT = 0.15
_SOFTFAIL_WEIGHT = 0.30

_RESULT_WEIGHT: dict[str, float] = {
    "softfail": _SOFTFAIL_WEIGHT,
    "neutral": _UNINFORMATIVE_WEIGHT,
    "none": _UNINFORMATIVE_WEIGHT,
    "temperror": _UNINFORMATIVE_WEIGHT,
    "permerror": _PERMERROR_WEIGHT,
}

_COMMENT_PATTERN = re.compile(r"\([^)]*\)")
_RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=([a-zA-Z]+)", re.IGNORECASE)

# [Story 9.1] DMARC policy capture -- informational only, per AC4 no weight
# anywhere in this file reads these. Deliberately separate from
# _RESULT_PATTERN/_COMMENT_PATTERN above, which strip ALL parenthetical
# content before matching mechanism=result specifically because a comment
# can carry attacker-influenced text (e.g. an SPF comment echoing back the
# claimed envelope-from domain) -- trusting comment content for THAT
# purpose would let a crafted domain inject a fake "dmarc=pass" match.
# Reading the policy necessarily means trusting some comment content, so
# _parse_dmarc_policy below narrows the trust surface as far as
# practical: see its own docstring.
#
# The comment body excludes "(" as well as ")" (not just ")" like
# _COMMENT_PATTERN above): a genuine DMARC comment is never itself
# parenthesized, so requiring zero nested "(" means a malformed/unclosed
# comment fails to match at all -- falling through to "unknown" -- rather
# than silently capturing through to some LATER, unrelated mechanism's
# close-paren and reading its content instead.
_DMARC_COMMENT_PATTERN = re.compile(r"\bdmarc=([a-zA-Z]+)\s*\(([^()]*)\)", re.IGNORECASE)
_POLICY_TOKEN_PATTERN = re.compile(r"\bp=([a-zA-Z]+)", re.IGNORECASE)
_SUBDOMAIN_POLICY_TOKEN_PATTERN = re.compile(r"\bsp=([a-zA-Z]+)", re.IGNORECASE)


def _weight_for(mechanism: str, result: str) -> float:
    if result == "pass":
        return _MECHANISM_PASS_WEIGHT[mechanism]
    if result == "fail":
        return _MECHANISM_FAIL_WEIGHT[mechanism]
    return _RESULT_WEIGHT[result]


def _parse_dmarc_policy(
    auth_results_header: str, expected_result: str
) -> tuple[str | None, str | None]:
    """Extracts (policy, subdomain_policy) from the parenthetical comment
    immediately following the DMARC mechanism's own result token in the
    ORIGINAL (not comment-stripped) header text -- e.g.
    "dmarc=pass (p=NONE sp=NONE dis=NONE)" -> ("none", "none"). Returns
    (None, None) if no such comment exists, or it exists but contains no
    parseable p=/sp= token -- callers must render this as an explicit
    "unknown", never silently omit it or default to a specific policy
    (AC3).

    [Security] Two independent checks, closing two distinct injection
    routes found in adversarial review:

    1. Result cross-validation: requires a literal "dmarc=<result>" token
       immediately (whitespace only) before the parenthetical read from,
       AND requires <result> to exactly match `expected_result` -- the
       mechanism's own result as already established by
       investigate_header_authentication's safe, comment-stripped parse.
       Checks EVERY such occurrence in the header, not just the first: a
       crafted comment elsewhere (e.g. an SPF comment echoing back an
       attacker-controlled envelope-from) could contain a
       "dmarc=<wrong-result> (...)" sequence positioned before the real
       one, and stopping at the first match would then miss the real,
       later, matching occurrence entirely -- a false "unknown" for
       perfectly legitimate mail.

    2. Nesting rejection: a candidate is discarded if its "dmarc=" token
       starts inside an EARLIER _COMMENT_PATTERN span (the same
       comment-matching the safe parse itself relies on). Without this, a
       fake "dmarc=pass (p=...)" nested inside an unrelated, earlier
       comment (e.g. SPF's) can carry the SAME result as the genuine
       DMARC clause -- Gmail's own header ordering always places DMARC
       last, so this is not a contrived layout -- and would otherwise be
       accepted as genuine merely because its result matches, silently
       overwriting a real, DIFFERENT policy value rather than just
       filling an absence.

    Together with _DMARC_COMMENT_PATTERN's own "(" -excluding comment
    body (see its definition), these narrow the trust surface as far as
    practical without eliminating it entirely: an attacker who can both
    predict the real result AND place a matching, well-formed
    "dmarc=<result> (...)" sequence outside every earlier comment span
    (i.e. as a second top-level token) could still fool this. Per AC4 no
    weight anywhere is affected by the result either way -- this is a
    purely informational field, and this is a proportionate level of
    care for one.
    """
    comment_spans = [m.span() for m in _COMMENT_PATTERN.finditer(auth_results_header)]

    def _nested_in_earlier_comment(pos: int) -> bool:
        return any(start <= pos < end for start, end in comment_spans)

    match = next(
        (
            m
            for m in _DMARC_COMMENT_PATTERN.finditer(auth_results_header)
            if m.group(1).lower() == expected_result
            and not _nested_in_earlier_comment(m.start())
        ),
        None,
    )
    if match is None:
        return None, None
    comment = match.group(2)
    policy_match = _POLICY_TOKEN_PATTERN.search(comment)
    subdomain_match = _SUBDOMAIN_POLICY_TOKEN_PATTERN.search(comment)
    policy = policy_match.group(1).lower() if policy_match else None
    subdomain_policy = subdomain_match.group(1).lower() if subdomain_match else None
    return policy, subdomain_policy


def _dmarc_policy_suffix(auth_results_header: str, result: str) -> str:
    """Builds the " (policy: ...)" suffix for a DMARC finding string (AC2).
    Always includes a policy value -- "unknown" per AC3 when none could be
    parsed, never silently omitted. Subdomain policy is appended only when
    present (Notes for dev: capture if cheap, parent policy is the
    priority -- not a field that needs its own "unknown" state)."""
    policy, subdomain_policy = _parse_dmarc_policy(auth_results_header, result)
    policy_label = policy if policy is not None else "unknown"
    suffix = f" (policy: {policy_label}"
    if subdomain_policy is not None:
        suffix += f", subdomain policy: {subdomain_policy}"
    return suffix + ")"


def investigate_header_authentication(auth_results_header: str | None) -> list[EvidenceItem]:
    try:
        header_was_provided = bool(auth_results_header and auth_results_header.strip())

        results: dict[str, str] = {}
        conflicts: set[str] = set()
        if header_was_provided:
            assert auth_results_header is not None  # narrows for mypy; header_was_provided implies this
            cleaned = _COMMENT_PATTERN.sub("", auth_results_header)
            for raw_mechanism, raw_result in _RESULT_PATTERN.findall(cleaned):
                mechanism = raw_mechanism.lower()
                result = raw_result.lower()
                if mechanism in results and results[mechanism] != result:
                    conflicts.add(mechanism)
                results[mechanism] = result

        header_was_unparseable = header_was_provided and not results

        items: list[EvidenceItem] = []
        for mechanism in _MECHANISMS:
            if mechanism in conflicts:
                items.append(
                    EvidenceItem(
                        name=f"{mechanism}_check",
                        finding=(
                            f"Conflicting {mechanism.upper()} results found in headers "
                            "— cannot trust either"
                        ),
                        weight=_UNINFORMATIVE_WEIGHT,
                        direction="neutral",
                    )
                )
                continue

            if mechanism not in results:
                if header_was_unparseable:
                    finding = (
                        f"Authentication-Results header present but no recognized "
                        f"{mechanism.upper()} result could be parsed from it"
                    )
                else:
                    finding = f"No {mechanism.upper()} authentication result present in headers"
                items.append(
                    EvidenceItem(
                        name=f"{mechanism}_check",
                        finding=finding,
                        weight=_UNINFORMATIVE_WEIGHT,
                        direction="neutral",
                    )
                )
                continue

            result = results[mechanism]
            if result not in _RESULT_DIRECTION:
                items.append(
                    EvidenceItem(
                        name=f"{mechanism}_check",
                        finding=f"{mechanism.upper()} result {result!r} is not a recognized outcome",
                        weight=_UNINFORMATIVE_WEIGHT,
                        direction="neutral",
                    )
                )
                continue

            # [Story 9.1, AC1/AC2] DMARC-only: capture the policy strength
            # the "carries alignment+policy context" comment above has
            # always claimed but never actually read. AC4: this is purely
            # descriptive text appended to the finding string -- weight and
            # direction on the line below are computed exactly as before,
            # untouched by the policy value.
            finding = f"{mechanism.upper()} authentication result: {result}"
            if mechanism == "dmarc":
                # header_was_provided (checked above, this branch is only
                # reachable when it was True) already narrowed
                # auth_results_header to non-None inside that block; mypy
                # can't carry that narrowing across the loop, so assert it
                # again here rather than re-litigate it silently.
                assert auth_results_header is not None
                finding += _dmarc_policy_suffix(auth_results_header, result)

            items.append(
                EvidenceItem(
                    name=f"{mechanism}_check",
                    finding=finding,
                    weight=_weight_for(mechanism, result),
                    direction=_RESULT_DIRECTION[result],
                )
            )
        return items
    except Exception as e:
        return [
            EvidenceItem(
                name="header_auth_check",
                finding=f"Header authentication check failed unexpectedly: {type(e).__name__}",
                weight=0.0,
                direction="neutral",
            )
        ]
