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


def _weight_for(mechanism: str, result: str) -> float:
    if result == "pass":
        return _MECHANISM_PASS_WEIGHT[mechanism]
    if result == "fail":
        return _MECHANISM_FAIL_WEIGHT[mechanism]
    return _RESULT_WEIGHT[result]


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

            items.append(
                EvidenceItem(
                    name=f"{mechanism}_check",
                    finding=f"{mechanism.upper()} authentication result: {result}",
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
