import json
import re

import anthropic

from sentinel.config import Config
from sentinel.triage.evidence import EvidenceItem
from sentinel.verdict import AgentResult, BlindSpot

_MODEL = "claude-haiku-4-5-20251001"

# PROVISIONAL PRIORS, not calibrated values — Watchman's raw_confidence
# tier ("Investigating"/"Probable"/"Confirmed") is a categorical LLM
# self-assessment, not a measured probability. Mapping it to empirical
# outcome frequency is Epic 3's job (Story 3.2's calibration harness);
# expect these exact numbers to be revisited once that runs against
# real data. Watchman's prompt only ever asks it to assess indicators
# OF COMPROMISE — it has no mechanism to assert "benign" — so every
# finding-derived EvidenceItem below uses direction="malicious", never
# "benign". This is a real, permanent asymmetry versus headers.py
# (which can assert benign via an SPF/DKIM/DMARC pass), not a gap.
_CONFIDENCE_WEIGHT: dict[str, float] = {
    "Confirmed": 0.7,
    "Probable": 0.5,
    "Investigating": 0.3,
}

# scoring.compute_raw_score does NOT exclude neutral-direction items from its
# calculation: every item's weight is added to total_weight (the
# denominator), regardless of direction -- only malicious/benign items add
# to signed_sum (the numerator). A neutral item therefore contributes 0.0 to
# the numerator but still inflates the denominator, which DAMPS/DILUTES the
# final normalized score toward the neutral prior (0.5), proportional to its
# weight. This is the same mechanism headers.py's own _UNINFORMATIVE_WEIGHT
# relies on ("must stay non-zero so sparse evidence damps toward uncertainty
# ... instead of railing a single weak signal to a certain 0.0 or 1.0
# score") -- so the weight value chosen here is NOT cosmetic, it has a real,
# non-zero effect on every other item's contribution to the final score.
# 0.10 mirrors headers.py's own _UNINFORMATIVE_WEIGHT constant exactly (same
# rationale, same value) rather than being independently chosen.
#
# weight=0.0 is used elsewhere in this file (empty findings; all three
# error/coverage-gap paths in analyze()) specifically because those cases
# have NO signal at all -- 0.0 added to total_weight changes nothing, so
# those items are mathematically invisible to compute_raw_score, present in
# the evidence list only for audit visibility. 0.10 here is deliberately
# different: confidence-tier-unrecognized findings DID flag something, just
# without a confident weight to assign it, so they should damp the rest of
# the evidence rather than vanish entirely.
_UNINFORMATIVE_WEIGHT = 0.10

_SYSTEM = (
    "You are a security analysis tool. "
    "You MUST respond with raw JSON only — no markdown, no code fences, no explanatory text. "
    "Your entire response must be a single JSON object parseable by json.loads()."
)

_PROMPT_TEMPLATE = """\
Analyze the following security alert for behavioral indicators of compromise.

Respond with this exact JSON structure and nothing else — no markdown, no code fences:
{{"findings": ["<specific behavioral finding>", "<another finding>"], "confidence": "<Investigating|Probable|Confirmed>", "mitre_tags": ["T1003", "T1071"]}}

In "mitre_tags", include relevant MITRE ATT&CK technique IDs. Leave the array empty if none apply.

Alert: {alert}"""


def _build_evidence(findings: list[str], confidence: str | None) -> list[EvidenceItem]:
    """Success-path evidence construction. Mirrors headers.py's discipline of
    always emitting at least one EvidenceItem documenting what was checked,
    never silently omitting -- the absence of a finding is itself auditable
    evidence, distinct from a coverage gap (see the error-path handling in
    analyze(), which uses weight=0.0 for genuine gaps rather than this
    function's neutral/uninformative fallback)."""
    if not findings:
        # weight=0.0: no signal at all, so this item is mathematically
        # invisible to compute_raw_score (see the _UNINFORMATIVE_WEIGHT
        # comment above for why this differs from the 0.10 fallback below).
        return [
            EvidenceItem(
                name="watchman_analysis",
                finding="Watchman completed analysis; no behavioral indicators of compromise found",
                weight=0.0,
                direction="neutral",
            )
        ]
    weight = _CONFIDENCE_WEIGHT.get(confidence) if confidence is not None else None
    if weight is None:
        # confidence missing or not one of the three values the prompt
        # instructs Claude to always use -- defensive fallback for
        # prompt-instruction drift, mirrors headers.py's own "recognized
        # signal present but the result keyword itself is unrecognized"
        # pattern: neutral, damped, never assumed malicious without a
        # valid confidence signal backing it.
        return [
            EvidenceItem(
                name="watchman_finding",
                finding=finding,
                weight=_UNINFORMATIVE_WEIGHT,
                direction="neutral",
            )
            for finding in findings
        ]
    return [
        EvidenceItem(name="watchman_finding", finding=finding, weight=weight, direction="malicious")
        for finding in findings
    ]


class WatchmanAgent:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._client = anthropic.Anthropic(
            api_key=config.anthropic_api_key,
            timeout=config.timeout_seconds,
        )

    def analyze(self, input_data: str) -> AgentResult:
        try:
            response = self._client.messages.create(
                model=_MODEL,
                max_tokens=1024,
                system=_SYSTEM,
                messages=[
                    {
                        "role": "user",
                        "content": _PROMPT_TEMPLATE.format(alert=input_data),
                    }
                ],
            )
            raw_text: str = response.content[0].text  # type: ignore[union-attr]
            # Strip markdown code fences Claude sometimes adds despite instructions
            cleaned = re.sub(r"```(?:json)?\s*\n?", "", raw_text.strip())
            cleaned = re.sub(r"```\s*", "", cleaned).strip()
            parsed = json.loads(cleaned)
            findings: list[str] = parsed.get("findings") or []
            confidence: str | None = parsed.get("confidence")
            raw_tags = parsed.get("mitre_tags")
            mitre_tags: list[str] = raw_tags if isinstance(raw_tags, list) else []
            if not isinstance(findings, list):
                raise ValueError("findings must be a list")
            return AgentResult(
                source_name="watchman",
                findings=findings,
                blind_spots=[],
                raw_confidence=confidence,
                error=None,
                mitre_tags=mitre_tags,
                evidence=_build_evidence(findings, confidence),
            )
        # All three except blocks below use weight=0.0 for the same reason as
        # the empty-findings case in _build_evidence: total coverage gap, no
        # signal at all, mathematically invisible to compute_raw_score (see
        # the _UNINFORMATIVE_WEIGHT comment above for the contrast with the
        # deliberately-nonzero 0.10 fallback).
        except anthropic.APITimeoutError:
            reason = "Watchman timed out — behavioral analysis unavailable"
            return AgentResult(
                source_name="watchman",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="watchman",
                        reason=reason,
                        next_step="Retry when Anthropic API is available or increase SENTINEL_TIMEOUT",
                    )
                ],
                raw_confidence=None,
                error="timeout",
                evidence=[
                    EvidenceItem(name="watchman_analysis", finding=reason, weight=0.0, direction="neutral")
                ],
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            reason = "Watchman output malformed — behavioral analysis unavailable"
            return AgentResult(
                source_name="watchman",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="watchman",
                        reason=reason,
                        next_step=None,
                    )
                ],
                raw_confidence=None,
                error="malformed_output",
                evidence=[
                    EvidenceItem(name="watchman_analysis", finding=reason, weight=0.0, direction="neutral")
                ],
            )
        except Exception:
            reason = "Watchman analysis failed — behavioral analysis unavailable"
            return AgentResult(
                source_name="watchman",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="watchman",
                        reason=reason,
                        next_step=None,
                    )
                ],
                raw_confidence=None,
                error="analysis_failed",
                evidence=[
                    EvidenceItem(name="watchman_analysis", finding=reason, weight=0.0, direction="neutral")
                ],
            )
