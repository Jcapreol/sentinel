import json
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, TypedDict

from sentinel.triage.evidence import EvidenceItem


class BlindSpot(TypedDict):
    source: str
    reason: str
    next_step: str | None


class _AgentResultRequired(TypedDict):
    source_name: str
    findings: list[str]
    blind_spots: list[BlindSpot]
    raw_confidence: str | None
    error: str | None


class AgentResult(_AgentResultRequired, total=False):
    mitre_tags: list[str]
    evidence: list[EvidenceItem]


# [2026-08-06] Lives here (the foundation layer, per project-context.md's
# documented import hierarchy: verdict.py -> confidence.py -> main.py ->
# web/) specifically so confidence.py's severity classification AND this
# module's own status labeling can share ONE evaluation of "does this
# result actually show a real threat" -- confidence.py already depends on
# verdict.py (imports AgentResult), so verdict.py cannot import back from
# confidence.py without a cycle. Duplicating this regex match independently
# in each caller is exactly what let evidence_chain's/methodology's status
# field silently disagree with the confidence tier before this fix.
_VT_MALICIOUS_RE = re.compile(r"VirusTotal:.*flagged by (\d+) engines as malicious")
_ABUSE_SCORE_RE = re.compile(r"AbuseIPDB:.*abuse confidence (\d+)%")
_ABUSE_MALICIOUS_THRESHOLD = 25


def cipher_findings_show_malicious(findings: list[str]) -> bool:
    """True if any finding string matches Cipher's VT-engines-flagged or
    AbuseIPDB-score-over-threshold pattern. Known gap, pre-existing: a
    URLhaus-only finding never matches either pattern, so a real URLhaus
    hit is not recognized as malicious here."""
    for finding in findings:
        m = _VT_MALICIOUS_RE.search(finding)
        if m and int(m.group(1)) > 0:
            return True
        m = _ABUSE_SCORE_RE.search(finding)
        if m and int(m.group(1)) >= _ABUSE_MALICIOUS_THRESHOLD:
            return True
    return False


def cipher_agent_status(result: AgentResult) -> Literal["success", "partial", "error"]:
    """Display status label for Cipher's entry in methodology/evidence_chain,
    consistent with confidence.py's _parse_cipher_severity's own error-vs-
    findings handling (2026-08-06). AgentResult.error itself is untouched by
    this -- purely a richer status LABEL for display, not a redefinition of
    what `error` means.

    "success" — no error.
    "partial" — error is set, but a real malicious finding survived from a
                DIFFERENT sub-lookup that completed before the error
                occurred (cipher.py only ever appends a finding after a
                full, successfully-parsed response, and a finding's own
                append and its sub-lookup's error path are mutually
                exclusive -- see cipher.py's per-sub-lookup try/except
                structure). A real threat signal alongside a degraded
                check must never display as a plain "error".
    "error"   — error is set and no malicious finding survived -- matches
                _parse_cipher_severity's own "no_data" classification for
                this same input. Not used for Watchman: its own severity
                parsing (_parse_watchman_severity) treats any error as
                no_data regardless of findings, so its status stays a
                simple error/success binary, computed inline where it's
                used rather than through this Cipher-specific function.
    """
    if result["error"] is None:
        return "success"
    return "partial" if cipher_findings_show_malicious(result["findings"]) else "error"


class _VerdictSchemaRequired(TypedDict):
    verdict: str
    confidence_tier: int
    methodology: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    blind_spots: list[BlindSpot]
    source_independence_confirmed: bool
    execution_time_seconds: float
    timestamp: str


class VerdictSchema(_VerdictSchemaRequired, total=False):
    incident_report: dict[str, Any]


class SentinelAgent(Protocol):
    def analyze(self, input_data: str) -> AgentResult: ...


def assemble_verdict(
    watchman_result: AgentResult,
    cipher_result: AgentResult,
    tier: tuple[int, str],
    source_independence_confirmed: bool,
    start_time: float,
) -> VerdictSchema:
    tier_int, tier_str = tier
    results = [watchman_result, cipher_result]
    # [2026-08-06] Watchman's status stays a plain error/success binary
    # (its own severity parsing treats any error as no_data regardless of
    # findings, so there's no "partial" case to distinguish for it).
    # Cipher's status goes through cipher_agent_status specifically, so a
    # real malicious finding surviving a partial error reads as "partial",
    # not a plain "error" that would contradict the confidence tier it also
    # now drives (see cipher_agent_status's own docstring).
    methodology: list[dict[str, Any]] = [
        {
            "agent": r["source_name"],
            "status": (
                cipher_agent_status(r)
                if r["source_name"] == "cipher"
                else ("error" if r["error"] else "success")
            ),
            "error": r["error"],
        }
        for r in results
    ]
    citations: list[dict[str, Any]] = [
        {"source": r["source_name"], "finding": finding}
        for r in results
        for finding in r["findings"]
    ]
    blind_spots: list[BlindSpot] = [bs for r in results for bs in r["blind_spots"]]
    return VerdictSchema(
        verdict=tier_str,
        confidence_tier=tier_int,
        methodology=methodology,
        citations=citations,
        blind_spots=blind_spots,
        source_independence_confirmed=source_independence_confirmed,
        execution_time_seconds=round(time.time() - start_time, 3),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def print_verdict(verdict: VerdictSchema) -> None:
    print(json.dumps(verdict, indent=2), file=sys.stdout)
