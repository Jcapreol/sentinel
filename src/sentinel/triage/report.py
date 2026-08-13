"""Canonical JSON triage report and derived Markdown rendering.

The JSON report is the single source of truth; Markdown is always generated
fresh from it at read time, never stored as a separate artifact.
"""

from typing import Literal, TypedDict

from sentinel.triage.evidence import EvidenceItem


class TriageReport(TypedDict):
    # [Story 6.1] "CoverageGap" is structurally distinct from "Deferred":
    # Deferred means analysis ran and genuinely couldn't reach a confident
    # verdict (real evidence, real raw_score, just uncertain). CoverageGap
    # means no analysis happened at all -- the message itself could not be
    # fetched (Gmail 404, "Requested entity was not found", meaning it was
    # deleted or moved out of the mailbox between the list call and the
    # fetch call). Before this story, that case was misreported as
    # Deferred at the neutral midpoint (0.5) -- indistinguishable from a
    # genuine uncertain judgment, which silently polluted calibration
    # metrics with entries that were never real predictions. Name aligns
    # with this project's existing "coverage gap" log/finding vocabulary
    # (worker.py's raw-fetch-failure log line and header_fetch EvidenceItem
    # finding text both already used this exact term before this state
    # existed to express it).
    verdict: Literal["Malicious", "Benign", "Deferred", "CoverageGap"]
    # [Review][Patch] Story 3.2's calibration harness now exists: worker.py
    # assigns apply_calibration(raw_score), not the raw score itself, here.
    # Numerically the two are still equal today only because the shipped
    # calibration_model_v1.json is an explicit "identity" placeholder (see
    # that file and scoring.py's apply_calibration) -- not because this
    # field is still a raw-score stand-in.
    #
    # [Story 6.1] None if and only if verdict == "CoverageGap" -- there is
    # no raw_score to calibrate when no analysis ever ran, so there is
    # nothing to put here. Every other verdict always carries a real float.
    calibrated_confidence: float | None
    # [Story 6.1] Genuinely empty ([]) if and only if verdict ==
    # "CoverageGap" -- not a placeholder single item describing the
    # failure (that lived here before this story; see coverage_gap_reason
    # below for where the description moved). An empty list is the more
    # honest representation of "nothing was analyzed," and makes "no code
    # path emits confidence 0.500 with empty evidence" true by
    # construction: the only path that can produce empty evidence
    # (CoverageGap) never has confidence 0.5, and every path that can
    # produce confidence 0.5 (the two structural-deferral gates in
    # worker.py's check_structural_deferral) always has real, non-empty
    # evidence -- investigate_header_authentication alone always
    # contributes at least one EvidenceItem per SPF/DKIM/DMARC mechanism,
    # header data present or not.
    evidence: list[EvidenceItem]
    schema_version: int
    # [Story 6.1] Always a genuine SHA-256 of the message's raw content --
    # EXCEPT for verdict == "CoverageGap", where it is instead
    # hashlib.sha256(message_id.encode()).hexdigest(): an identifier-based
    # hash, not a tamper-evidence hash, because the raw content was never
    # fetched and there is nothing to hash. This is an explicit, expected
    # property of a CoverageGap record, not a degraded/error condition --
    # verdict == "CoverageGap" is itself the complete, sufficient signal
    # for which kind of hash this is; no separate field encodes it, since
    # that would just duplicate what verdict already says unambiguously.
    # Still safe as a SQLite PRIMARY KEY (evidence_records.message_hash):
    # collision-resistant and stable across replays regardless of basis.
    message_hash: str
    timestamp: str
    # [Story 6.1] Short, human-readable explanation of why this is a
    # CoverageGap record (e.g. "Failed to fetch raw message content:
    # HttpError 404 ..."), replacing the diagnostic detail that used to
    # live inside a synthetic EvidenceItem's finding text before evidence
    # became genuinely empty for this state. None for every other verdict.
    # A REQUIRED key on every freshly-constructed TriageReport (so a
    # construction site can never silently forget to set it either way),
    # but a record loaded from disk that predates this story's schema
    # change won't have this key in its stored JSON at all -- readers of
    # POSSIBLY-OLD persisted data must use .get("coverage_gap_reason")
    # defensively, never report["coverage_gap_reason"] directly, mirroring
    # this codebase's existing precedent for EvidenceRecord's
    # deferral_threshold_used field (see worker.py's _run_replay). Old
    # records can never have verdict == "CoverageGap" in the first place
    # (that value didn't exist when they were written), so this only
    # matters for code that reads the field unconditionally regardless of
    # verdict, e.g. --view's table rendering.
    coverage_gap_reason: str | None


def render_markdown(report: TriageReport) -> str:
    lines = [f"# Triage Report — {report['verdict']}"]

    if report["verdict"] == "CoverageGap":
        lines.append("")
        # .get(): see coverage_gap_reason's TriageReport docstring -- this
        # function's report argument could in principle be a loaded record.
        reason = report.get("coverage_gap_reason") or "message unavailable at ingest time"
        lines.append(f"Coverage gap — {reason}. No analysis was performed; there is no verdict.")
    elif report["verdict"] == "Deferred":
        lines.append("")
        lines.append(
            f"Coverage gap — evidence was insufficient for a confident verdict "
            f"(calibrated confidence: {report['calibrated_confidence']:.3f})."
        )

    lines.append("")
    lines.append("## Evidence")
    if not report["evidence"]:
        lines.append("- (none — no analysis was performed for this record)")
    for item in report["evidence"]:
        if item["direction"] == "neutral":
            lines.append(f"- Coverage gap — {item['finding']}")
        else:
            lines.append(
                f"- [{item['direction']}] {item['name']}: {item['finding']} "
                f"(weight={item['weight']})"
            )

    return "\n".join(lines)
