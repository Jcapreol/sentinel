"""Canonical JSON triage report and derived Markdown rendering.

The JSON report is the single source of truth; Markdown is always generated
fresh from it at read time, never stored as a separate artifact.
"""

from typing import Literal, TypedDict

from sentinel.triage.evidence import EvidenceItem


class TriageReport(TypedDict):
    verdict: Literal["Malicious", "Benign", "Deferred"]
    calibrated_confidence: float  # PROVISIONAL: this is the raw, uncalibrated score from
    # compute_raw_score(), not real calibrated confidence. Epic 3's calibration harness
    # (Story 3.2) does not exist yet. Replace this assignment when it does.
    evidence: list[EvidenceItem]
    schema_version: int
    message_hash: str
    timestamp: str


def render_markdown(report: TriageReport) -> str:
    lines = [f"# Triage Report — {report['verdict']}"]

    if report["verdict"] == "Deferred":
        lines.append("")
        lines.append(
            f"Coverage gap — evidence was insufficient for a confident verdict "
            f"(raw score: {report['calibrated_confidence']:.3f})."
        )

    lines.append("")
    lines.append("## Evidence")
    for item in report["evidence"]:
        if item["direction"] == "neutral":
            lines.append(f"- Coverage gap — {item['finding']}")
        else:
            lines.append(
                f"- [{item['direction']}] {item['name']}: {item['finding']} "
                f"(weight={item['weight']})"
            )

    return "\n".join(lines)
