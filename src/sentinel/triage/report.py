"""Canonical JSON triage report and derived Markdown rendering.

The JSON report is the single source of truth; Markdown is always generated
fresh from it at read time, never stored as a separate artifact.
"""

from typing import Literal, TypedDict

from sentinel.triage.evidence import EvidenceItem


class TriageReport(TypedDict):
    verdict: Literal["Malicious", "Benign", "Deferred"]
    # [Review][Patch] Story 3.2's calibration harness now exists: worker.py
    # assigns apply_calibration(raw_score), not the raw score itself, here.
    # Numerically the two are still equal today only because the shipped
    # calibration_model_v1.json is an explicit "identity" placeholder (see
    # that file and scoring.py's apply_calibration) -- not because this
    # field is still a raw-score stand-in.
    calibrated_confidence: float
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
            f"(calibrated confidence: {report['calibrated_confidence']:.3f})."
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
