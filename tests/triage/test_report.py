import json
from collections.abc import Callable

from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.report import TriageReport, render_markdown


def _make_report(
    verdict: str = "Malicious",
    calibrated_confidence: float = 0.8,
    evidence: list[EvidenceItem] | None = None,
) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[typeddict-item]
        calibrated_confidence=calibrated_confidence,
        evidence=evidence if evidence is not None else [],
        schema_version=1,
        message_hash="abc123",
        timestamp="2026-07-22T00:00:00+00:00",
    )


def test_triage_report_round_trips_through_json(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    report = _make_report(
        evidence=[make_evidence_item(name="spf", finding="spf=fail", direction="malicious")]
    )

    serialized = json.dumps(report)
    deserialized = json.loads(serialized)

    assert deserialized == report


def test_render_markdown_uses_coverage_gap_for_neutral_evidence(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    report = _make_report(
        verdict="Benign",
        evidence=[
            make_evidence_item(name="spf", finding="header missing", direction="neutral"),
        ],
    )

    output = render_markdown(report)

    assert "Coverage gap —" in output
    assert "Error" not in output


def test_render_markdown_uses_coverage_gap_for_deferred_verdict(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    report = _make_report(verdict="Deferred", calibrated_confidence=0.51)

    output = render_markdown(report)

    assert "Coverage gap —" in output
    assert "Error" not in output


def test_render_markdown_never_contains_the_word_error(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    report = _make_report(
        verdict="Malicious",
        evidence=[
            make_evidence_item(name="spf", finding="spf=fail", direction="malicious"),
            make_evidence_item(name="dkim", finding="dkim missing", direction="neutral"),
        ],
    )

    output = render_markdown(report)

    assert "Error" not in output


def test_render_markdown_is_deterministic_across_calls(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    report = _make_report(
        evidence=[make_evidence_item(name="spf", finding="spf=fail", direction="malicious")]
    )

    first = render_markdown(report)
    second = render_markdown(report)

    assert first == second
