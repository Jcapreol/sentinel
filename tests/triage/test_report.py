import json
from collections.abc import Callable

from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.report import TriageReport, render_markdown


def _make_report(
    verdict: str = "Malicious",
    calibrated_confidence: float | None = 0.8,
    evidence: list[EvidenceItem] | None = None,
    coverage_gap_reason: str | None = None,
) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[typeddict-item]
        calibrated_confidence=calibrated_confidence,
        evidence=evidence if evidence is not None else [],
        schema_version=1,
        message_hash="abc123",
        timestamp="2026-07-22T00:00:00+00:00",
        coverage_gap_reason=coverage_gap_reason,
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


def test_render_markdown_renders_coverage_gap_verdict_without_confidence() -> None:
    """[Story 6.1] A CoverageGap report has no calibrated_confidence at all
    (None) -- render_markdown must not try to format it as a float (the
    pre-existing Deferred branch does exactly that and would crash on
    None), and must surface coverage_gap_reason instead."""
    report = _make_report(
        verdict="CoverageGap",
        calibrated_confidence=None,
        evidence=[],
        coverage_gap_reason="Failed to fetch raw message content: HttpError 404",
    )

    output = render_markdown(report)

    # Unlike the general evidence-rendering "never say Error" convention
    # tested below (which guards against internal exception noise leaking
    # into ordinary findings), a CoverageGap record's whole point IS to
    # transparently explain what fetch failure occurred -- "HttpError 404"
    # appearing here is the correct, intended behavior, not a leak.
    assert "Coverage gap —" in output
    assert "Failed to fetch raw message content: HttpError 404" in output
    assert "None" not in output  # no str(None) leakage from the missing confidence


def test_render_markdown_coverage_gap_with_empty_evidence_does_not_crash() -> None:
    """A CoverageGap record's evidence is genuinely [] -- the evidence
    section must render something sensible, not an empty/blank list."""
    report = _make_report(verdict="CoverageGap", calibrated_confidence=None, evidence=[])

    output = render_markdown(report)

    assert "## Evidence" in output
    assert "none" in output.lower()


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
