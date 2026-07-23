import anthropic
import pytest
from pytest_mock import MockerFixture

from sentinel.config import Config
from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.scoring import compute_raw_score
from sentinel.verdict import SentinelAgent
from sentinel.watchman import WatchmanAgent


def test_watchman_success(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_response = mocker.MagicMock()
    mock_response.content[0].text = (
        '{"findings": ["Suspicious outbound connection to known Tor exit node",'
        ' "High-volume data transfer on port 443"], "confidence": "Probable"}'
    )
    mock_anthropic.return_value.messages.create.return_value = mock_response

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["source_name"] == "watchman"
    assert result["error"] is None
    assert result["blind_spots"] == []
    assert len(result["findings"]) > 0
    assert result["raw_confidence"] == "Probable"
    # 2026-07-22, Story 2.1: one EvidenceItem per finding, not one aggregate item.
    assert len(result["evidence"]) == 2
    for item, finding_text in zip(result["evidence"], result["findings"], strict=True):
        assert item["name"] == "watchman_finding"
        assert item["finding"] == finding_text
        assert item["direction"] == "malicious"
        # 2026-07-23, Story 2.2: weight-averaged per finding (tier_weight / len(findings))
        # to fix the correlated-evidence score inflation deferred from Story 2.1's review.
        assert item["weight"] == 0.25  # _CONFIDENCE_WEIGHT["Probable"] (0.5) / 2 findings


def test_watchman_correlated_evidence_weight_averaging_fixes_score_inflation(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """Deferred from Story 2.1's code review (see deferred-work.md): N findings
    from ONE Watchman inference must not inflate its influence on
    compute_raw_score proportional to finding-count. Reproduces the exact
    worked example from deferred-work.md -- 5 findings at "Confirmed"
    (weight=0.7 each pre-fix) combined with one weight=0.45/benign header item
    produced ~0.886 pre-fix vs ~0.609 for the same signal collapsed to 1
    finding. Post-fix, both must produce the same score."""
    header_evidence = [
        EvidenceItem(name="dmarc_check", finding="DMARC pass", weight=0.45, direction="benign")
    ]

    def _watchman_evidence(num_findings: int) -> list[EvidenceItem]:
        findings_json = ", ".join(f'"Finding {i}"' for i in range(num_findings))
        mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
        mock_response = mocker.MagicMock()
        mock_response.content[0].text = (
            f'{{"findings": [{findings_json}], "confidence": "Confirmed"}}'
        )
        mock_anthropic.return_value.messages.create.return_value = mock_response
        agent = WatchmanAgent(config=fake_config)
        result = agent.analyze(sample_alert)
        return result["evidence"]

    score_one_finding = compute_raw_score(header_evidence + _watchman_evidence(1))
    score_five_findings = compute_raw_score(header_evidence + _watchman_evidence(5))

    assert score_one_finding == pytest.approx(score_five_findings, abs=1e-9)
    assert score_one_finding == pytest.approx(0.609, abs=0.01)


def test_watchman_unrecognized_confidence_yields_neutral_uninformative_evidence(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """The prompt instructs Claude to always emit one of
    Investigating|Probable|Confirmed, but this is a defensive fallback for
    prompt-instruction drift -- an unrecognized confidence value must not be
    silently treated as malicious without a valid signal backing it."""
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_response = mocker.MagicMock()
    mock_response.content[0].text = (
        '{"findings": ["Unusual login time"], "confidence": "High"}'
    )
    mock_anthropic.return_value.messages.create.return_value = mock_response

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["direction"] == "neutral"
    assert result["evidence"][0]["weight"] == 0.10
    assert result["evidence"][0]["finding"] == "Unusual login time"


def test_watchman_unhashable_confidence_does_not_crash(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """A malformed but valid-JSON response where "confidence" is a list/dict
    (not a str) must not crash _CONFIDENCE_WEIGHT.get(confidence) with
    TypeError: unhashable type -- it must be treated the same as any other
    unrecognized confidence value (neutral/uninformative), not misreported
    as error="analysis_failed"."""
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_response = mocker.MagicMock()
    mock_response.content[0].text = (
        '{"findings": ["Unusual login time"], "confidence": ["High"]}'
    )
    mock_anthropic.return_value.messages.create.return_value = mock_response

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] is None
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["direction"] == "neutral"
    assert result["evidence"][0]["weight"] == 0.10
    assert result["evidence"][0]["finding"] == "Unusual login time"


def test_watchman_non_string_finding_elements_are_filtered_out(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """The prompt instructs Claude to emit a findings array of strings, but
    only the outer list type is validated at runtime. A non-string element
    (e.g. a nested object) must not flow into EvidenceItem.finding (typed
    str) or AgentResult.findings (typed list[str])."""
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_response = mocker.MagicMock()
    mock_response.content[0].text = (
        '{"findings": ["Unusual login time", {"nested": "object"}, 42],'
        ' "confidence": "Probable"}'
    )
    mock_anthropic.return_value.messages.create.return_value = mock_response

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["findings"] == ["Unusual login time"]
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["finding"] == "Unusual login time"


def test_watchman_empty_and_whitespace_only_findings_are_filtered_out(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """2026-07-23 code-review patch: the isinstance(f, str) filter excludes
    non-string types but not empty/whitespace-only strings, which would
    still count toward len(findings) in the weight-averaging division,
    diluting a genuinely malicious finding's weight for free."""
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_response = mocker.MagicMock()
    mock_response.content[0].text = (
        '{"findings": ["Unusual login time", "", "   "], "confidence": "Probable"}'
    )
    mock_anthropic.return_value.messages.create.return_value = mock_response

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["findings"] == ["Unusual login time"]
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["weight"] == 0.5  # not diluted by the 2 blank entries


def test_watchman_empty_findings_yields_single_neutral_evidence_item(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """A completed analysis that legitimately found nothing is not a coverage
    gap -- it must still emit one auditable EvidenceItem documenting that
    Watchman ran and found nothing, distinct from a timeout/error."""
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_response = mocker.MagicMock()
    mock_response.content[0].text = '{"findings": [], "confidence": "Investigating"}'
    mock_anthropic.return_value.messages.create.return_value = mock_response

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["evidence"] == [
        {
            "name": "watchman_analysis",
            "finding": "Watchman completed analysis; no behavioral indicators of compromise found",
            "weight": 0.0,
            "direction": "neutral",
        }
    ]


def test_watchman_timeout_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_anthropic.return_value.messages.create.side_effect = (
        anthropic.APITimeoutError(request=mocker.MagicMock())
    )

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "timeout"
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["source"] == "watchman"
    assert "timed out" in result["blind_spots"][0]["reason"]
    # 2026-07-22, Story 2.1: coverage-gap EvidenceItem, same text as the BlindSpot reason.
    assert result["evidence"] == [
        {
            "name": "watchman_analysis",
            "finding": result["blind_spots"][0]["reason"],
            "weight": 0.0,
            "direction": "neutral",
        }
    ]


def test_watchman_malformed_output_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_response = mocker.MagicMock()
    mock_response.content[0].text = "Sorry, I cannot analyze this alert."
    mock_anthropic.return_value.messages.create.return_value = mock_response

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "malformed_output"
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["reason"] == (
        "Watchman output malformed — behavioral analysis unavailable"
    )
    assert result["evidence"] == [
        {
            "name": "watchman_analysis",
            "finding": result["blind_spots"][0]["reason"],
            "weight": 0.0,
            "direction": "neutral",
        }
    ]


def test_watchman_generic_exception_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_anthropic.return_value.messages.create.side_effect = (
        anthropic.APIConnectionError(request=mocker.MagicMock())
    )

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] is not None
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["source"] == "watchman"
    assert result["evidence"] == [
        {
            "name": "watchman_analysis",
            "finding": result["blind_spots"][0]["reason"],
            "weight": 0.0,
            "direction": "neutral",
        }
    ]


def test_watchman_satisfies_sentinel_agent_protocol(
    mocker: MockerFixture, fake_config: Config
) -> None:
    mocker.patch("sentinel.watchman.anthropic.Anthropic")
    agent: SentinelAgent = WatchmanAgent(config=fake_config)
    assert callable(getattr(agent, "analyze", None))
