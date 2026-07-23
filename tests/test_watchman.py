import anthropic
from pytest_mock import MockerFixture

from sentinel.config import Config
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
        assert item["weight"] == 0.5  # _CONFIDENCE_WEIGHT["Probable"]


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
