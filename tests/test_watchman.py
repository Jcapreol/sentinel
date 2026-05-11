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


def test_watchman_satisfies_sentinel_agent_protocol(
    mocker: MockerFixture, fake_config: Config
) -> None:
    mocker.patch("sentinel.watchman.anthropic.Anthropic")
    agent: SentinelAgent = WatchmanAgent(config=fake_config)
    assert callable(getattr(agent, "analyze", None))
