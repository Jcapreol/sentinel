import httpx
from pytest_mock import MockerFixture

from sentinel.cipher import CipherAgent
from sentinel.config import Config
from sentinel.verdict import SentinelAgent


def test_cipher_success(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 2}
            }
        }
    }

    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {
        "data": {"abuseConfidenceScore": 87, "totalReports": 12}
    }

    mock_client.get.side_effect = [vt_response, ab_response]

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["source_name"] == "cipher"
    assert result["error"] is None
    assert result["blind_spots"] == []
    assert len(result["findings"]) == 2


def test_cipher_no_ioc_returns_structured_null(fake_config: Config) -> None:
    agent = CipherAgent(config=fake_config)
    result = agent.analyze("Authentication failure for admin from internal system")

    assert result["error"] is None
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert "not applicable" in result["blind_spots"][0]["reason"]


def test_cipher_rate_limit_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    mock_429 = mocker.MagicMock()
    mock_429.status_code = 429
    mock_client.get.return_value = mock_429

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "rate_limited"
    assert result["findings"] == []
    assert len(result["blind_spots"]) >= 1
    assert any("rate limit" in bs["reason"].lower() for bs in result["blind_spots"])


def test_cipher_timeout_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    mock_client.get.side_effect = httpx.ReadTimeout("timed out")

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "timeout"
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["source"] == "cipher"


def test_cipher_generic_exception_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    mock_client.get.side_effect = httpx.ConnectError("connection refused")

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] is not None
    assert result["findings"] == []
    assert len(result["blind_spots"]) >= 1


def test_cipher_satisfies_sentinel_agent_protocol(
    mocker: MockerFixture, fake_config: Config
) -> None:
    mocker.patch("sentinel.cipher.httpx.Client")
    agent: SentinelAgent = CipherAgent(config=fake_config)
    assert callable(getattr(agent, "analyze", None))
