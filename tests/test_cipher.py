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


# --- URLhaus tests ---


def test_cipher_urlhaus_hit_adds_finding(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}
    }
    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
    uh_response = mocker.MagicMock()
    uh_response.status_code = 200
    uh_response.json.return_value = {"query_status": "ok", "url_count": 3}

    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.return_value = uh_response

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] is None
    assert any("URLhaus" in f for f in result["findings"])
    assert any("3" in f for f in result["findings"])
    # POST was called with the expected indicator
    mock_client.post.assert_called_once()
    call_kwargs = mock_client.post.call_args
    assert call_kwargs.kwargs["data"]["host"] == "185.220.101.45"


def test_cipher_urlhaus_miss_is_no_data_not_clean(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """no_results must not add a finding OR a blind spot — absence is not exonerating."""
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}
    }
    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
    uh_response = mocker.MagicMock()
    uh_response.status_code = 200
    uh_response.json.return_value = {"query_status": "no_results"}

    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.return_value = uh_response

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] is None
    assert not any("URLhaus" in f for f in result["findings"])
    assert not any(bs["source"] == "urlhaus" for bs in result["blind_spots"])


def test_cipher_urlhaus_failure_adds_blind_spot(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}
    }
    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}

    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.side_effect = httpx.ConnectError("connection refused")

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert not any("URLhaus" in f for f in result["findings"])
    assert any(bs["source"] == "urlhaus" for bs in result["blind_spots"])


# --- Domain path tests ---


def test_cipher_bare_domain_vt_lookup(mocker: MockerFixture, fake_config: Config) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 3, "suspicious": 1}
            }
        }
    }
    mock_client.get.return_value = vt_response

    agent = CipherAgent(config=fake_config)
    result = agent.analyze("Phishing email links to malware.example.com — user clicked")

    assert result["source_name"] == "cipher"
    assert result["error"] is None
    assert len(result["findings"]) == 1
    assert "malware.example.com" in result["findings"][0]
    assert "VirusTotal" in result["findings"][0]
    # AbuseIPDB is IP-only — must appear as a blind spot
    assert any(bs["source"] == "abuseipdb" for bs in result["blind_spots"])
    assert any("domain" in bs["reason"].lower() for bs in result["blind_spots"])


def test_cipher_domain_extracted_from_url(mocker: MockerFixture, fake_config: Config) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 7, "suspicious": 0}
            }
        }
    }
    mock_client.get.return_value = vt_response

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(
        "User navigated to https://phishing.attacker.org/steal/creds.html"
    )

    assert result["error"] is None
    assert len(result["findings"]) == 1
    assert "phishing.attacker.org" in result["findings"][0]


def test_cipher_domain_rate_limit_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    mock_429 = mocker.MagicMock()
    mock_429.status_code = 429
    mock_client.get.return_value = mock_429

    agent = CipherAgent(config=fake_config)
    # Private IP excluded → falls into domain branch for evil.example.net
    result = agent.analyze("DNS query to evil.example.net observed from 10.0.0.5")

    assert result["error"] == "rate_limited"
    assert result["findings"] == []
    assert any("rate limit" in bs["reason"].lower() for bs in result["blind_spots"])
    assert any(bs["source"] == "abuseipdb" for bs in result["blind_spots"])


def test_cipher_domain_vt_failure_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    mock_client.get.side_effect = httpx.ConnectError("connection refused")

    agent = CipherAgent(config=fake_config)
    result = agent.analyze("C2 beacon to command.evil.net port 443")

    assert result["error"] is not None
    assert result["findings"] == []
    assert any(bs["source"] == "virustotal" for bs in result["blind_spots"])


def test_cipher_ip_takes_precedence_over_domain(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """Public IP present → IP path fires; domain path is not reached."""
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}}
    }
    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {
        "data": {"abuseConfidenceScore": 50, "totalReports": 3}
    }
    mock_client.get.side_effect = [vt_response, ab_response]

    agent = CipherAgent(config=fake_config)
    # sample_alert contains a public IP — domain path must not fire
    result = agent.analyze(sample_alert + " see also tracker.evil.org")

    assert result["error"] is None
    # IP path produces exactly 2 findings (VT + AbuseIPDB), not the domain VT-only 1
    assert len(result["findings"]) == 2
    assert all("185.220.101.45" in f for f in result["findings"])
