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
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["source_name"] == "cipher"
    assert result["error"] is None
    assert result["blind_spots"] == []
    assert len(result["findings"]) == 2
    # 2026-07-23, Story 2.2: VT malicious=5 -> high-consensus tier (>=5); AbuseIPDB
    # score=87 -> high tier (>=75); URLhaus no_results -> uninformative gap item.
    assert len(result["evidence"]) == 3
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert vt_item["weight"] == 0.70
    assert vt_item["direction"] == "malicious"
    assert ab_item["weight"] == 0.65
    assert ab_item["direction"] == "malicious"
    assert uh_item["weight"] == 0.10
    assert uh_item["direction"] == "neutral"
    assert not any(i["direction"] == "benign" for i in result["evidence"])


def test_cipher_no_ioc_returns_structured_null(fake_config: Config) -> None:
    agent = CipherAgent(config=fake_config)
    result = agent.analyze("Authentication failure for admin from internal system")

    assert result["error"] is None
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert "not applicable" in result["blind_spots"][0]["reason"]
    assert result["evidence"] == [
        {
            "name": "cipher_analysis",
            "finding": result["blind_spots"][0]["reason"],
            "weight": 0.0,
            "direction": "neutral",
        }
    ]


def test_cipher_rate_limit_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    mock_429 = mocker.MagicMock()
    mock_429.status_code = 429
    mock_client.get.return_value = mock_429
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "rate_limited"
    assert result["findings"] == []
    assert len(result["blind_spots"]) >= 1
    assert any("rate limit" in bs["reason"].lower() for bs in result["blind_spots"])
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert vt_item["weight"] == 0.10
    assert vt_item["direction"] == "neutral"
    assert ab_item["weight"] == 0.10
    assert ab_item["direction"] == "neutral"


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
    assert result["evidence"] == [
        {
            "name": "cipher_analysis",
            "finding": result["blind_spots"][0]["reason"],
            "weight": 0.0,
            "direction": "neutral",
        }
    ]


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
    # sample_alert contains an IP -> _analyze_ip's own per-lookup except blocks
    # catch this (VT/AbuseIPDB), not analyze()'s outer generic-exception handler.
    vt_blind_spot = next(bs for bs in result["blind_spots"] if bs["source"] == "virustotal")
    ab_blind_spot = next(bs for bs in result["blind_spots"] if bs["source"] == "abuseipdb")
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert vt_item == {"name": "virustotal_finding", "finding": vt_blind_spot["reason"], "weight": 0.0, "direction": "neutral"}
    assert ab_item == {"name": "abuseipdb_finding", "finding": ab_blind_spot["reason"], "weight": 0.0, "direction": "neutral"}


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
    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert uh_item["weight"] == 0.60  # url_count=3 -> multi-hit tier (>=3)
    assert uh_item["direction"] == "malicious"
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert vt_item["weight"] == 0.10  # malicious=0, suspicious=0 -> uninformative
    assert vt_item["direction"] == "neutral"
    assert ab_item["weight"] == 0.10  # score=0 -> uninformative
    assert ab_item["direction"] == "neutral"


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
    # 2026-07-23, Story 2.2: a miss is still auditable evidence (neutral/uninformative),
    # even though it deliberately produces no `findings`/`blind_spots` entry (unchanged).
    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert uh_item["weight"] == 0.10
    assert uh_item["direction"] == "neutral"


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
    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert uh_item["weight"] == 0.0
    assert uh_item["direction"] == "neutral"
    urlhaus_blind_spot = next(bs for bs in result["blind_spots"] if bs["source"] == "urlhaus")
    assert uh_item["finding"] == urlhaus_blind_spot["reason"]


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
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

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
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    assert vt_item["weight"] == 0.45  # malicious=3 -> low-consensus tier (1 <= x < 5)
    assert vt_item["direction"] == "malicious"
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert ab_item["weight"] == 0.0  # domain lookup never attempted -> true gap
    assert ab_item["direction"] == "neutral"
    abuseipdb_blind_spot = next(bs for bs in result["blind_spots"] if bs["source"] == "abuseipdb")
    assert ab_item["finding"] == abuseipdb_blind_spot["reason"]


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
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(
        "User navigated to https://phishing.attacker.org/steal/creds.html"
    )

    assert result["error"] is None
    assert len(result["findings"]) == 1
    assert "phishing.attacker.org" in result["findings"][0]
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    assert vt_item["weight"] == 0.70  # malicious=7 -> high-consensus tier (>=5)
    assert vt_item["direction"] == "malicious"


def test_cipher_domain_rate_limit_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    mock_429 = mocker.MagicMock()
    mock_429.status_code = 429
    mock_client.get.return_value = mock_429
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    # Private IP excluded → falls into domain branch for evil.example.net
    result = agent.analyze("DNS query to evil.example.net observed from 10.0.0.5")

    assert result["error"] == "rate_limited"
    assert result["findings"] == []
    assert any("rate limit" in bs["reason"].lower() for bs in result["blind_spots"])
    assert any(bs["source"] == "abuseipdb" for bs in result["blind_spots"])
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    assert vt_item["weight"] == 0.10
    assert vt_item["direction"] == "neutral"


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
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    assert vt_item["weight"] == 0.0
    assert vt_item["direction"] == "neutral"
    vt_blind_spot = next(bs for bs in result["blind_spots"] if bs["source"] == "virustotal")
    assert vt_item["finding"] == vt_blind_spot["reason"]


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
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    # sample_alert contains a public IP — domain path must not fire
    result = agent.analyze(sample_alert + " see also tracker.evil.org")

    assert result["error"] is None
    # IP path produces exactly 2 findings (VT + AbuseIPDB), not the domain VT-only 1
    assert len(result["findings"]) == 2
    assert all("185.220.101.45" in f for f in result["findings"])
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert vt_item["weight"] == 0.45  # malicious=1 -> low-consensus tier
    assert ab_item["weight"] == 0.40  # score=50 -> moderate tier (25 <= x < 75)
    assert ab_item["direction"] == "malicious"


# --- Weight-tier boundary tests (Story 2.2) ---


def _ip_result(
    mocker: MockerFixture,
    fake_config: Config,
    sample_alert: str,
    malicious: int,
    suspicious: int,
    score: int,
    reports: int = 1,
) -> dict:  # type: ignore[type-arg]
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious}}}
    }
    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {"data": {"abuseConfidenceScore": score, "totalReports": reports}}
    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    return agent.analyze(sample_alert)  # type: ignore[return-value]


def test_cipher_vt_boundary_exactly_five_malicious_is_high_tier(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    result = _ip_result(mocker, fake_config, sample_alert, malicious=5, suspicious=0, score=0)
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    assert vt_item["weight"] == 0.70
    assert vt_item["direction"] == "malicious"


def test_cipher_vt_boundary_four_malicious_is_low_tier(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    result = _ip_result(mocker, fake_config, sample_alert, malicious=4, suspicious=0, score=0)
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    assert vt_item["weight"] == 0.45
    assert vt_item["direction"] == "malicious"


def test_cipher_vt_suspicious_only_is_neutral(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    result = _ip_result(mocker, fake_config, sample_alert, malicious=0, suspicious=2, score=0)
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    assert vt_item["weight"] == 0.20
    assert vt_item["direction"] == "neutral"


def test_cipher_abuseipdb_boundary_exactly_75_is_high_tier(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    result = _ip_result(mocker, fake_config, sample_alert, malicious=0, suspicious=0, score=75)
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert ab_item["weight"] == 0.65
    assert ab_item["direction"] == "malicious"


def test_cipher_abuseipdb_boundary_74_is_moderate_tier(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    result = _ip_result(mocker, fake_config, sample_alert, malicious=0, suspicious=0, score=74)
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert ab_item["weight"] == 0.40
    assert ab_item["direction"] == "malicious"


def test_cipher_abuseipdb_boundary_exactly_25_is_moderate_tier(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    result = _ip_result(mocker, fake_config, sample_alert, malicious=0, suspicious=0, score=25)
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert ab_item["weight"] == 0.40
    assert ab_item["direction"] == "malicious"


def test_cipher_abuseipdb_boundary_24_is_low_tier(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    result = _ip_result(mocker, fake_config, sample_alert, malicious=0, suspicious=0, score=24)
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert ab_item["weight"] == 0.15
    assert ab_item["direction"] == "neutral"


def test_cipher_urlhaus_boundary_exactly_three_is_multi_hit_tier(
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

    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert uh_item["weight"] == 0.60
    assert uh_item["direction"] == "malicious"


def test_cipher_urlhaus_boundary_two_is_single_hit_tier(
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
    uh_response.json.return_value = {"query_status": "ok", "url_count": 2}
    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.return_value = uh_response

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert uh_item["weight"] == 0.40
    assert uh_item["direction"] == "malicious"


def test_cipher_never_asserts_benign_direction(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """Across every scenario, Cipher's reputation-lookup EvidenceItems only ever
    use 'malicious' or 'neutral' -- absence of detection/reports is never treated
    as proof of safety, mirroring Watchman's permanent malicious/neutral-only
    asymmetry and extending _lookup_urlhaus's existing 'absence is not
    exonerating' principle to all three sub-signals."""
    result = _ip_result(mocker, fake_config, sample_alert, malicious=0, suspicious=0, score=0)
    assert all(item["direction"] != "benign" for item in result["evidence"])


# --- Code-review patches (2026-07-23) ---


def test_cipher_vt_non_200_status_is_coverage_gap_not_clean_scan(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """A VirusTotal 404 ('never scanned') or 401/403 (auth failure) previously
    fell through to `.get(..., 0)` defaults, producing a false '0 malicious
    engines' neutral EvidenceItem with no error/blind_spot signal --
    indistinguishable from a genuine clean scan. Must now route to a
    coverage gap instead."""
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    vt_response = mocker.MagicMock()
    vt_response.status_code = 404
    vt_response.json.return_value = {"error": {"code": "NotFoundError"}}
    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] is not None
    assert not any("flagged by" in f for f in result["findings"])
    assert any(bs["source"] == "virustotal" for bs in result["blind_spots"])
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    assert vt_item["weight"] == 0.0
    assert vt_item["direction"] == "neutral"


def test_cipher_abuseipdb_non_200_status_is_coverage_gap_not_clean_scan(
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
    ab_response.status_code = 401
    ab_response.json.return_value = {"errors": [{"detail": "Invalid API key"}]}
    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] is not None
    assert not any("abuse confidence" in f for f in result["findings"])
    assert any(bs["source"] == "abuseipdb" for bs in result["blind_spots"])
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert ab_item["weight"] == 0.0
    assert ab_item["direction"] == "neutral"


def test_cipher_vt_null_malicious_value_does_not_produce_phantom_finding(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """A malformed API response with an explicit JSON null for 'malicious'
    must not append a phantom finding claiming a lookup succeeded while
    evidence/blind_spots simultaneously report a failure."""
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": None, "suspicious": 0}}}
    }
    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert not any("flagged by None" in f for f in result["findings"])


def test_cipher_urlhaus_unrecognized_query_status_is_coverage_gap_not_benign_miss(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """A URLhaus query_status other than 'ok'/'no_results' (e.g. the
    documented 'invalid_host') means the query itself was rejected -- must
    not be conflated with a genuine no-data miss."""
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
    uh_response.json.return_value = {"query_status": "invalid_host"}
    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.return_value = uh_response

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert any(bs["source"] == "urlhaus" for bs in result["blind_spots"])
    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert uh_item["weight"] == 0.0
    assert uh_item["direction"] == "neutral"


def test_cipher_urlhaus_ok_status_with_zero_url_count_is_not_misleading_finding(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """query_status == 'ok' with url_count == 0 is a degenerate API shape --
    must read identically to a genuine no_results miss, not emit a
    misleading '0 malicious URL(s)' finding."""
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
    uh_response.json.return_value = {"query_status": "ok", "url_count": 0}
    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.return_value = uh_response

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert not any("URLhaus" in f for f in result["findings"])
    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert uh_item["weight"] == 0.10
    assert uh_item["direction"] == "neutral"
