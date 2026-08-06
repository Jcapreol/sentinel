import httpx
import pytest
from pytest_mock import MockerFixture

from sentinel.cipher import (
    _UNINFORMATIVE_WEIGHT,
    CipherAgent,
    _extract_domains,
    _extract_public_ips,
    extract_ioc,
)
from sentinel.config import Config
from sentinel.triage.script_guard import ApiCallBudgetExceededError, CachedLookup, LookupCache
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
    mocker: MockerFixture, fake_config: Config, sample_alert: str, capsys: pytest.CaptureFixture[str]
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
    # [Story 4.1] A VT degradation must be visible in stderr -- "no errors in
    # the log" was silently false comfort before this (see deferred-work.md).
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "VirusTotal" in captured.err
    assert ab_item["direction"] == "neutral"


def test_cipher_timeout_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """[Code review, 2026-08-05] Previously, a timeout on ANY sub-lookup
    re-raised past _analyze_ip entirely, discarding whatever the OTHER
    sub-lookups had already found and replacing the whole result with a
    single aggregate coverage-gap item -- this test's own assertions used
    to lock in that exact (buggy) shape. Now every sub-lookup degrades
    independently, matching every other exception type's existing
    handling, so a timeout on every .get() call still produces one
    coverage-gap EvidenceItem per sub-signal (VT, AbuseIPDB, URLhaus),
    not one aggregate "cipher_analysis" item -- see
    test_cipher_timeout_on_one_sublookup_preserves_already_gathered_evidence
    for the regression this was actually about: findings gathered BEFORE
    a later timeout must survive."""
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    mock_client.get.side_effect = httpx.ReadTimeout("timed out")
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "timeout"
    assert result["findings"] == []
    # [Code review, 2026-08-05] Exact counts, not just existence -- a bug
    # producing a spurious extra blind_spot/evidence item (e.g. the
    # believed-unreachable outer analyze() timeout handler firing
    # unexpectedly, or a double-handled exception) must fail this test.
    # 2 blind_spots (VT + AbuseIPDB timed out); URLhaus's own .post() call
    # succeeded (no_results), which adds an evidence item but no blind_spot.
    assert len(result["blind_spots"]) == 2
    assert len(result["evidence"]) == 3
    vt_blind_spot = next(bs for bs in result["blind_spots"] if bs["source"] == "virustotal")
    ab_blind_spot = next(bs for bs in result["blind_spots"] if bs["source"] == "abuseipdb")
    assert "timed out" in vt_blind_spot["reason"].lower()
    assert "timed out" in ab_blind_spot["reason"].lower()
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert vt_item == {"name": "virustotal_finding", "finding": vt_blind_spot["reason"], "weight": 0.0, "direction": "neutral"}
    assert ab_item == {"name": "abuseipdb_finding", "finding": ab_blind_spot["reason"], "weight": 0.0, "direction": "neutral"}
    # URLhaus's own .post() call was mocked to succeed (no_results) -- only
    # the two .get()-based lookups (VT/AbuseIPDB) were made to time out.
    assert uh_item["direction"] == "neutral"
    assert uh_item["weight"] == _UNINFORMATIVE_WEIGHT


def test_cipher_timeout_on_one_sublookup_preserves_already_gathered_evidence(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """[Code review, 2026-08-05] The core regression: VT succeeds and finds
    a real malicious signal (20 engines), THEN AbuseIPDB times out. Before
    this fix, AbuseIPDB's timeout re-raised past _analyze_ip entirely,
    discarding VT's already-gathered finding/evidence and replacing the
    whole AgentResult with a single empty coverage-gap item -- a confirmed
    malicious indicator would score as "nothing found". Now AbuseIPDB's
    timeout degrades to its own coverage-gap item, same as every other
    exception type, and VT's real evidence survives."""
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 20, "suspicious": 0}}}
    }
    mock_client.get.side_effect = [vt_response, httpx.ReadTimeout("timed out")]
    mock_client.post.return_value.status_code = 200
    mock_client.post.return_value.json.return_value = {"query_status": "no_results"}

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "timeout"
    assert len(result["findings"]) == 1
    assert "20 engines" in result["findings"][0]
    assert len(result["blind_spots"]) == 1
    assert len(result["evidence"]) == 3  # VT (real) + AbuseIPDB (gap) + URLhaus (no_results)
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    assert vt_item["weight"] == 0.70
    assert vt_item["direction"] == "malicious"
    ab_blind_spot = next(bs for bs in result["blind_spots"] if bs["source"] == "abuseipdb")
    assert "timed out" in ab_blind_spot["reason"].lower()
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert ab_item == {"name": "abuseipdb_finding", "finding": ab_blind_spot["reason"], "weight": 0.0, "direction": "neutral"}


def test_cipher_urlhaus_timeout_preserves_vt_and_abuseipdb_evidence(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """Mirrors the VT-then-AbuseIPDB-timeout test above for the third
    sub-lookup site (_lookup_urlhaus's own timeout handling, shared by
    both _analyze_ip and _analyze_domain) -- VT and AbuseIPDB both
    succeed, URLhaus times out; their real findings must survive."""
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 0}}}
    }
    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {"data": {"abuseConfidenceScore": 80, "totalReports": 3}}
    mock_client.get.side_effect = [vt_response, ab_response]
    mock_client.post.side_effect = httpx.ReadTimeout("timed out")

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "timeout"
    assert len(result["findings"]) == 2
    assert len(result["blind_spots"]) == 1
    assert len(result["evidence"]) == 3
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    assert vt_item["direction"] == "malicious"
    assert ab_item["direction"] == "malicious"
    uh_blind_spot = next(bs for bs in result["blind_spots"] if bs["source"] == "urlhaus")
    assert "timed out" in uh_blind_spot["reason"].lower()
    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert uh_item == {"name": "urlhaus_finding", "finding": uh_blind_spot["reason"], "weight": 0.0, "direction": "neutral"}


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
    mocker: MockerFixture, fake_config: Config, capsys: pytest.CaptureFixture[str]
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
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "VirusTotal" in captured.err


def test_cipher_domain_timeout_on_urlhaus_preserves_vt_evidence(
    mocker: MockerFixture, fake_config: Config
) -> None:
    """[Code review, 2026-08-05] Domain-path mirror of the ip-path
    preservation tests above -- confirms the same fix was applied to
    _analyze_domain's own VT timeout site (a separate code location from
    _analyze_ip's), not just the ip path."""
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 6, "suspicious": 0}}}
    }
    mock_client.get.return_value = vt_response
    mock_client.post.side_effect = httpx.ReadTimeout("timed out")

    agent = CipherAgent(config=fake_config)
    result = agent.analyze("DNS query to evil.example.net observed from 10.0.0.5")

    assert result["error"] == "timeout"
    assert len(result["findings"]) == 1
    # 2 blind_spots: AbuseIPDB's unconditional "not applicable to domains"
    # gap, plus URLhaus's timeout. 3 evidence items: VT (real) + AbuseIPDB
    # (not-applicable gap) + URLhaus (timeout gap).
    assert len(result["blind_spots"]) == 2
    assert len(result["evidence"]) == 3
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    assert vt_item["direction"] == "malicious"
    uh_blind_spot = next(bs for bs in result["blind_spots"] if bs["source"] == "urlhaus")
    assert "timed out" in uh_blind_spot["reason"].lower()


def test_cipher_domain_vt_failure_returns_blind_spot(
    mocker: MockerFixture, fake_config: Config, capsys: pytest.CaptureFixture[str]
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
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "VirusTotal" in captured.err


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
    mocker: MockerFixture, fake_config: Config, sample_alert: str, capsys: pytest.CaptureFixture[str]
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
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "VirusTotal" in captured.err


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


# --- Story 4.2: lookup cache + budget enforcement (real-corpus scripts only) ---

_DOMAIN_ALERT = "Suspicious activity involving evilcorp-malware.example.com from workstation"


def _populate_full_cache(cache: LookupCache, indicator_type: str, indicator_value: str) -> None:
    cache.put(
        indicator_type, indicator_value, "virustotal",
        CachedLookup(weight=0.70, direction="malicious", finding="cached VT finding"),
    )
    cache.put(
        indicator_type, indicator_value, "abuseipdb",
        CachedLookup(weight=0.65, direction="malicious", finding="cached AbuseIPDB finding"),
    )
    cache.put(
        indicator_type, indicator_value, "urlhaus",
        CachedLookup(weight=0.60, direction="malicious", finding="cached URLhaus finding"),
    )


def test_cipher_cache_hit_returns_cached_result_without_calling_httpx_client(
    mocker: MockerFixture, fake_config: Config, sample_alert: str, tmp_path
) -> None:
    cache = LookupCache(str(tmp_path / "cache.db"), ttl_seconds=3600)
    _populate_full_cache(cache, "ip", "185.220.101.45")
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    agent = CipherAgent(config=fake_config, cache=cache)
    result = agent.analyze(sample_alert)

    mock_client.get.assert_not_called()
    mock_client.post.assert_not_called()
    vt_item = next(i for i in result["evidence"] if i["name"] == "virustotal_finding")
    ab_item = next(i for i in result["evidence"] if i["name"] == "abuseipdb_finding")
    uh_item = next(i for i in result["evidence"] if i["name"] == "urlhaus_finding")
    assert vt_item["weight"] == 0.70 and vt_item["finding"] == "cached VT finding"
    assert ab_item["weight"] == 0.65 and ab_item["finding"] == "cached AbuseIPDB finding"
    assert uh_item["weight"] == 0.60 and uh_item["finding"] == "cached URLhaus finding"


def test_cipher_cache_miss_calls_through_and_populates_cache(
    mocker: MockerFixture, fake_config: Config, sample_alert: str, tmp_path
) -> None:
    cache = LookupCache(str(tmp_path / "cache.db"), ttl_seconds=3600)
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 0}}}
    }
    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {"data": {"abuseConfidenceScore": 80, "totalReports": 3}}
    mock_client.get.side_effect = [vt_response, ab_response]
    uh_response = mocker.MagicMock()
    uh_response.status_code = 200
    uh_response.json.return_value = {"query_status": "no_results"}
    mock_client.post.return_value = uh_response

    agent = CipherAgent(config=fake_config, cache=cache)
    agent.analyze(sample_alert)

    mock_client.get.assert_called()
    assert cache.get("ip", "185.220.101.45", "virustotal") is not None
    assert cache.get("ip", "185.220.101.45", "abuseipdb") is not None
    assert cache.get("ip", "185.220.101.45", "urlhaus") is not None


def test_cipher_budget_check_and_record_called_before_each_real_http_call_on_a_miss(
    mocker: MockerFixture, fake_config: Config, sample_alert: str, tmp_path
) -> None:
    cache = LookupCache(str(tmp_path / "cache.db"), ttl_seconds=3600)
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    ok_response = mocker.MagicMock()
    ok_response.status_code = 200
    ok_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}},
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "query_status": "no_results",
    }
    mock_client.get.return_value = ok_response
    mock_client.post.return_value = ok_response
    budget = mocker.MagicMock()

    agent = CipherAgent(config=fake_config, cache=cache, budget=budget)
    agent.analyze(sample_alert)

    sources_checked = {call.args[0] for call in budget.check_and_record.call_args_list}
    assert sources_checked == {"virustotal", "abuseipdb", "urlhaus"}


def test_cipher_budget_not_checked_for_cache_hits(
    mocker: MockerFixture, fake_config: Config, sample_alert: str, tmp_path
) -> None:
    cache = LookupCache(str(tmp_path / "cache.db"), ttl_seconds=3600)
    _populate_full_cache(cache, "ip", "185.220.101.45")
    mocker.patch("sentinel.cipher.httpx.Client")
    budget = mocker.MagicMock()

    agent = CipherAgent(config=fake_config, cache=cache, budget=budget)
    agent.analyze(sample_alert)

    budget.check_and_record.assert_not_called()


def _budget_that_rejects(mocker: MockerFixture, rejected_source: str):  # type: ignore[no-untyped-def]
    budget = mocker.MagicMock()

    def side_effect(source: str, *_args: object, **_kwargs: object) -> None:
        if source == rejected_source:
            raise ApiCallBudgetExceededError(f"ceiling reached for {source}")

    budget.check_and_record.side_effect = side_effect
    return budget


def test_cipher_budget_exceeded_on_virustotal_via_ip_propagates_uncaught(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    """Regression guard for the exact swallowing bug this story's design
    caught during drafting: _analyze_ip's VT except Exception: block must
    NOT convert ApiCallBudgetExceededError into a neutral coverage-gap
    EvidenceItem -- it must propagate all the way out of analyze()."""
    mocker.patch("sentinel.cipher.httpx.Client")
    budget = _budget_that_rejects(mocker, "virustotal")

    agent = CipherAgent(config=fake_config, budget=budget)

    with pytest.raises(ApiCallBudgetExceededError):
        agent.analyze(sample_alert)


def test_cipher_budget_exceeded_on_abuseipdb_via_ip_propagates_uncaught(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}
    }
    mock_client.get.return_value = vt_response
    budget = _budget_that_rejects(mocker, "abuseipdb")

    agent = CipherAgent(config=fake_config, budget=budget)

    with pytest.raises(ApiCallBudgetExceededError):
        agent.analyze(sample_alert)


def test_cipher_budget_exceeded_on_urlhaus_via_ip_propagates_uncaught(
    mocker: MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    ok_response = mocker.MagicMock()
    ok_response.status_code = 200
    ok_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}},
        "abuseConfidenceScore": 0,
        "totalReports": 0,
    }
    mock_client.get.return_value = ok_response
    budget = _budget_that_rejects(mocker, "urlhaus")

    agent = CipherAgent(config=fake_config, budget=budget)

    with pytest.raises(ApiCallBudgetExceededError):
        agent.analyze(sample_alert)


def test_cipher_budget_exceeded_on_virustotal_via_domain_propagates_uncaught(
    mocker: MockerFixture, fake_config: Config
) -> None:
    """Distinct code site from the IP-path VT test above (_analyze_domain
    has its own separate VT try/except block) -- proves that site is
    guarded too, not just _analyze_ip's."""
    mocker.patch("sentinel.cipher.httpx.Client")
    budget = _budget_that_rejects(mocker, "virustotal")

    agent = CipherAgent(config=fake_config, budget=budget)

    with pytest.raises(ApiCallBudgetExceededError):
        agent.analyze(_DOMAIN_ALERT)


# --- _extract_domains / _extract_public_ips / extract_ioc -------------------
#
# [Cipher domain-extraction fix, Phase 2] No direct unit coverage of these
# three functions existed before this fix -- every prior test exercised them
# only indirectly via CipherAgent.analyze() against a fixture already
# containing a single, clean IP/domain. Real-content fixtures below are
# excerpts of actual corpus files (benign_corpus_raw/, gitignored -- not
# available in CI or to other clones, so the real bytes are embedded here
# directly rather than referenced by path), sourced during Phase 1's
# investigation (deferred-work.md, Task 6 follow-up).


def test_extract_public_ips_rejects_invalid_octets() -> None:
    """_IP_PATTERN itself has no octet-range check -- a formatted number
    like a price ("27.500.000.00") or any other 4-group dotted-digit string
    previously matched and was returned as if it were a real IP, taking
    priority over any real domain in the same file (extract_ioc/
    CipherAgent.analyze both check IPs before domains)."""
    assert _extract_public_ips("total: 27.500.000.00 due") == []
    assert _extract_public_ips("ref 999.999.999.999 confirmed") == []


def test_extract_public_ips_accepts_valid_boundary_octets() -> None:
    assert _extract_public_ips("contact 8.8.255.255 now") == ["8.8.255.255"]
    assert _extract_public_ips("see 1.2.3.0 for details") == ["1.2.3.0"]


def test_extract_public_ips_still_filters_private_ranges() -> None:
    """Regression: the pre-existing _PRIVATE_IP filter must survive this
    fix unchanged -- octet-range validity and private-range exclusion are
    two independent, both-required gates."""
    assert _extract_public_ips("internal host 192.168.1.1") == []
    assert _extract_public_ips("loopback 127.0.0.1") == []


def test_extract_domains_rejects_implausible_tld() -> None:
    """Real excerpt from benign_corpus_raw/malicious/held_out/sample-1762.eml
    (a real recruiting-phishing forward) -- a quoted Outlook 'From:' header
    block in the HTML body. 'guddy.kumari' (the local part of
    guddy.kumari@pyramidconsultinginc.com) matches _DOMAIN_PATTERN's bare
    word.word shape exactly as well as the real company domain that follows
    it, separated only by '@'. Neither 'kumari' nor 'antal' is a real TLD."""
    text = (
        "<p class=\"MsoNormal\"><b>From:</b> Guddy Kumari "
        "&lt;guddy.kumari@pyramidconsultinginc.com&gt;<br>"
        "<b>To:</b> Praveen Antal &lt;praveen.antal@pyramidconsultinginc.com&gt;</p>"
    )

    domains = _extract_domains(text)

    assert "guddy.kumari" not in domains
    assert "praveen.antal" not in domains
    assert "pyramidconsultinginc.com" in domains


def test_extract_domains_accepts_known_abused_phishing_tld() -> None:
    """The real malicious indicator from sample-1073.eml (Phase 1) --
    .shop is a cheap, heavily-abused TLD. The allow-list must include it:
    under-inclusion here would silently re-introduce this exact bug for
    real malicious domains, not just reject false positives."""
    domains = _extract_domains("unsubscribe at http://bsq2.firiri.shop/unsub")

    assert "bsq2.firiri.shop" in domains


def test_extract_domains_accepts_cyou_and_cfd_confirmed_real_phishing_infra() -> None:
    """[Code review, 2026-08-05] Added to the allow-list after finding real
    corpus evidence -- both TLDs appear repeatedly as clear malicious C2-
    style infrastructure (random-label subdomains under one base domain,
    e.g. real corpus matches like *.comocileshox.cyou and
    app-ladioactivemail.cfd)."""
    domains = _extract_domains("callback to http://bnourajrnuwtbcm.comocileshox.cyou/x "
                                "and http://app-ladioactivemail.cfd/y")

    assert "bnourajrnuwtbcm.comocileshox.cyou" in domains
    assert "app-ladioactivemail.cfd" in domains


def test_extract_domains_accepts_further_confirmed_phishing_tlds() -> None:
    """[Code review, 2026-08-05, Edge Case Hunter] .sbs/.buzz/.quest/.vip/
    .cam confirmed via the same real-corpus check as .cyou/.cfd above --
    all show the same random-label-subdomain phishing pattern. .rest/.surf
    were also suggested but show zero real matches either way and are
    plausible English words -- not added, same standard as .zip/.mov."""
    domains = _extract_domains(
        "http://vd1z.sbs/a http://emailtracklink.buzz/b "
        "http://pandajimmys.quest/c http://yahya01.algoritme.vip/d "
        "http://creativeforu.cam/e"
    )

    assert "vd1z.sbs" in domains
    assert "emailtracklink.buzz" in domains
    assert "pandajimmys.quest" in domains
    assert "yahya01.algoritme.vip" in domains
    assert "creativeforu.cam" in domains


def test_extract_domains_rejects_zip_and_mov_despite_being_known_abused_tlds_elsewhere() -> None:
    """[Code review, 2026-08-05] .zip/.mov are well-known abused gTLDs in
    the wild (they collide with common file extensions), but this
    project's own real corpus was checked specifically: the only real
    .zip-ending match across 10,435 files is "Reclamado.zip", an
    attachment FILENAME, not a domain, and there are zero .mov matches at
    all. Including them would trade an absent real-world benefit (no real
    .zip/.mov phishing domain observed) for a concrete, common false-
    positive source (ordinary "see attached report.zip" mentions) --
    deliberately excluded. A regression test, not just a design note: this
    guards the decision from being silently reversed later without
    re-checking real evidence."""
    domains = _extract_domains("please see attached Reclamado.zip and video.mov")

    assert domains == []


def test_extract_domains_accepts_branded_domain_regardless_of_casing() -> None:
    """Real corpus domains appear as www.KAY.com (all-caps brand) and
    DentalPlans.com (TitleCase brand) in real marketing email body text --
    both are real, legitimate domains. A casing-based heuristic (e.g.
    rejecting any lowercase-to-uppercase transition) would incorrectly
    reject DentalPlans.com ('l' -> 'P' is such a transition) -- deliberately
    not used here; TLD plausibility is the only filter, independent of
    casing."""
    domains = _extract_domains("shop now at www.KAY.com or DentalPlans.com today")

    assert "www.KAY.com" in domains
    assert "DentalPlans.com" in domains


def test_extract_ioc_prefers_real_domain_over_leaked_script_identifiers() -> None:
    """End-to-end regression for the exact bug pattern found in Task 6's
    real run: extract_email_content (fix A) removes the <script> block's
    JS identifiers entirely, then extract_ioc (fix B, via _extract_domains'
    TLD check) correctly picks the one real domain that remains. Real
    excerpt from benign_corpus_raw/malicious/held_out/sample-1073.eml, where
    the un-fixed pipeline picked ("domain", "history.pushState") and queried
    VirusTotal for it instead of the real phishing domain."""
    from sentinel.triage.ingest import extract_email_content

    raw_bytes = (
        b"From: newsletter@example.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><head>"
        b'<script ecommerce-type="extend-native-history-api">(()=>{const e=history.pushState,'
        b"t=history.replaceState;history.pushState=function(){e.apply(history,arguments)},"
        b"history.replaceState=function(){t.apply(history,arguments)}})()</script>"
        b"</head>"
        b'<body>Um sich abzumelden, klicken Sie bitte auf '
        b'<a href="http://bsq2.firiri.shop/unsubscribe">Hier</a></body></html>'
    )

    content = extract_email_content(raw_bytes)
    picked = extract_ioc(content)

    assert picked == ("domain", "bsq2.firiri.shop")
