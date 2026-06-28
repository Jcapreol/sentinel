import pytest

from sentinel.config import Config
from sentinel.verdict import AgentResult, BlindSpot


@pytest.fixture
def fake_config() -> Config:
    return Config(
        anthropic_api_key="test-anthropic-key",
        virustotal_api_key="test-virustotal-key",
        abuseipdb_api_key="test-abuseipdb-key",
        urlhaus_api_key="test-urlhaus-key",
        timeout_seconds=5,
    )


@pytest.fixture
def sample_alert() -> str:
    return "Unusual outbound traffic to 185.220.101.45 on port 443 from prod-db-01"


def make_agent_result(
    source: str = "watchman",
    findings: list[str] | None = None,
    blind_spots: list[BlindSpot] | None = None,
    error: str | None = None,
) -> AgentResult:
    return AgentResult(
        source_name=source,
        findings=findings or [],
        blind_spots=blind_spots or [],
        raw_confidence=None if error else "Probable",
        error=error,
    )
