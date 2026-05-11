import re

import httpx

from sentinel.config import Config
from sentinel.verdict import AgentResult, BlindSpot

_VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PRIVATE_IP = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)


def _extract_public_ips(text: str) -> list[str]:
    return [ip for ip in _IP_PATTERN.findall(text) if not _PRIVATE_IP.match(ip)]


class CipherAgent:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._client = httpx.Client(timeout=config.timeout_seconds)

    def analyze(self, input_data: str) -> AgentResult:
        try:
            ips = _extract_public_ips(input_data)
            if not ips:
                return AgentResult(
                    source_name="cipher",
                    findings=[],
                    blind_spots=[
                        BlindSpot(
                            source="cipher",
                            reason="No external IOCs found in alert — threat intelligence lookup not applicable",
                            next_step="Verify alert contains an external IP address, domain, or file hash",
                        )
                    ],
                    raw_confidence=None,
                    error=None,
                )

            ip = ips[0]
            findings: list[str] = []
            blind_spots: list[BlindSpot] = []
            overall_error: str | None = None

            # VirusTotal lookup
            try:
                vt_resp = self._client.get(
                    _VT_URL.format(ip=ip),
                    headers={"x-apikey": self._config.virustotal_api_key},
                )
                if vt_resp.status_code == 429:
                    blind_spots.append(
                        BlindSpot(
                            source="virustotal",
                            reason="VirusTotal rate limit reached — reputation data unavailable",
                            next_step="Wait 60 seconds or upgrade to VirusTotal Premium",
                        )
                    )
                    overall_error = "rate_limited"
                else:
                    vt_data = vt_resp.json()
                    stats = (
                        vt_data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    findings.append(
                        f"VirusTotal: {ip} flagged by {malicious} engines as malicious, "
                        f"{suspicious} as suspicious"
                    )
            except httpx.TimeoutException:
                raise
            except Exception:
                blind_spots.append(
                    BlindSpot(
                        source="virustotal",
                        reason="VirusTotal lookup failed — reputation data unavailable",
                        next_step=None,
                    )
                )
                if overall_error is None:
                    overall_error = "analysis_failed"

            # AbuseIPDB lookup
            try:
                ab_resp = self._client.get(
                    _ABUSEIPDB_URL,
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": self._config.abuseipdb_api_key,
                        "Accept": "application/json",
                    },
                )
                if ab_resp.status_code == 429:
                    blind_spots.append(
                        BlindSpot(
                            source="abuseipdb",
                            reason="AbuseIPDB rate limit reached — abuse report data unavailable",
                            next_step="Wait before retrying or upgrade your AbuseIPDB plan",
                        )
                    )
                    if overall_error is None:
                        overall_error = "rate_limited"
                else:
                    ab_data = ab_resp.json()
                    score = ab_data.get("data", {}).get("abuseConfidenceScore", 0)
                    reports = ab_data.get("data", {}).get("totalReports", 0)
                    findings.append(
                        f"AbuseIPDB: {ip} abuse confidence {score}% from {reports} reports"
                    )
            except httpx.TimeoutException:
                raise
            except Exception:
                blind_spots.append(
                    BlindSpot(
                        source="abuseipdb",
                        reason="AbuseIPDB lookup failed — abuse report data unavailable",
                        next_step=None,
                    )
                )
                if overall_error is None:
                    overall_error = "analysis_failed"

            return AgentResult(
                source_name="cipher",
                findings=findings,
                blind_spots=blind_spots,
                raw_confidence=None,
                error=overall_error,
            )

        except httpx.TimeoutException:
            return AgentResult(
                source_name="cipher",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="cipher",
                        reason="Cipher timed out — threat intelligence lookup unavailable",
                        next_step="Retry when VirusTotal and AbuseIPDB APIs are reachable or increase SENTINEL_TIMEOUT",
                    )
                ],
                raw_confidence=None,
                error="timeout",
            )
        except Exception:
            return AgentResult(
                source_name="cipher",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="cipher",
                        reason="Cipher analysis failed — threat intelligence lookup unavailable",
                        next_step=None,
                    )
                ],
                raw_confidence=None,
                error="analysis_failed",
            )
