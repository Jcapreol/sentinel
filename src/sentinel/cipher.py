import re

import httpx

from sentinel.config import Config
from sentinel.verdict import AgentResult, BlindSpot

_VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PRIVATE_IP = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)
# Collapses https?://[user:pass@]host/path to just host before domain scanning,
# preventing path tokens like "payload.exe" from matching the domain pattern.
_URL_STRIP = re.compile(r"https?://(?:[^\s@]*@)?([^/\s?#:]+)")
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)


def _extract_public_ips(text: str) -> list[str]:
    return [ip for ip in _IP_PATTERN.findall(text) if not _PRIVATE_IP.match(ip)]


def _extract_domains(text: str) -> list[str]:
    stripped = _URL_STRIP.sub(r"\1", text)
    seen: dict[str, None] = {}
    for d in _DOMAIN_PATTERN.findall(stripped):
        seen[d] = None
    return list(seen)


def extract_ioc(text: str) -> tuple[str, str] | None:
    """Return the first extractable IOC as (type, value), or None."""
    ips = _extract_public_ips(text)
    if ips:
        return ("ip", ips[0])
    domains = _extract_domains(text)
    if domains:
        return ("domain", domains[0])
    return None


class CipherAgent:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._client = httpx.Client(timeout=config.timeout_seconds)

    def analyze(self, input_data: str) -> AgentResult:
        try:
            ips = _extract_public_ips(input_data)
            if ips:
                return self._analyze_ip(ips[0])

            domains = _extract_domains(input_data)
            if domains:
                return self._analyze_domain(domains[0])

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

    def _lookup_urlhaus(
        self,
        indicator: str,
        findings: list[str],
        blind_spots: list[BlindSpot],
    ) -> str | None:
        """Query URLhaus host endpoint (POST). Returns an error code or None.

        A 'no_results' status is treated as no-data — absence from URLhaus
        does not indicate the indicator is safe.
        """
        try:
            uh_resp = self._client.post(
                _URLHAUS_URL,
                data={"host": indicator},
                headers={"Auth-Key": self._config.urlhaus_api_key},
            )
            if uh_resp.status_code == 429:
                blind_spots.append(
                    BlindSpot(
                        source="urlhaus",
                        reason="URLhaus rate limit reached — malicious URL data unavailable",
                        next_step="Wait before retrying or check URLhaus API quota",
                    )
                )
                return "rate_limited"
            uh_data = uh_resp.json()
            if uh_data.get("query_status") == "ok":
                url_count = int(uh_data.get("url_count", 0))
                findings.append(
                    f"URLhaus: {indicator} associated with {url_count} malicious URL(s)"
                )
            # query_status == "no_results" → silent no-data; absence is not exonerating
            return None
        except httpx.TimeoutException:
            raise
        except Exception:
            blind_spots.append(
                BlindSpot(
                    source="urlhaus",
                    reason="URLhaus lookup failed — malicious URL data unavailable",
                    next_step=None,
                )
            )
            return "analysis_failed"

    def _analyze_ip(self, ip: str) -> AgentResult:
        findings: list[str] = []
        blind_spots: list[BlindSpot] = []
        overall_error: str | None = None

        # VirusTotal lookup
        try:
            vt_resp = self._client.get(
                _VT_IP_URL.format(ip=ip),
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

        # URLhaus lookup
        uh_error = self._lookup_urlhaus(ip, findings, blind_spots)
        if uh_error is not None and overall_error is None:
            overall_error = uh_error

        return AgentResult(
            source_name="cipher",
            findings=findings,
            blind_spots=blind_spots,
            raw_confidence=None,
            error=overall_error,
        )

    def _analyze_domain(self, domain: str) -> AgentResult:
        findings: list[str] = []
        blind_spots: list[BlindSpot] = []
        overall_error: str | None = None

        # VirusTotal domain lookup
        try:
            vt_resp = self._client.get(
                _VT_DOMAIN_URL.format(domain=domain),
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
                    f"VirusTotal: {domain} flagged by {malicious} engines as malicious, "
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

        # AbuseIPDB is IP-only — domain lookups are a blind spot
        blind_spots.append(
            BlindSpot(
                source="abuseipdb",
                reason="AbuseIPDB does not support domain lookups — abuse report data unavailable for domains",
                next_step="Query AbuseIPDB manually with the resolved IP address if available",
            )
        )

        # URLhaus lookup (supports both IPs and domains)
        uh_error = self._lookup_urlhaus(domain, findings, blind_spots)
        if uh_error is not None and overall_error is None:
            overall_error = uh_error

        return AgentResult(
            source_name="cipher",
            findings=findings,
            blind_spots=blind_spots,
            raw_confidence=None,
            error=overall_error,
        )
