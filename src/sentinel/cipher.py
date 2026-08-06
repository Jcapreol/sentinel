import re
import sys
from typing import Literal

import httpx

from sentinel.config import Config
from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.script_guard import (
    ApiCallBudget,
    ApiCallBudgetExceededError,
    CachedLookup,
    LookupCache,
)
from sentinel.verdict import AgentResult, BlindSpot

# PROVISIONAL PRIORS, not calibrated values (matches headers.py/watchman.py's
# identical framing) -- exact tier boundaries and weights are placeholders
# pending Epic 3's calibration harness (Story 3.2). Cipher's reputation-lookup
# EvidenceItems can never assert direction="benign" -- only "malicious" or
# "neutral" -- the same permanent asymmetry Watchman has (see watchman.py):
# absence of detection/reports is not proof of safety. This extends the
# "absence is not exonerating" principle already documented on
# _lookup_urlhaus's docstring consistently across all three sub-signals below,
# not just URLhaus.
#
# _UNINFORMATIVE_WEIGHT (0.10, "present but ambiguous") vs. weight=0.0 via
# _coverage_gap_evidence ("total gap") is a deliberate distinction, used
# consistently at every rate-limit (429) site below: a 429 means the request
# WAS sent and a response WAS received -- something was attempted, just not
# completed -- the same "present but ambiguous" semantics as an unrecognized
# result. That is different from a true coverage gap (timeout, connection
# failure, unparseable response), where nothing informative happened at all.
# Both damp the score toward uncertainty via compute_raw_score's total_weight
# denominator, but 0.10 damps less aggressively than 0.0's complete inertness.
_UNINFORMATIVE_WEIGHT = 0.10

_VT_HIGH_CONSENSUS_WEIGHT = 0.70  # malicious_count >= 5
_VT_LOW_CONSENSUS_WEIGHT = 0.45  # 1 <= malicious_count < 5
_VT_SUSPICIOUS_ONLY_WEIGHT = 0.20  # malicious_count == 0, suspicious_count >= 1

_ABUSEIPDB_HIGH_WEIGHT = 0.65  # score >= 75
_ABUSEIPDB_MODERATE_WEIGHT = 0.40  # 25 <= score < 75
_ABUSEIPDB_LOW_WEIGHT = 0.15  # 1 <= score < 25

_URLHAUS_MULTI_HIT_WEIGHT = 0.60  # url_count >= 3
_URLHAUS_SINGLE_HIT_WEIGHT = 0.40  # 1 <= url_count < 3

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

# [Cipher domain-extraction fix, Phase 2] A curated allow-list, not the full
# ~1500-entry IANA root zone -- _DOMAIN_PATTERN's bare "word.word...letters"
# shape matches plenty of non-domain text (a person's name written
# firstname.lastname, a filename, a JS/CSS identifier that survives HTML
# stripping) that a TLD check alone rejects cheaply. Deliberately includes
# TLDs heavily abused by real phishing infrastructure (.shop, .xyz, .top,
# .club, .online, .site, .live, .icu, .link, .click, plus the historically-
# free Freenom TLDs .tk/.ml/.ga/.cf/.gq) precisely because under-inclusion
# here would silently re-introduce this exact bug for real malicious
# domains, not just reject false positives -- see bsq2.firiri.shop, the real
# indicator Task 6's run failed to query (deferred-work.md). An unmatched
# but real, legitimate ccTLD is a conservative miss (extract_ioc finds no
# IOC in that file, same as today's "no domains found" case), not a crash or
# a wrong answer -- acceptable for a heuristic IOC pre-filter, not a DNS
# resolver. Deliberately does NOT filter on casing (e.g. rejecting camelCase
# labels) -- real corpus domains legitimately appear as "www.KAY.com"
# (all-caps brand) and "DentalPlans.com" (TitleCase brand; note "l"->"P" is
# itself a lowercase-to-uppercase transition), so a casing heuristic would
# reject real domains, not just junk.
_PLAUSIBLE_TLDS = frozenset(
    {
        # Legacy / infrastructure gTLDs
        "com", "net", "org", "edu", "gov", "mil", "int",
        # Common modern gTLDs (legitimate use)
        "io", "co", "me", "tv", "cc", "info", "biz", "name", "pro", "mobi", "ai",
        "asia", "app", "dev", "tech", "email", "cloud", "digital", "network",
        "systems", "solutions", "agency", "company", "group", "world", "life",
        "today", "news", "media", "blog", "design", "expert", "guru", "work",
        "store", "site",
        # gTLDs heavily abused by real phishing/malware infrastructure --
        # must stay included, not just "common legitimate" ones. .cyou/.cfd
        # added 2026-08-05 (code review) after confirming real-corpus
        # evidence: both appear repeatedly as clear malicious C2-style
        # infrastructure (e.g. random-label subdomains under a single base
        # domain). .zip/.mov deliberately NOT included despite being
        # well-known abused gTLDs elsewhere -- checked this project's real
        # corpus specifically and the only .zip match is "Reclamado.zip", a
        # real attachment FILENAME, not a domain; the ordinary-file-mention
        # collision risk outweighs the absent benefit here (zero real .zip/
        # .mov domain evidence in 10,435 files).
        "shop", "xyz", "top", "club", "online", "live", "icu", "link", "click",
        "pw", "tk", "ml", "ga", "cf", "gq", "win", "bid", "loan", "download",
        "stream", "gdn", "men", "party", "review", "science", "trade", "webcam",
        "cyou", "cfd", "cm",
        # Added 2026-08-05 (code review, Edge Case Hunter) after confirming
        # real-corpus evidence for each -- .sbs/.buzz/.quest/.vip/.cam all
        # show the same random-label-subdomain phishing-infrastructure
        # pattern already seen for .shop/.cyou/.cfd. .rest/.surf were also
        # suggested but show zero real matches either way and are plausible
        # English words -- skipped, same standard applied to .zip/.mov.
        "sbs", "buzz", "quest", "vip", "cam",
        # Major country-code TLDs (not exhaustive -- ISO 3166 has ~250; an
        # unmatched real ccTLD is a conservative miss, see comment above)
        "uk", "us", "ca", "au", "de", "fr", "jp", "cn", "ru", "br", "in", "it",
        "es", "nl", "se", "no", "dk", "fi", "pl", "ch", "at", "be", "ie", "nz",
        "mx", "kr", "sg", "hk", "tw", "za", "ae", "il", "tr", "gr", "pt", "cz",
        "ro", "hu", "ua", "id", "th", "vn", "ph", "my", "pk", "ng", "eg", "sa",
        "ar", "cl", "pe", "ve",
    }
)


def _has_plausible_tld(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld in _PLAUSIBLE_TLDS


def _has_valid_octets(ip: str) -> bool:
    """_IP_PATTERN itself only checks 1-3 DIGITS per group, not that each
    group is a real 0-255 octet -- a formatted number like "27.500.000.00"
    (a price) matches the pattern exactly as well as a real IP, and
    extract_ioc/CipherAgent.analyze both check IPs before domains, so an
    unvalidated match like that preempts any real domain in the same file."""
    return all(0 <= int(octet) <= 255 for octet in ip.split("."))


def _extract_public_ips(text: str) -> list[str]:
    return [
        ip
        for ip in _IP_PATTERN.findall(text)
        if _has_valid_octets(ip) and not _PRIVATE_IP.match(ip)
    ]


def _extract_domains(text: str) -> list[str]:
    stripped = _URL_STRIP.sub(r"\1", text)
    seen: dict[str, None] = {}
    for d in _DOMAIN_PATTERN.findall(stripped):
        if _has_plausible_tld(d):
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


def _warn_vt_degraded(indicator: str, reason: str) -> None:
    """[Story 4.1] Every VT failure path below (429/other-non-200/exception)
    already degrades silently to a low-weight neutral or coverage-gap
    EvidenceItem, with nothing surfacing in either real-corpus script's own
    output -- confirmed directly from this file during Task 6's real-run
    investigation (see deferred-work.md). This is a minimal visibility fix,
    not a full one: a single stderr line so "no errors in the log" becomes a
    meaningful signal again, matching this project's existing per-item
    stderr-warning precedent (e.g. ingest.py's own per-message warnings)."""
    print(f"WARNING: VirusTotal lookup degraded for {indicator!r}: {reason}", file=sys.stderr)


def _coverage_gap_evidence(name: str, reason: str) -> list[EvidenceItem]:
    """weight=0.0: total coverage gap, no signal at all, mathematically
    invisible to compute_raw_score -- built as a shared helper from the
    start (unlike watchman.py's identical pattern, which had to be patched
    into this shape after the fact during Story 2.1's code review)."""
    return [EvidenceItem(name=name, finding=reason, weight=0.0, direction="neutral")]


def _vt_weight_and_direction(malicious: int, suspicious: int) -> tuple[float, Literal["malicious", "neutral"]]:
    if malicious >= 5:
        return _VT_HIGH_CONSENSUS_WEIGHT, "malicious"
    if malicious >= 1:
        return _VT_LOW_CONSENSUS_WEIGHT, "malicious"
    if suspicious >= 1:
        return _VT_SUSPICIOUS_ONLY_WEIGHT, "neutral"
    return _UNINFORMATIVE_WEIGHT, "neutral"


def _abuseipdb_weight_and_direction(score: int) -> tuple[float, Literal["malicious", "neutral"]]:
    if score >= 75:
        return _ABUSEIPDB_HIGH_WEIGHT, "malicious"
    if score >= 25:
        return _ABUSEIPDB_MODERATE_WEIGHT, "malicious"
    if score >= 1:
        return _ABUSEIPDB_LOW_WEIGHT, "neutral"
    return _UNINFORMATIVE_WEIGHT, "neutral"


def _urlhaus_weight_and_direction(url_count: int) -> tuple[float, Literal["malicious", "neutral"]]:
    if url_count >= 3:
        return _URLHAUS_MULTI_HIT_WEIGHT, "malicious"
    if url_count >= 1:
        return _URLHAUS_SINGLE_HIT_WEIGHT, "malicious"
    return _UNINFORMATIVE_WEIGHT, "neutral"


class CipherAgent:
    """`cache`/`budget` are Story 4.2 additions -- both default to
    `None`/off. Only fit_real_calibration_model.py/run_evaluation_harness.py
    ever pass them; worker.py's live-triage `CipherAgent(config)` call sites
    are unmodified, so live triage never checks a cache or a call ceiling
    (AC5)."""

    def __init__(
        self,
        config: Config,
        cache: LookupCache | None = None,
        budget: ApiCallBudget | None = None,
    ) -> None:
        self._config = config
        self._cache = cache
        self._budget = budget
        self._client = httpx.Client(timeout=config.timeout_seconds)

    def analyze(self, input_data: str) -> AgentResult:
        try:
            ips = _extract_public_ips(input_data)
            if ips:
                return self._analyze_ip(ips[0])

            domains = _extract_domains(input_data)
            if domains:
                return self._analyze_domain(domains[0])

            reason = "No external IOCs found in alert — threat intelligence lookup not applicable"
            return AgentResult(
                source_name="cipher",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="cipher",
                        reason=reason,
                        next_step="Verify alert contains an external IP address, domain, or file hash",
                    )
                ],
                raw_confidence=None,
                error=None,
                evidence=_coverage_gap_evidence("cipher_analysis", reason),
            )

        except httpx.TimeoutException:
            reason = "Cipher timed out — threat intelligence lookup unavailable"
            return AgentResult(
                source_name="cipher",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="cipher",
                        reason=reason,
                        next_step="Retry when VirusTotal and AbuseIPDB APIs are reachable or increase SENTINEL_TIMEOUT",
                    )
                ],
                raw_confidence=None,
                error="timeout",
                evidence=_coverage_gap_evidence("cipher_analysis", reason),
            )
        except ApiCallBudgetExceededError:
            # Story 4.2: must propagate uncaught, never converted into a
            # coverage-gap AgentResult -- see the identical guard on each of
            # _analyze_ip/_analyze_domain/_lookup_urlhaus's own except blocks.
            raise
        except Exception:
            reason = "Cipher analysis failed — threat intelligence lookup unavailable"
            return AgentResult(
                source_name="cipher",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="cipher",
                        reason=reason,
                        next_step=None,
                    )
                ],
                raw_confidence=None,
                error="analysis_failed",
                evidence=_coverage_gap_evidence("cipher_analysis", reason),
            )

    def _lookup_urlhaus(
        self,
        indicator: str,
        indicator_type: Literal["ip", "domain"],
        findings: list[str],
        blind_spots: list[BlindSpot],
        evidence: list[EvidenceItem],
    ) -> str | None:
        """Query URLhaus host endpoint (POST). Returns an error code or None.

        A 'no_results' status is treated as no-data — absence from URLhaus
        does not indicate the indicator is safe. Unlike `findings`/`blind_spots`
        (unchanged — a miss still adds neither), a miss NOW also emits a
        neutral/uninformative EvidenceItem (Story 2.2): "nothing found" is
        itself auditable evidence for the weighted score, distinct from a true
        coverage gap (the except Exception path below, where the lookup never
        completed at all).

        Story 4.2: `indicator_type` identifies the cache key alongside
        `indicator`/`source="urlhaus"`. A cache hit reconstructs only the
        `EvidenceItem` (added to `evidence`) -- NOT `findings`/`blind_spots`
        membership, which this codebase's real-corpus-script consumers
        (`gather_evidence_and_raw_score`) never read anyway; replicating
        exact historical `findings` text on every cache hit would add real
        complexity for zero actual benefit to this story's purpose.
        """
        if self._cache is not None:
            cached = self._cache.get(indicator_type, indicator, "urlhaus")
            if cached is not None:
                evidence.append(
                    EvidenceItem(
                        name="urlhaus_finding",
                        finding=cached["finding"],
                        weight=cached["weight"],
                        direction=cached["direction"],
                    )
                )
                return None
        try:
            if self._budget is not None:
                self._budget.check_and_record("urlhaus")
            uh_resp = self._client.post(
                _URLHAUS_URL,
                data={"host": indicator},
                headers={"Auth-Key": self._config.urlhaus_api_key},
            )
            if uh_resp.status_code == 429:
                reason = "URLhaus rate limit reached — malicious URL data unavailable"
                blind_spots.append(
                    BlindSpot(
                        source="urlhaus",
                        reason=reason,
                        next_step="Wait before retrying or check URLhaus API quota",
                    )
                )
                evidence.append(
                    EvidenceItem(
                        name="urlhaus_finding", finding=reason, weight=_UNINFORMATIVE_WEIGHT, direction="neutral"
                    )
                )
                return "rate_limited"
            uh_data = uh_resp.json()
            query_status = uh_data.get("query_status")
            no_association_reason = (
                f"URLhaus: no malicious URL association found for {indicator} — absence is not proof of safety"
            )
            if query_status == "ok":
                url_count = int(uh_data.get("url_count") or 0)
                if url_count > 0:
                    finding = f"URLhaus: {indicator} associated with {url_count} malicious URL(s)"
                    findings.append(finding)
                    weight, direction = _urlhaus_weight_and_direction(url_count)
                    evidence.append(EvidenceItem(name="urlhaus_finding", finding=finding, weight=weight, direction=direction))
                    if self._cache is not None:
                        self._cache.put(
                            indicator_type, indicator, "urlhaus",
                            CachedLookup(weight=weight, direction=direction, finding=finding),
                        )
                else:
                    # "ok" with url_count == 0 is a degenerate API shape -- read
                    # identically to a genuine no_results miss below, not a
                    # misleading "0 malicious URL(s)" finding.
                    evidence.append(
                        EvidenceItem(
                            name="urlhaus_finding", finding=no_association_reason,
                            weight=_UNINFORMATIVE_WEIGHT, direction="neutral",
                        )
                    )
                    if self._cache is not None:
                        self._cache.put(
                            indicator_type, indicator, "urlhaus",
                            CachedLookup(
                                weight=_UNINFORMATIVE_WEIGHT, direction="neutral",
                                finding=no_association_reason,
                            ),
                        )
            elif query_status == "no_results":
                # silent no-data for findings/blind_spots (unchanged); absence is
                # not exonerating, so still record a neutral, uninformative
                # EvidenceItem rather than omitting it entirely.
                evidence.append(
                    EvidenceItem(
                        name="urlhaus_finding", finding=no_association_reason,
                        weight=_UNINFORMATIVE_WEIGHT, direction="neutral",
                    )
                )
                if self._cache is not None:
                    self._cache.put(
                        indicator_type, indicator, "urlhaus",
                        CachedLookup(
                            weight=_UNINFORMATIVE_WEIGHT, direction="neutral", finding=no_association_reason
                        ),
                    )
            else:
                # Any other/unrecognized query_status (e.g. URLhaus's documented
                # "invalid_host") means the query itself was rejected or
                # malformed -- a real coverage gap, not a completed "nothing
                # found" lookup. Must not be conflated with the genuine
                # no_results case above.
                reason = (
                    f"URLhaus returned unrecognized query_status {query_status!r} "
                    f"for {indicator} — malicious URL data unavailable"
                )
                blind_spots.append(BlindSpot(source="urlhaus", reason=reason, next_step=None))
                evidence.extend(_coverage_gap_evidence("urlhaus_finding", reason))
                return "analysis_failed"
            return None
        except httpx.TimeoutException:
            raise
        except ApiCallBudgetExceededError:
            raise  # Story 4.2: must not be swallowed by the generic handler below
        except Exception:
            reason = "URLhaus lookup failed — malicious URL data unavailable"
            blind_spots.append(
                BlindSpot(
                    source="urlhaus",
                    reason=reason,
                    next_step=None,
                )
            )
            evidence.extend(_coverage_gap_evidence("urlhaus_finding", reason))
            return "analysis_failed"

    def _analyze_ip(self, ip: str) -> AgentResult:
        findings: list[str] = []
        blind_spots: list[BlindSpot] = []
        evidence: list[EvidenceItem] = []
        overall_error: str | None = None

        # VirusTotal lookup
        vt_cached = self._cache.get("ip", ip, "virustotal") if self._cache is not None else None
        if vt_cached is not None:
            evidence.append(
                EvidenceItem(
                    name="virustotal_finding", finding=vt_cached["finding"],
                    weight=vt_cached["weight"], direction=vt_cached["direction"],
                )
            )
        else:
            try:
                if self._budget is not None:
                    self._budget.check_and_record("virustotal")
                vt_resp = self._client.get(
                    _VT_IP_URL.format(ip=ip),
                    headers={"x-apikey": self._config.virustotal_api_key},
                )
                if vt_resp.status_code == 429:
                    reason = "VirusTotal rate limit reached — reputation data unavailable"
                    _warn_vt_degraded(ip, reason)
                    blind_spots.append(
                        BlindSpot(
                            source="virustotal",
                            reason=reason,
                            next_step="Wait 60 seconds or upgrade to VirusTotal Premium",
                        )
                    )
                    evidence.append(
                        EvidenceItem(name="virustotal_finding", finding=reason, weight=_UNINFORMATIVE_WEIGHT, direction="neutral")
                    )
                    overall_error = "rate_limited"
                elif vt_resp.status_code != 200:
                    # Any other non-200 (VT's documented 404 "indicator never
                    # scanned", 401/403 auth failure, 5xx) previously fell through
                    # to the .get(..., 0) defaults below, producing a false "0
                    # malicious engines" neutral EvidenceItem indistinguishable
                    # from a genuine clean scan. Must be a coverage gap instead.
                    reason = f"VirusTotal returned unexpected status {vt_resp.status_code} — reputation data unavailable"
                    _warn_vt_degraded(ip, reason)
                    blind_spots.append(
                        BlindSpot(
                            source="virustotal",
                            reason=reason,
                            next_step="Check the VirusTotal API key and indicator format",
                        )
                    )
                    evidence.extend(_coverage_gap_evidence("virustotal_finding", reason))
                    if overall_error is None:
                        overall_error = "analysis_failed"
                else:
                    vt_data = vt_resp.json()
                    stats = (
                        vt_data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    # Defensive cast (matches _lookup_urlhaus's existing
                    # int(..., 0) precedent) -- an explicit JSON null or
                    # non-numeric value here would otherwise raise mid-tier-
                    # comparison, AFTER `finding` is already appended below.
                    malicious = int(stats.get("malicious") or 0)
                    suspicious = int(stats.get("suspicious") or 0)
                    finding = (
                        f"VirusTotal: {ip} flagged by {malicious} engines as malicious, "
                        f"{suspicious} as suspicious"
                    )
                    findings.append(finding)
                    weight, direction = _vt_weight_and_direction(malicious, suspicious)
                    evidence.append(EvidenceItem(name="virustotal_finding", finding=finding, weight=weight, direction=direction))
                    if self._cache is not None:
                        self._cache.put(
                            "ip", ip, "virustotal", CachedLookup(weight=weight, direction=direction, finding=finding)
                        )
            except httpx.TimeoutException:
                raise
            except ApiCallBudgetExceededError:
                raise  # Story 4.2: must not be swallowed by the generic handler below
            except Exception:
                reason = "VirusTotal lookup failed — reputation data unavailable"
                _warn_vt_degraded(ip, reason)
                blind_spots.append(
                    BlindSpot(
                        source="virustotal",
                        reason=reason,
                        next_step=None,
                    )
                )
                evidence.extend(_coverage_gap_evidence("virustotal_finding", reason))
                if overall_error is None:
                    overall_error = "analysis_failed"

        # AbuseIPDB lookup
        ab_cached = self._cache.get("ip", ip, "abuseipdb") if self._cache is not None else None
        if ab_cached is not None:
            evidence.append(
                EvidenceItem(
                    name="abuseipdb_finding", finding=ab_cached["finding"],
                    weight=ab_cached["weight"], direction=ab_cached["direction"],
                )
            )
        else:
            try:
                if self._budget is not None:
                    self._budget.check_and_record("abuseipdb")
                ab_resp = self._client.get(
                    _ABUSEIPDB_URL,
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": self._config.abuseipdb_api_key,
                        "Accept": "application/json",
                    },
                )
                if ab_resp.status_code == 429:
                    reason = "AbuseIPDB rate limit reached — abuse report data unavailable"
                    blind_spots.append(
                        BlindSpot(
                            source="abuseipdb",
                            reason=reason,
                            next_step="Wait before retrying or upgrade your AbuseIPDB plan",
                        )
                    )
                    evidence.append(
                        EvidenceItem(name="abuseipdb_finding", finding=reason, weight=_UNINFORMATIVE_WEIGHT, direction="neutral")
                    )
                    if overall_error is None:
                        overall_error = "rate_limited"
                elif ab_resp.status_code != 200:
                    reason = f"AbuseIPDB returned unexpected status {ab_resp.status_code} — abuse report data unavailable"
                    blind_spots.append(
                        BlindSpot(
                            source="abuseipdb",
                            reason=reason,
                            next_step="Check the AbuseIPDB API key and indicator format",
                        )
                    )
                    evidence.extend(_coverage_gap_evidence("abuseipdb_finding", reason))
                    if overall_error is None:
                        overall_error = "analysis_failed"
                else:
                    ab_data = ab_resp.json()
                    # Defensive cast, matching _lookup_urlhaus's existing precedent.
                    score = int(ab_data.get("data", {}).get("abuseConfidenceScore") or 0)
                    reports = int(ab_data.get("data", {}).get("totalReports") or 0)
                    finding = f"AbuseIPDB: {ip} abuse confidence {score}% from {reports} reports"
                    findings.append(finding)
                    weight, direction = _abuseipdb_weight_and_direction(score)
                    evidence.append(EvidenceItem(name="abuseipdb_finding", finding=finding, weight=weight, direction=direction))
                    if self._cache is not None:
                        self._cache.put(
                            "ip", ip, "abuseipdb", CachedLookup(weight=weight, direction=direction, finding=finding)
                        )
            except httpx.TimeoutException:
                raise
            except ApiCallBudgetExceededError:
                raise  # Story 4.2: must not be swallowed by the generic handler below
            except Exception:
                reason = "AbuseIPDB lookup failed — abuse report data unavailable"
                blind_spots.append(
                    BlindSpot(
                        source="abuseipdb",
                        reason=reason,
                        next_step=None,
                    )
                )
                evidence.extend(_coverage_gap_evidence("abuseipdb_finding", reason))
                if overall_error is None:
                    overall_error = "analysis_failed"

        # URLhaus lookup
        uh_error = self._lookup_urlhaus(ip, "ip", findings, blind_spots, evidence)
        if uh_error is not None and overall_error is None:
            overall_error = uh_error

        return AgentResult(
            source_name="cipher",
            findings=findings,
            blind_spots=blind_spots,
            raw_confidence=None,
            error=overall_error,
            evidence=evidence,
        )

    def _analyze_domain(self, domain: str) -> AgentResult:
        findings: list[str] = []
        blind_spots: list[BlindSpot] = []
        evidence: list[EvidenceItem] = []
        overall_error: str | None = None

        # VirusTotal domain lookup
        vt_cached = self._cache.get("domain", domain, "virustotal") if self._cache is not None else None
        if vt_cached is not None:
            evidence.append(
                EvidenceItem(
                    name="virustotal_finding", finding=vt_cached["finding"],
                    weight=vt_cached["weight"], direction=vt_cached["direction"],
                )
            )
        else:
            try:
                if self._budget is not None:
                    self._budget.check_and_record("virustotal")
                vt_resp = self._client.get(
                    _VT_DOMAIN_URL.format(domain=domain),
                    headers={"x-apikey": self._config.virustotal_api_key},
                )
                if vt_resp.status_code == 429:
                    reason = "VirusTotal rate limit reached — reputation data unavailable"
                    _warn_vt_degraded(domain, reason)
                    blind_spots.append(
                        BlindSpot(
                            source="virustotal",
                            reason=reason,
                            next_step="Wait 60 seconds or upgrade to VirusTotal Premium",
                        )
                    )
                    evidence.append(
                        EvidenceItem(name="virustotal_finding", finding=reason, weight=_UNINFORMATIVE_WEIGHT, direction="neutral")
                    )
                    overall_error = "rate_limited"
                elif vt_resp.status_code != 200:
                    reason = f"VirusTotal returned unexpected status {vt_resp.status_code} — reputation data unavailable"
                    _warn_vt_degraded(domain, reason)
                    blind_spots.append(
                        BlindSpot(
                            source="virustotal",
                            reason=reason,
                            next_step="Check the VirusTotal API key and indicator format",
                        )
                    )
                    evidence.extend(_coverage_gap_evidence("virustotal_finding", reason))
                    if overall_error is None:
                        overall_error = "analysis_failed"
                else:
                    vt_data = vt_resp.json()
                    stats = (
                        vt_data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    malicious = int(stats.get("malicious") or 0)
                    suspicious = int(stats.get("suspicious") or 0)
                    finding = (
                        f"VirusTotal: {domain} flagged by {malicious} engines as malicious, "
                        f"{suspicious} as suspicious"
                    )
                    findings.append(finding)
                    weight, direction = _vt_weight_and_direction(malicious, suspicious)
                    evidence.append(EvidenceItem(name="virustotal_finding", finding=finding, weight=weight, direction=direction))
                    if self._cache is not None:
                        self._cache.put(
                            "domain", domain, "virustotal", CachedLookup(weight=weight, direction=direction, finding=finding)
                        )
            except httpx.TimeoutException:
                raise
            except ApiCallBudgetExceededError:
                raise  # Story 4.2: must not be swallowed by the generic handler below
            except Exception:
                reason = "VirusTotal lookup failed — reputation data unavailable"
                _warn_vt_degraded(domain, reason)
                blind_spots.append(
                    BlindSpot(
                        source="virustotal",
                        reason=reason,
                        next_step=None,
                    )
                )
                evidence.extend(_coverage_gap_evidence("virustotal_finding", reason))
                if overall_error is None:
                    overall_error = "analysis_failed"

        # AbuseIPDB is IP-only — domain lookups are a blind spot
        abuseipdb_gap_reason = (
            "AbuseIPDB does not support domain lookups — abuse report data unavailable for domains"
        )
        blind_spots.append(
            BlindSpot(
                source="abuseipdb",
                reason=abuseipdb_gap_reason,
                next_step="Query AbuseIPDB manually with the resolved IP address if available",
            )
        )
        evidence.extend(_coverage_gap_evidence("abuseipdb_finding", abuseipdb_gap_reason))

        # URLhaus lookup (supports both IPs and domains)
        uh_error = self._lookup_urlhaus(domain, "domain", findings, blind_spots, evidence)
        if uh_error is not None and overall_error is None:
            overall_error = uh_error

        return AgentResult(
            source_name="cipher",
            findings=findings,
            blind_spots=blind_spots,
            raw_confidence=None,
            error=overall_error,
            evidence=evidence,
        )
