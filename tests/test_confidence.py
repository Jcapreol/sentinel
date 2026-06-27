from conftest import make_agent_result
from sentinel.confidence import (
    ConfidenceTier,
    TIER_MAP,
    calculate_tier,
    count_independent_sources,
)
from sentinel.source_registry import SOURCE_CATEGORIES
from sentinel.verdict import AgentResult, BlindSpot


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _watchman(raw_confidence: str | None, error: str | None = None) -> AgentResult:
    return AgentResult(
        source_name="watchman",
        findings=[],
        blind_spots=[],
        raw_confidence=raw_confidence,
        error=error,
    )


def _cipher(findings: list[str], error: str | None = None) -> AgentResult:
    return AgentResult(
        source_name="cipher",
        findings=findings,
        blind_spots=[],
        raw_confidence=None,
        error=error,
    )


_VT_MALICIOUS = "VirusTotal: 185.220.101.45 flagged by 5 engines as malicious, 2 as suspicious"
_VT_CLEAN = "VirusTotal: example.com flagged by 0 engines as malicious, 0 as suspicious"
_ABUSE_MALICIOUS = "AbuseIPDB: 185.220.101.45 abuse confidence 87% from 12 reports"
_ABUSE_CLEAN = "AbuseIPDB: 1.2.3.4 abuse confidence 0% from 0 reports"
_ABUSE_AT_THRESHOLD = "AbuseIPDB: 10.9.8.7 abuse confidence 25% from 3 reports"
_ABUSE_BELOW_THRESHOLD = "AbuseIPDB: 10.9.8.7 abuse confidence 24% from 2 reports"


# ---------------------------------------------------------------------------
# Enum and TIER_MAP shape
# ---------------------------------------------------------------------------

def test_confidence_tier_enum_values() -> None:
    assert ConfidenceTier.BENIGN.value == "Benign"
    assert ConfidenceTier.INVESTIGATING.value == "Investigating"
    assert ConfidenceTier.PROBABLE.value == "Probable"
    assert ConfidenceTier.CONFIRMED.value == "Confirmed"


def test_tier_map_values() -> None:
    assert TIER_MAP[ConfidenceTier.BENIGN] == (0, "Benign")
    assert TIER_MAP[ConfidenceTier.INVESTIGATING] == (1, "Investigating")
    assert TIER_MAP[ConfidenceTier.PROBABLE] == (2, "Probable")
    assert TIER_MAP[ConfidenceTier.CONFIRMED] == (3, "Confirmed")


# ---------------------------------------------------------------------------
# count_independent_sources (unchanged contract)
# ---------------------------------------------------------------------------

def test_count_independent_sources_two_independent() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    assert count_independent_sources([watchman, cipher]) == 2


def test_count_independent_sources_same_category() -> None:
    vt = make_agent_result(source="virustotal")
    ab = make_agent_result(source="abuseipdb")
    assert count_independent_sources([vt, ab]) == 1


def test_failed_agent_excluded_from_count() -> None:
    watchman = make_agent_result(source="watchman")
    failed_cipher = make_agent_result(source="cipher", error="timeout")
    assert count_independent_sources([watchman, failed_cipher]) == 1


# ---------------------------------------------------------------------------
# Benign — Cipher checked and found the IOC clean
# ---------------------------------------------------------------------------

def test_clean_ioc_watchman_investigating_returns_benign() -> None:
    # Cipher checked; zero engines + 0% abuse. Watchman also sees nothing threatening.
    assert calculate_tier(
        _watchman("Investigating"),
        _cipher([_VT_CLEAN, _ABUSE_CLEAN]),
    ) == ConfidenceTier.BENIGN


def test_clean_domain_vt_only_watchman_probable_returns_benign() -> None:
    # Domain lookup — no AbuseIPDB data (IP-only). VT says clean.
    # Watchman "Probable" is medium severity but explicit exoneration wins.
    assert calculate_tier(
        _watchman("Probable"),
        _cipher([_VT_CLEAN]),
    ) == ConfidenceTier.BENIGN


def test_clean_ioc_watchman_no_signal_returns_benign() -> None:
    assert calculate_tier(
        _watchman(None, error="timeout"),
        _cipher([_VT_CLEAN]),
    ) == ConfidenceTier.BENIGN


def test_clean_ioc_watchman_confirmed_returns_investigating() -> None:
    # IOC cleared by intel but LLM strongly suspects threat — stay cautious rather
    # than calling it benign.
    assert calculate_tier(
        _watchman("Confirmed"),
        _cipher([_VT_CLEAN, _ABUSE_CLEAN]),
    ) == ConfidenceTier.INVESTIGATING


# ---------------------------------------------------------------------------
# Probable — malicious IOC with no corroborating LLM signal
# ---------------------------------------------------------------------------

def test_malicious_vt_watchman_low_returns_probable() -> None:
    assert calculate_tier(
        _watchman("Investigating"),
        _cipher([_VT_MALICIOUS]),
    ) == ConfidenceTier.PROBABLE


def test_malicious_ioc_cipher_no_watchman_signal_returns_probable() -> None:
    assert calculate_tier(
        _watchman(None, error="timeout"),
        _cipher([_VT_MALICIOUS, _ABUSE_MALICIOUS]),
    ) == ConfidenceTier.PROBABLE


def test_watchman_confirmed_cipher_no_data_returns_probable() -> None:
    # LLM strongly suspects threat but no IOC to look up — single source, Probable.
    assert calculate_tier(
        _watchman("Confirmed"),
        _cipher([], error="timeout"),
    ) == ConfidenceTier.PROBABLE


# ---------------------------------------------------------------------------
# Confirmed — malicious IOC + corroborating Watchman
# ---------------------------------------------------------------------------

def test_malicious_ioc_watchman_confirmed_returns_confirmed() -> None:
    assert calculate_tier(
        _watchman("Confirmed"),
        _cipher([_VT_MALICIOUS, _ABUSE_MALICIOUS]),
    ) == ConfidenceTier.CONFIRMED


def test_malicious_ioc_watchman_probable_returns_confirmed() -> None:
    # Two independent sources (LLM behavioral + threat intel) both flag threat.
    assert calculate_tier(
        _watchman("Probable"),
        _cipher([_VT_MALICIOUS]),
    ) == ConfidenceTier.CONFIRMED


def test_abuse_at_threshold_watchman_probable_returns_confirmed() -> None:
    # Score exactly at threshold counts as malicious.
    assert calculate_tier(
        _watchman("Probable"),
        _cipher([_ABUSE_AT_THRESHOLD]),
    ) == ConfidenceTier.CONFIRMED


# ---------------------------------------------------------------------------
# Investigating — no data or ambiguous signal
# ---------------------------------------------------------------------------

def test_both_agents_failed_returns_investigating() -> None:
    assert calculate_tier(
        _watchman(None, error="timeout"),
        _cipher([], error="timeout"),
    ) == ConfidenceTier.INVESTIGATING


def test_cipher_no_ioc_watchman_probable_returns_investigating() -> None:
    # Cipher found no IOC in the alert — no_data, not clean.
    # Watchman alone with medium signal → Investigating (not Probable without corroboration).
    assert calculate_tier(
        _watchman("Probable"),
        _cipher([]),  # no findings, no error — no IOC found
    ) == ConfidenceTier.INVESTIGATING


def test_cipher_rate_limited_watchman_probable_returns_investigating() -> None:
    assert calculate_tier(
        _watchman("Probable"),
        _cipher([], error="rate_limited"),
    ) == ConfidenceTier.INVESTIGATING


def test_watchman_investigating_cipher_no_data_returns_investigating() -> None:
    assert calculate_tier(
        _watchman("Investigating"),
        _cipher([], error="timeout"),
    ) == ConfidenceTier.INVESTIGATING


def test_abuse_below_threshold_treated_as_clean() -> None:
    # Score just below threshold → clean, not malicious. Watchman medium → Benign.
    assert calculate_tier(
        _watchman("Probable"),
        _cipher([_ABUSE_BELOW_THRESHOLD]),
    ) == ConfidenceTier.BENIGN
