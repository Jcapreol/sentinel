from conftest import make_agent_result
from sentinel.confidence import (
    ConfidenceTier,
    TIER_MAP,
    calculate_tier,
    count_independent_sources,
)
from sentinel.source_registry import SOURCE_CATEGORIES


def test_confidence_tier_enum_values() -> None:
    assert ConfidenceTier.INVESTIGATING.value == "Investigating"
    assert ConfidenceTier.PROBABLE.value == "Probable"
    assert ConfidenceTier.CONFIRMED.value == "Confirmed"


def test_tier_map_values() -> None:
    assert TIER_MAP[ConfidenceTier.INVESTIGATING] == (1, "Investigating")
    assert TIER_MAP[ConfidenceTier.PROBABLE] == (2, "Probable")
    assert TIER_MAP[ConfidenceTier.CONFIRMED] == (3, "Confirmed")


def test_zero_sources_investigating() -> None:
    assert calculate_tier([]) == ConfidenceTier.INVESTIGATING


def test_one_source_investigating() -> None:
    result = make_agent_result(source="watchman")
    assert calculate_tier([result]) == ConfidenceTier.INVESTIGATING


def test_two_independent_sources_probable() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    assert calculate_tier([watchman, cipher]) == ConfidenceTier.PROBABLE


def test_two_dependent_sources_counts_as_one() -> None:
    vt = make_agent_result(source="virustotal")
    ab = make_agent_result(source="abuseipdb")
    assert calculate_tier([vt, ab]) == ConfidenceTier.INVESTIGATING


def test_three_or_more_sources_confirmed() -> None:
    SOURCE_CATEGORIES["shodan"] = "network_scanning"
    try:
        watchman = make_agent_result(source="watchman")
        cipher = make_agent_result(source="cipher")
        shodan = make_agent_result(source="shodan")
        assert calculate_tier([watchman, cipher, shodan]) == ConfidenceTier.CONFIRMED
    finally:
        del SOURCE_CATEGORIES["shodan"]


def test_failed_agent_excluded_from_count() -> None:
    watchman = make_agent_result(source="watchman")
    failed_cipher = make_agent_result(source="cipher", error="timeout")
    assert count_independent_sources([watchman, failed_cipher]) == 1
    assert calculate_tier([watchman, failed_cipher]) == ConfidenceTier.INVESTIGATING


def test_count_independent_sources_two_independent() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    assert count_independent_sources([watchman, cipher]) == 2


def test_count_independent_sources_same_category() -> None:
    vt = make_agent_result(source="virustotal")
    ab = make_agent_result(source="abuseipdb")
    assert count_independent_sources([vt, ab]) == 1
