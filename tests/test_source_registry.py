from sentinel.source_registry import SOURCE_CATEGORIES, are_independent


def test_llm_and_threat_intel_are_independent() -> None:
    assert are_independent("anthropic_claude", "virustotal") is True


def test_same_source_is_not_independent() -> None:
    assert are_independent("virustotal", "virustotal") is False


def test_virustotal_and_abuseipdb_same_category() -> None:
    assert are_independent("virustotal", "abuseipdb") is False


def test_unknown_source_returns_false() -> None:
    assert are_independent("unknown_source", "virustotal") is False


def test_anthropic_and_abuseipdb_are_independent() -> None:
    assert are_independent("anthropic_claude", "abuseipdb") is True


def test_new_entry_extensibility() -> None:
    SOURCE_CATEGORIES["shodan"] = "network_scanning"
    try:
        assert are_independent("shodan", "virustotal") is True
        assert are_independent("shodan", "anthropic_claude") is True
        assert are_independent("shodan", "abuseipdb") is True
    finally:
        del SOURCE_CATEGORIES["shodan"]
