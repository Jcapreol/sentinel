from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.web.demo import (
    VALID_SLUGS,
    FixtureSchemaError,
    UnknownSlugError,
    load_fixture,
)

_REQUIRED_FIELDS = {
    "verdict",
    "confidence_tier",
    "methodology",
    "citations",
    "blind_spots",
    "source_independence_confirmed",
    "execution_time_seconds",
    "timestamp",
}

_EXPECTED_TIERS: dict[str, int] = {
    "lsass-credential-dumping": 2,
    "tor-exit-node": 3,
    "google-benign": 0,
    "urlhaus-malware-ip": 3,
    "ssh-brute-force": 1,
}

_EXPECTED_VERDICTS: dict[str, str] = {
    "lsass-credential-dumping": "Probable",
    "tor-exit-node": "Confirmed",
    "google-benign": "Benign",
    "urlhaus-malware-ip": "Confirmed",
    "ssh-brute-force": "Investigating",
}


# --- slug validation ---

def test_unknown_slug_raises_unknown_slug_error() -> None:
    with pytest.raises(UnknownSlugError):
        load_fixture("not-a-real-scenario")


def test_unknown_slug_error_message_contains_slug() -> None:
    with pytest.raises(UnknownSlugError, match="not-a-real-scenario"):
        load_fixture("not-a-real-scenario")


def test_unknown_slug_error_message_lists_valid_slugs() -> None:
    with pytest.raises(UnknownSlugError) as exc_info:
        load_fixture("bogus")
    msg = str(exc_info.value)
    for slug in VALID_SLUGS:
        assert slug in msg


def test_empty_string_slug_raises_unknown_slug_error() -> None:
    with pytest.raises(UnknownSlugError):
        load_fixture("")


# --- fixture loading ---

@pytest.mark.parametrize("slug", sorted(VALID_SLUGS))
def test_all_valid_slugs_load_without_error(slug: str) -> None:
    result = load_fixture(slug)
    assert result is not None


# --- schema conformance ---

@pytest.mark.parametrize("slug", sorted(VALID_SLUGS))
def test_fixture_has_all_required_fields(slug: str) -> None:
    result = load_fixture(slug)
    missing = _REQUIRED_FIELDS - result.keys()
    assert not missing, f"{slug!r} missing fields: {missing}"


@pytest.mark.parametrize("slug", sorted(VALID_SLUGS))
def test_fixture_confidence_tier_is_valid_int(slug: str) -> None:
    result = load_fixture(slug)
    assert isinstance(result["confidence_tier"], int)
    assert result["confidence_tier"] in {0, 1, 2, 3}


@pytest.mark.parametrize("slug", sorted(VALID_SLUGS))
def test_fixture_methodology_is_list_of_dicts(slug: str) -> None:
    result = load_fixture(slug)
    assert isinstance(result["methodology"], list)
    for entry in result["methodology"]:
        assert "agent" in entry
        assert "status" in entry


@pytest.mark.parametrize("slug", sorted(VALID_SLUGS))
def test_fixture_citations_is_list_of_dicts(slug: str) -> None:
    result = load_fixture(slug)
    assert isinstance(result["citations"], list)
    for entry in result["citations"]:
        assert "source" in entry
        assert "finding" in entry


@pytest.mark.parametrize("slug", sorted(VALID_SLUGS))
def test_fixture_blind_spots_is_list(slug: str) -> None:
    result = load_fixture(slug)
    assert isinstance(result["blind_spots"], list)
    for bs in result["blind_spots"]:
        assert "source" in bs
        assert "reason" in bs
        assert "next_step" in bs


# --- tier / verdict accuracy ---

@pytest.mark.parametrize("slug,expected_tier", sorted(_EXPECTED_TIERS.items()))
def test_fixture_confidence_tier_matches_scenario(slug: str, expected_tier: int) -> None:
    assert load_fixture(slug)["confidence_tier"] == expected_tier


@pytest.mark.parametrize("slug,expected_verdict", sorted(_EXPECTED_VERDICTS.items()))
def test_fixture_verdict_string_matches_scenario(slug: str, expected_verdict: str) -> None:
    assert load_fixture(slug)["verdict"] == expected_verdict


def test_verdict_string_matches_tier_for_all_slugs() -> None:
    tier_to_verdict = {0: "Benign", 1: "Investigating", 2: "Probable", 3: "Confirmed"}
    for slug in VALID_SLUGS:
        result = load_fixture(slug)
        assert result["verdict"] == tier_to_verdict[result["confidence_tier"]]


# --- FixtureSchemaError on incomplete fixture ---

def test_fixture_schema_error_on_missing_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sentinel.web import demo

    slug = "bad-fixture"
    (tmp_path / f"{slug}.json").write_text(
        json.dumps({"verdict": "Confirmed"}), encoding="utf-8"
    )
    monkeypatch.setattr(demo, "VALID_SLUGS", frozenset({slug}))
    monkeypatch.setattr(demo, "_FIXTURES_DIR", tmp_path)

    with pytest.raises(FixtureSchemaError, match="missing required fields"):
        load_fixture(slug)


def test_fixture_schema_error_names_missing_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sentinel.web import demo

    slug = "partial-fixture"
    (tmp_path / f"{slug}.json").write_text(
        json.dumps({"verdict": "Benign", "confidence_tier": 0}), encoding="utf-8"
    )
    monkeypatch.setattr(demo, "VALID_SLUGS", frozenset({slug}))
    monkeypatch.setattr(demo, "_FIXTURES_DIR", tmp_path)

    with pytest.raises(FixtureSchemaError) as exc_info:
        load_fixture(slug)
    assert "timestamp" in str(exc_info.value)
