import json
from pathlib import Path
from typing import Any, cast

from sentinel.verdict import VerdictSchema

_FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "fixtures"

VALID_SLUGS: frozenset[str] = frozenset(
    {
        "lsass-credential-dumping",
        "tor-exit-node",
        "google-benign",
        "urlhaus-malware-ip",
        "ssh-brute-force",
    }
)

_REQUIRED_FIELDS: frozenset[str] = frozenset(
    {
        "verdict",
        "confidence_tier",
        "methodology",
        "citations",
        "blind_spots",
        "source_independence_confirmed",
        "execution_time_seconds",
        "timestamp",
    }
)


class UnknownSlugError(ValueError):
    pass


class FixtureSchemaError(ValueError):
    pass


def load_fixture(slug: str) -> VerdictSchema:
    """Load a demo fixture by slug. Raises UnknownSlugError for unrecognised slugs."""
    if slug not in VALID_SLUGS:
        raise UnknownSlugError(
            f"Unknown demo slug {slug!r}. Valid slugs: {sorted(VALID_SLUGS)}"
        )
    path = _FIXTURES_DIR / f"{slug}.json"
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    missing = _REQUIRED_FIELDS - data.keys()
    if missing:
        raise FixtureSchemaError(
            f"Fixture {slug!r} missing required fields: {sorted(missing)}"
        )
    return cast(VerdictSchema, data)
