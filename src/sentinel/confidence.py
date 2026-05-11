from enum import Enum

from sentinel.source_registry import SOURCE_CATEGORIES
from sentinel.verdict import AgentResult


class ConfidenceTier(Enum):
    INVESTIGATING = "Investigating"
    PROBABLE = "Probable"
    CONFIRMED = "Confirmed"


TIER_MAP: dict[ConfidenceTier, tuple[int, str]] = {
    ConfidenceTier.INVESTIGATING: (1, "Investigating"),
    ConfidenceTier.PROBABLE: (2, "Probable"),
    ConfidenceTier.CONFIRMED: (3, "Confirmed"),
}


def count_independent_sources(results: list[AgentResult]) -> int:
    categories: set[str] = set()
    for result in results:
        if result["error"] is None:
            cat = SOURCE_CATEGORIES.get(result["source_name"])
            if cat is not None:
                categories.add(cat)
    return len(categories)


def calculate_tier(results: list[AgentResult]) -> ConfidenceTier:
    count = count_independent_sources(results)
    if count >= 3:
        return ConfidenceTier.CONFIRMED
    if count >= 2:
        return ConfidenceTier.PROBABLE
    return ConfidenceTier.INVESTIGATING
