from typing import Any, Protocol, TypedDict


class BlindSpot(TypedDict):
    source: str
    reason: str
    next_step: str | None


class AgentResult(TypedDict):
    source_name: str
    findings: list[str]
    blind_spots: list[BlindSpot]
    raw_confidence: str | None
    error: str | None


class VerdictSchema(TypedDict):
    verdict: str
    confidence_tier: int
    methodology: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    blind_spots: list[BlindSpot]
    source_independence_confirmed: bool
    execution_time_seconds: float
    timestamp: str


class SentinelAgent(Protocol):
    def analyze(self, input_data: str) -> AgentResult: ...
