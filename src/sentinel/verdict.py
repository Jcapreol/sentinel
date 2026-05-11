import json
import sys
import time
from datetime import datetime, timezone
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


def assemble_verdict(
    watchman_result: AgentResult,
    cipher_result: AgentResult,
    tier: tuple[int, str],
    source_independence_confirmed: bool,
    start_time: float,
) -> VerdictSchema:
    tier_int, tier_str = tier
    results = [watchman_result, cipher_result]
    methodology: list[dict[str, Any]] = [
        {
            "agent": r["source_name"],
            "status": "error" if r["error"] else "success",
            "error": r["error"],
        }
        for r in results
    ]
    citations: list[dict[str, Any]] = [
        {"source": r["source_name"], "finding": finding}
        for r in results
        for finding in r["findings"]
    ]
    blind_spots: list[BlindSpot] = [bs for r in results for bs in r["blind_spots"]]
    return VerdictSchema(
        verdict=tier_str,
        confidence_tier=tier_int,
        methodology=methodology,
        citations=citations,
        blind_spots=blind_spots,
        source_independence_confirmed=source_independence_confirmed,
        execution_time_seconds=round(time.time() - start_time, 3),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def print_verdict(verdict: VerdictSchema) -> None:
    print(json.dumps(verdict, indent=2), file=sys.stdout)
