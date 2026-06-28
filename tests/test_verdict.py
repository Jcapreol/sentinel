import json
import time
import typing

import pytest

from conftest import make_agent_result
from sentinel.verdict import (
    AgentResult,
    BlindSpot,
    SentinelAgent,
    VerdictSchema,
    assemble_verdict,
    print_verdict,
)


def test_blindspot_fields() -> None:
    bs = BlindSpot(source="watchman", reason="timed out", next_step=None)
    assert bs["source"] == "watchman"
    assert bs["reason"] == "timed out"
    assert bs["next_step"] is None


def test_blindspot_next_step_can_be_string() -> None:
    bs = BlindSpot(
        source="cipher",
        reason="VirusTotal rate limited",
        next_step="Retry after 60 seconds or check VT web UI",
    )
    assert bs["next_step"] == "Retry after 60 seconds or check VT web UI"


def test_agent_result_fields() -> None:
    bs = BlindSpot(source="watchman", reason="timed out", next_step=None)
    result = AgentResult(
        source_name="watchman",
        findings=["suspicious behavior"],
        blind_spots=[bs],
        raw_confidence=None,
        error="timeout",
    )
    assert result["source_name"] == "watchman"
    assert result["findings"] == ["suspicious behavior"]
    assert result["raw_confidence"] is None
    assert result["error"] == "timeout"


def test_agent_result_blind_spots_is_list_of_blindspot() -> None:
    # Verify blind_spots holds BlindSpot dicts, not plain strings (architecture fix)
    bs = BlindSpot(source="cipher", reason="rate limited", next_step=None)
    result = AgentResult(
        source_name="cipher",
        findings=[],
        blind_spots=[bs],
        raw_confidence=None,
        error="rate_limited",
    )
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["source"] == "cipher"
    assert result["blind_spots"][0]["reason"] == "rate limited"


def test_verdict_schema_has_exactly_nine_fields() -> None:
    hints = typing.get_type_hints(VerdictSchema, include_extras=True)
    assert set(hints.keys()) == {
        "verdict",
        "confidence_tier",
        "methodology",
        "citations",
        "blind_spots",
        "source_independence_confirmed",
        "execution_time_seconds",
        "timestamp",
        "incident_report",
    }


def test_verdict_schema_fields() -> None:
    verdict = VerdictSchema(
        verdict="Probable",
        confidence_tier=2,
        methodology=[{"agent": "watchman", "action": "behavioral_analysis"}],
        citations=[{"source": "VirusTotal", "indicator": "1.2.3.4"}],
        blind_spots=[],
        source_independence_confirmed=True,
        execution_time_seconds=18.4,
        timestamp="2026-05-11T00:00:00Z",
    )
    assert verdict["verdict"] == "Probable"
    assert verdict["confidence_tier"] == 2
    assert verdict["source_independence_confirmed"] is True
    assert verdict["blind_spots"] == []
    assert isinstance(verdict["execution_time_seconds"], float)


def test_sentinel_agent_protocol_satisfied_structurally() -> None:
    # Annotating as SentinelAgent lets mypy verify structural conformance
    class MockAgent:
        def analyze(self, input_data: str) -> AgentResult:
            return AgentResult(
                source_name="mock",
                findings=[],
                blind_spots=[],
                raw_confidence=None,
                error=None,
            )

    agent: SentinelAgent = MockAgent()
    result = agent.analyze("test alert")
    assert result["source_name"] == "mock"
    assert result["blind_spots"] == []
    assert result["error"] is None


def test_assemble_verdict_investigating_tier() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher", error="timeout")
    verdict = assemble_verdict(watchman, cipher, (1, "Investigating"), False, time.time())
    assert verdict["confidence_tier"] == 1
    assert verdict["verdict"] == "Investigating"
    assert verdict["source_independence_confirmed"] is False


def test_assemble_verdict_probable_tier() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    verdict = assemble_verdict(watchman, cipher, (2, "Probable"), True, time.time())
    assert verdict["confidence_tier"] == 2
    assert verdict["verdict"] == "Probable"
    assert verdict["source_independence_confirmed"] is True


def test_assemble_verdict_blind_spots_always_list() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    verdict = assemble_verdict(watchman, cipher, (2, "Probable"), True, time.time())
    assert isinstance(verdict["blind_spots"], list)


def test_assemble_verdict_blind_spots_merged_from_both_agents() -> None:
    bs1 = BlindSpot(source="watchman", reason="timed out", next_step=None)
    bs2 = BlindSpot(source="cipher", reason="rate limited", next_step=None)
    watchman = make_agent_result(source="watchman", blind_spots=[bs1], error="timeout")
    cipher = make_agent_result(source="cipher", blind_spots=[bs2], error="rate_limited")
    verdict = assemble_verdict(watchman, cipher, (1, "Investigating"), False, time.time())
    assert len(verdict["blind_spots"]) == 2
    sources = {bs["source"] for bs in verdict["blind_spots"]}
    assert sources == {"watchman", "cipher"}


def test_assemble_verdict_json_round_trip() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    verdict = assemble_verdict(watchman, cipher, (2, "Probable"), True, time.time())
    parsed = json.loads(json.dumps(verdict))
    assert parsed["confidence_tier"] == 2
    assert parsed["verdict"] == "Probable"
    assert isinstance(parsed["blind_spots"], list)


def test_print_verdict_goes_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    verdict = assemble_verdict(watchman, cipher, (2, "Probable"), True, time.time())
    print_verdict(verdict)
    captured = capsys.readouterr()
    assert captured.out.strip() != ""
    assert captured.err == ""
    parsed = json.loads(captured.out)
    assert parsed["confidence_tier"] == 2


def test_assemble_verdict_all_fields_present_when_both_agents_fail() -> None:
    bs_w = BlindSpot(source="watchman", reason="timed out", next_step=None)
    bs_c = BlindSpot(source="cipher", reason="timed out", next_step=None)
    watchman = make_agent_result(source="watchman", blind_spots=[bs_w], error="timeout")
    cipher = make_agent_result(source="cipher", blind_spots=[bs_c], error="timeout")
    verdict = assemble_verdict(watchman, cipher, (1, "Investigating"), False, time.time())
    assert verdict["verdict"] == "Investigating"
    assert verdict["confidence_tier"] == 1
    assert isinstance(verdict["blind_spots"], list)
    assert len(verdict["blind_spots"]) == 2
    assert verdict["execution_time_seconds"] >= 0
    assert isinstance(verdict["timestamp"], str)
    assert len(verdict["timestamp"]) > 0
