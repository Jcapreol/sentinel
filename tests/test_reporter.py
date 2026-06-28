from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pytest_mock import MockerFixture

from conftest import make_agent_result
from sentinel.main import main
from sentinel.reporter import generate_report, write_report_markdown
from sentinel.verdict import VerdictSchema

if TYPE_CHECKING:
    from sentinel.config import Config


def _make_verdict(tier: str = "Confirmed", tier_int: int = 3) -> VerdictSchema:
    return VerdictSchema(
        verdict=tier,
        confidence_tier=tier_int,
        methodology=[],
        citations=[],
        blind_spots=[],
        source_independence_confirmed=True,
        execution_time_seconds=0.5,
        timestamp="2026-06-28T01-37-30+00:00",
    )


def test_report_generated_with_report_flag(
    mocker: MockerFixture,
    fake_config: Config,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    mocker.patch("sys.argv", ["sentinel", "--report", "suspicious traffic to 1.2.3.4"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    mocker.patch(
        "sentinel.main.write_report_markdown",
        return_value=tmp_path / "test-incident.md",
    )
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result(
        "watchman", findings=["Suspicious C2 beaconing detected"]
    )
    cipher_mock.return_value.analyze.return_value = make_agent_result(
        "cipher",
        findings=["VirusTotal: 1.2.3.4 flagged by 3 engines as malicious, 0 as suspicious"],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    output = json.loads(capsys.readouterr().out)
    assert "incident_report" in output


def test_report_contains_all_six_sections() -> None:
    watchman_result = make_agent_result(
        "watchman",
        findings=["Lateral movement detected [T1021]"],
    )
    watchman_result["mitre_tags"] = ["T1021"]
    cipher_result = make_agent_result(
        "cipher",
        findings=["VirusTotal: 1.2.3.4 flagged by 5 engines as malicious, 0 as suspicious"],
    )
    verdict = _make_verdict()

    report = generate_report(
        "suspicious traffic to 1.2.3.4",
        watchman_result,
        cipher_result,
        verdict,
    )

    assert "executive_summary" in report
    assert "indicator_details" in report
    assert "evidence_chain" in report
    assert "verdict_and_confidence" in report
    assert "mitre_attack_mapping" in report
    assert "recommended_next_steps" in report

    assert isinstance(report["executive_summary"], str)
    assert len(report["executive_summary"]) > 0
    assert isinstance(report["evidence_chain"], list)
    assert len(report["evidence_chain"]) == 2
    assert isinstance(report["recommended_next_steps"], list)
    assert len(report["recommended_next_steps"]) > 0


def test_mitre_tags_extracted_from_watchman_output() -> None:
    watchman_result = make_agent_result(
        "watchman",
        findings=["Command-and-control beaconing observed"],
    )
    watchman_result["mitre_tags"] = ["T1071", "T1041"]
    cipher_result = make_agent_result("cipher")
    verdict = _make_verdict()

    report = generate_report("alert text", watchman_result, cipher_result, verdict)

    assert "T1071" in report["mitre_attack_mapping"]
    assert "T1041" in report["mitre_attack_mapping"]


def test_markdown_file_written_to_reports_dir(tmp_path: Path) -> None:
    watchman_result = make_agent_result(
        "watchman", findings=["Suspicious outbound connection"]
    )
    watchman_result["mitre_tags"] = ["T1071", "T1999"]  # known + unknown tag
    cipher_result = make_agent_result(
        "cipher",
        findings=["AbuseIPDB: 1.2.3.4 abuse confidence 80% from 12 reports"],
    )
    verdict = _make_verdict()
    report = generate_report("alert to 1.2.3.4", watchman_result, cipher_result, verdict)

    md_path = write_report_markdown(report, verdict["timestamp"], reports_dir=tmp_path)

    assert md_path.exists()
    content = md_path.read_text(encoding="utf-8")
    assert "# Sentinel Incident Report" in content
    assert "## Executive Summary" in content
    assert "## Indicator Details" in content
    assert "## Evidence Chain" in content
    assert "## Verdict and Confidence" in content
    assert "## MITRE ATT&CK Mapping" in content
    assert "## Recommended Next Steps" in content
    # known tag renders with name; unknown tag renders as-is
    assert "T1071 — Application Layer Protocol" in content
    assert "T1999" in content
    assert "T1999 —" not in content


def test_existing_behavior_unchanged_without_flag(
    mocker: MockerFixture,
    fake_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel", "suspicious traffic to 1.2.3.4"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result(
        "watchman", findings=["Suspicious C2 beaconing"]
    )
    cipher_mock.return_value.analyze.return_value = make_agent_result(
        "cipher",
        findings=["VirusTotal: 1.2.3.4 flagged by 3 engines as malicious, 0 as suspicious"],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    output = json.loads(capsys.readouterr().out)
    assert "incident_report" not in output
    assert "verdict" in output
    assert "confidence_tier" in output
