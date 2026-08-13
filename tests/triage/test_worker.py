import ast
import base64
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from googleapiclient.errors import HttpError

from sentinel.config import Config, ConfigError
from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.ingest import FetchFailed, fetch_headers_for_messages
from sentinel.triage.report import TriageReport
from sentinel.triage.script_guard import ApiCallBudgetExceededError
from sentinel.triage.scoring import apply_calibration, compute_raw_score, determine_verdict
from sentinel.triage.store import (
    EvidenceRecord,
    is_message_processed,
    persist_evidence_record,
    read_evidence_record,
)
from sentinel.triage.worker import (
    check_structural_deferral,
    gather_evidence_and_raw_score,
    main,
    process_message,
    run_continuous_loop,
    run_poll_cycle,
    run_test_alert,
    run_view,
)
from sentinel.verdict import AgentResult, SentinelAgent


def _config(deferral_threshold: float = 0.05) -> Config:
    return Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        deferral_threshold=deferral_threshold,
    )


class _NeutralAgent:
    """SentinelAgent stub contributing zero evidence -- process_message's
    header-directional tests stay driven purely by header evidence, exactly
    as before Story 2.2's pipeline wiring (empty evidence list means nothing
    is added to the merged evidence fed to compute_raw_score)."""

    def analyze(self, input_data: str) -> AgentResult:
        return AgentResult(
            source_name="stub",
            findings=[],
            blind_spots=[],
            raw_confidence=None,
            error=None,
            evidence=[],
        )


_neutral_agent: SentinelAgent = _NeutralAgent()


def test_process_message_malicious_header_returns_malicious_verdict() -> None:
    header = "spf=fail; dkim=fail; dmarc=fail"

    report = process_message("m1", header, "", _neutral_agent, _neutral_agent, _config())

    assert report["verdict"] == "Malicious"
    assert len(report["evidence"]) > 0


def test_process_message_benign_header_returns_benign_verdict() -> None:
    header = "spf=pass; dkim=pass; dmarc=pass"

    report = process_message("m1", header, "", _neutral_agent, _neutral_agent, _config())

    assert report["verdict"] == "Benign"


def test_process_message_no_header_defers() -> None:
    report = process_message("m1", None, "", _neutral_agent, _neutral_agent, _config())

    assert report["verdict"] == "Deferred"
    assert len(report["evidence"]) > 0


def test_process_message_no_informative_evidence_defers_structurally_even_if_calibration_saturates(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """[Fix] Regression test for the exact bug that just occurred in
    production: a real fitted calibration curve that saturates hard to
    0.0/1.0 (a pure step function, never landing anywhere near the neutral
    prior) silently defeated deferral_band-based protection for the
    zero-evidence case -- apply_calibration(0.5) == 1.0 under the real
    committed model, so a message with NO real evidence anywhere got
    verdict="Malicious" instead of "Deferred". This proves the NEW
    structural bypass (mirroring the FetchFailed precedent) protects the
    zero-evidence case independent of calibration behavior entirely --
    even with apply_calibration mocked to ALWAYS return 1.0 (the worst
    case, maximally "confident"-looking saturation), a message with no
    informative evidence anywhere (no header, neutral Watchman/Cipher)
    must still defer. This is what stops it from silently regressing
    again the way it just did, no matter how a future calibration fit
    happens to shape its curve."""
    mocker.patch("sentinel.triage.worker.apply_calibration", return_value=1.0)

    report = process_message("m1", None, "", _neutral_agent, _neutral_agent, _config())

    assert report["verdict"] == "Deferred"


def test_process_message_score_inside_deferral_band_defers() -> None:
    # dmarc=pass (benign, weight 0.45) vs spf=fail (malicious, weight 0.40) yields
    # a raw score close to 0.5 (weak-but-PRESENT, nearly-canceling directional
    # evidence) -- within the default 0.05 deferral_band around 0.5. Proves the
    # config.deferral_threshold -> worker -> scoring.py wiring actually defers
    # on a close-but-not-exact score, not just on the exact-neutral case
    # already covered by test_process_message_no_header_defers.
    #
    # [Fix] Previously deliberately left failing: the real fitted calibration
    # model committed 2026-07-28 is a hard 0.0/1.0 step function (the corpus
    # has no ambiguous/conflicting-evidence examples for PAVA to fit a middle
    # output to), so this raw score calibrated to a confident 1.0 -- no
    # deferral_band value on the CALIBRATED score could catch it, since 0.0
    # and 1.0 are both always exactly 0.5 from the neutral prior under that
    # curve shape. Resolved by a second structural deferral gate in
    # process_message that checks raw_score directly, before apply_calibration
    # ever runs -- a stopgap pending a broader calibration corpus (see
    # deferred-work.md), not a permanent design choice.
    header = "dmarc=pass; spf=fail"

    report = process_message(
        "m1", header, "", _neutral_agent, _neutral_agent, _config(deferral_threshold=0.05)
    )

    assert report["verdict"] == "Deferred"
    assert abs(report["calibrated_confidence"] - 0.5) < 0.05


def test_process_message_conflicting_evidence_defers_structurally_even_if_calibration_saturates(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """[Fix] Regression test for the second half of the production incident:
    weak-but-PRESENT, nearly-canceling directional evidence (dmarc=pass vs
    spf=fail) is real signal, so the all-neutral bypass correctly does not
    catch it -- but the real fitted calibration curve cannot yet be trusted to
    preserve that uncertainty (it's a hard 0.0/1.0 step function with no
    middle output). This proves the NEW raw-score structural deferral gate
    protects this case independent of calibration behavior entirely -- even
    with apply_calibration mocked to ALWAYS return 1.0 (the worst case), a
    message whose evidence nearly cancels around the neutral prior must still
    defer."""
    mocker.patch("sentinel.triage.worker.apply_calibration", return_value=1.0)
    header = "dmarc=pass; spf=fail"

    report = process_message(
        "m1", header, "", _neutral_agent, _neutral_agent, _config(deferral_threshold=0.05)
    )

    assert report["verdict"] == "Deferred"


def test_check_structural_deferral_true_for_all_neutral_evidence(
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    evidence = [make_evidence_item(name="spf", direction="neutral", weight=0.10)]

    assert check_structural_deferral(evidence, raw_score=0.5, deferral_band=0.0) is True


def test_check_structural_deferral_true_at_exact_neutral_prior_regardless_of_band(
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    # Directional (non-neutral) evidence, but raw_score==0.5 exactly -- Gate 1
    # (all-neutral) does not apply, but Gate 2's math.isclose check must still
    # catch this even with deferral_band=0.0 (the narrowest possible band).
    evidence = [make_evidence_item(name="spf", direction="malicious", weight=0.4)]

    assert check_structural_deferral(evidence, raw_score=0.5, deferral_band=0.0) is True


def test_check_structural_deferral_true_for_raw_score_within_band(
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    evidence = [make_evidence_item(name="spf", direction="malicious", weight=0.4)]

    assert check_structural_deferral(evidence, raw_score=0.47, deferral_band=0.05) is True


def test_check_structural_deferral_false_for_directional_evidence_outside_band(
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    evidence = [make_evidence_item(name="spf", direction="malicious", weight=0.8)]

    assert check_structural_deferral(evidence, raw_score=0.9, deferral_band=0.05) is False


def test_gather_evidence_and_raw_score_propagates_watchman_budget_exceeded_uncaught() -> None:
    """Story 4.2 regression guard: found during that story's implementation
    -- this function's own except Exception: blocks around
    watchman_future.result()/cipher_future.result() previously swallowed
    ANY exception (including ApiCallBudgetExceededError) into a normal
    "crashed unexpectedly" coverage-gap EvidenceItem, silently letting a
    real-corpus script continue past its configured API call ceiling one
    file at a time -- exactly what AC3 forbids. Confirmed via
    fit_real_calibration_model.py's own test suite actually running to
    completion and writing an output file when it should have aborted,
    before this fix. Only reachable when a caller's agent raises
    ApiCallBudgetExceededError (the two real-corpus scripts); worker.py's
    own live-triage WatchmanAgent(config)/CipherAgent(config) never
    construct a budget object, so this can never fire from process_message."""

    class _BudgetExceededAgent:
        def analyze(self, input_data: str) -> AgentResult:
            raise ApiCallBudgetExceededError("ceiling reached")

    budget_exceeded_agent: SentinelAgent = _BudgetExceededAgent()

    with pytest.raises(ApiCallBudgetExceededError):
        gather_evidence_and_raw_score(None, "content", budget_exceeded_agent, _neutral_agent)


def test_gather_evidence_and_raw_score_propagates_cipher_budget_exceeded_uncaught() -> None:
    class _BudgetExceededAgent:
        def analyze(self, input_data: str) -> AgentResult:
            raise ApiCallBudgetExceededError("ceiling reached")

    budget_exceeded_agent: SentinelAgent = _BudgetExceededAgent()

    with pytest.raises(ApiCallBudgetExceededError):
        gather_evidence_and_raw_score(None, "content", _neutral_agent, budget_exceeded_agent)


def test_process_message_never_raises_inconclusive_score_error() -> None:
    # Empty/neutral evidence would raise InconclusiveScoreError inside
    # determine_verdict — process_message must catch it internally, never
    # propagate it to the caller.
    report = process_message("m1", None, "", _neutral_agent, _neutral_agent, _config())

    assert report["verdict"] == "Deferred"


def test_process_message_message_hash_is_deterministic_sha256_of_message_id() -> None:
    report = process_message(
        "abc-123", "spf=pass", "", _neutral_agent, _neutral_agent, _config()
    )

    assert report["message_hash"] == hashlib.sha256(b"abc-123").hexdigest()


def test_process_message_produces_no_disk_io(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)

    process_message("m1", "spf=pass", "", _neutral_agent, _neutral_agent, _config())

    assert list(tmp_path.iterdir()) == []


def test_process_message_schema_version_is_one() -> None:
    report = process_message("m1", "spf=pass", "", _neutral_agent, _neutral_agent, _config())

    assert report["schema_version"] == 1


def test_process_message_fetch_failed_defers_never_directional() -> None:
    # A header fetch failure (Story 1.3's FetchFailed sentinel) must never be
    # treated as evidence — it must always defer, the same way
    # InconclusiveScoreError does, regardless of deferral_threshold.
    report = process_message(
        "m1", FetchFailed(), "", _neutral_agent, _neutral_agent, _config()
    )

    assert report["verdict"] == "Deferred"
    assert report["verdict"] != "Malicious"
    assert report["verdict"] != "Benign"


def _assert_never_confidence_half_with_empty_evidence(report: TriageReport) -> None:
    """[Story 6.1, AC3] The core invariant this story exists to enforce:
    confidence 0.500 must never co-occur with an empty evidence/findings
    list. Before this story, EVERY ingest-layer fetch-failure path produced
    exactly that combination (Deferred, calibrated_confidence=0.5,
    evidence=[<one synthetic placeholder item>]) -- misrepresenting "no
    analysis happened" as "analysis happened and was genuinely uncertain,"
    which polluted calibration metrics with entries that were never real
    predictions. After this story, the only path producing empty evidence
    is CoverageGap, which never carries confidence 0.5 (it carries None) --
    checked both directions here, not just one, since either direction
    failing would reopen the bug this story closes."""
    if report["evidence"] == []:
        assert report["calibrated_confidence"] is None, (
            f"report with empty evidence must have confidence=None, got "
            f"{report['calibrated_confidence']!r} (verdict={report['verdict']!r})"
        )
    if report["calibrated_confidence"] == 0.5:
        assert report["evidence"] != [], (
            "report with confidence=0.5 must have real, non-empty evidence "
            f"(verdict={report['verdict']!r})"
        )


def test_no_code_path_emits_confidence_half_with_empty_evidence(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Story 6.1, AC3] Exercises every currently-known TriageReport-
    producing code path and asserts the invariant on each of their outputs.
    Fails if a future change reintroduces the bug on any of these paths, or
    adds a new path that violates it."""
    config = store_config

    # Path 1: process_message, header fetch failed (FetchFailed) -- stays
    # Deferred by design (message content itself was available), not
    # CoverageGap, but must still respect the invariant.
    header_fetch_failed_report = process_message(
        "m1", FetchFailed(), "", _neutral_agent, _neutral_agent, config
    )
    _assert_never_confidence_half_with_empty_evidence(header_fetch_failed_report)

    # Path 2: process_message, structural deferral Gate 1 (all-neutral
    # evidence) -- real evidence was gathered (header investigation always
    # contributes at least one item per SPF/DKIM/DMARC mechanism), just
    # entirely uninformative. Must have confidence 0.5 with NON-empty
    # evidence (the normal, correct case this invariant protects).
    structural_deferral_report = process_message(
        "m2", None, "irrelevant content", _neutral_agent, _neutral_agent, config
    )
    assert structural_deferral_report["calibrated_confidence"] == 0.5
    assert structural_deferral_report["evidence"] != []
    _assert_never_confidence_half_with_empty_evidence(structural_deferral_report)

    # Path 3: run_poll_cycle, raw-content-fetch failure (the real-world
    # coverage-gap case -- Gmail 404, message unavailable). Must now be
    # CoverageGap with empty evidence and confidence=None.
    from sentinel.triage.store import read_evidence_record, save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    gmail_config = replace(
        config,
        gmail_monitored_mailbox="soc@example.com",
        gmail_credentials_path="secrets/gmail-service-account.json",
    )
    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m3"}}]}]
    }
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        RuntimeError("boom"),
        {"payload": {"headers": []}},  # Story 5.2.1 fallback marker/sender fetch
    ]

    run_poll_cycle(gmail_config, store_db_path, _neutral_agent, _neutral_agent)

    coverage_gap_hash = hashlib.sha256(b"m3").hexdigest()
    record = read_evidence_record(store_db_path, coverage_gap_hash, gmail_config)
    assert record is not None
    coverage_gap_report = record["report"]
    assert coverage_gap_report["verdict"] == "CoverageGap"
    _assert_never_confidence_half_with_empty_evidence(coverage_gap_report)


def test_process_message_fetch_failed_never_calls_header_investigation(mocker) -> None:  # type: ignore[no-untyped-def]
    # FetchFailed must short-circuit before investigate_header_authentication is
    # ever called — a fetch failure carries no header data to investigate.
    spy = mocker.patch("sentinel.triage.worker.investigate_header_authentication")

    process_message("m1", FetchFailed(), "", _neutral_agent, _neutral_agent, _config())

    spy.assert_not_called()


def test_process_message_fetch_failed_with_extreme_deferral_threshold_still_defers() -> None:
    # Even with deferral_threshold=0.0 (the narrowest possible band), a
    # FetchFailed must still defer — this is a hard routing rule, not a
    # side effect of the band width.
    report = process_message(
        "m1", FetchFailed(), "", _neutral_agent, _neutral_agent, _config(deferral_threshold=0.0)
    )

    assert report["verdict"] == "Deferred"


def test_process_message_end_to_end_fetch_failure_never_yields_directional_verdict(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    service = mocker.MagicMock()
    mocker.patch(
        "sentinel.triage.ingest.get_authentication_results_header",
        side_effect=RuntimeError("boom"),
    )

    fetch_results = fetch_headers_for_messages(service, "soc@example.com", [{"id": "m1"}])
    report = process_message(
        "m1", fetch_results["m1"], "", _neutral_agent, _neutral_agent, _config()
    )

    assert report["verdict"] == "Deferred"


def test_process_message_raises_config_error_when_deferral_threshold_above_range() -> None:
    with pytest.raises(ConfigError, match="SENTINEL_DEFERRAL_THRESHOLD"):
        process_message(
            "m1", "spf=pass", "", _neutral_agent, _neutral_agent, _config(deferral_threshold=1.5)
        )


def test_process_message_raises_config_error_when_deferral_threshold_below_range() -> None:
    with pytest.raises(ConfigError, match="SENTINEL_DEFERRAL_THRESHOLD"):
        process_message(
            "m1", "spf=pass", "", _neutral_agent, _neutral_agent, _config(deferral_threshold=-0.1)
        )


def test_process_message_aggregates_evidence_from_headers_watchman_and_cipher() -> None:
    """AC4: proves the verdict function correctly aggregates all three
    sources, not just header evidence -- the actual point of this story's
    pipeline wiring, per AC4's own wording."""

    class _MaliciousStub:
        def __init__(self, name: str) -> None:
            self._name = name

        def analyze(self, input_data: str) -> AgentResult:
            return AgentResult(
                source_name=self._name,
                findings=["synthetic malicious finding"],
                blind_spots=[],
                raw_confidence="Confirmed",
                error=None,
                evidence=[
                    EvidenceItem(
                        # Deliberately generic/synthetic name, not a real
                        # CipherAgent/WatchmanAgent evidence name -- this test
                        # validates Protocol-level aggregation, not either
                        # concrete agent's literal output shape.
                        name="stub_finding",
                        finding="synthetic malicious finding",
                        weight=0.7,
                        direction="malicious",
                    )
                ],
            )

    watchman_stub: SentinelAgent = _MaliciousStub("watchman")
    cipher_stub: SentinelAgent = _MaliciousStub("cipher")
    header = "spf=fail"  # malicious, weight 0.40 alone -> not enough for "Malicious" verdict

    header_only_report = process_message(
        "m1", header, "", _neutral_agent, _neutral_agent, _config()
    )
    combined_report = process_message(
        "m1", header, "synthetic email content", watchman_stub, cipher_stub, _config()
    )

    watchman_names = {item["name"] for item in combined_report["evidence"]}
    # Names are deliberately synthetic/generic ("stub_finding"), not real
    # CipherAgent/WatchmanAgent output shapes -- this test validates
    # SentinelAgent Protocol-level aggregation (per the Testing Standards
    # section above), not either concrete agent's exact evidence naming.
    assert len([n for n in watchman_names if n == "stub_finding"]) >= 1
    # [Fix] Combined score must reflect all three sources' weighted
    # contribution, not just the header's -- strictly more malicious-leaning
    # than header alone. Retargeted to RAW score (via compute_raw_score on
    # each report's own returned `evidence`, not a reimplementation) rather
    # than calibrated_confidence: a real fitted calibration curve is only
    # guaranteed monotonic non-decreasing, not STRICTLY increasing -- once a
    # saturating curve maps two genuinely different raw scores into the same
    # output bucket (e.g. a hard step function's two possible outputs, 0.0
    # or 1.0), the calibrated values legitimately tie even though evidence
    # aggregation worked correctly. Evidence aggregation's actual guarantee
    # is about the RAW weighted sum, which calibration is never required to
    # preserve strict ordering through.
    header_only_raw = compute_raw_score(header_only_report["evidence"])
    combined_raw = compute_raw_score(combined_report["evidence"])
    assert combined_raw > header_only_raw


def test_process_message_agent_crash_degrades_to_coverage_gap_not_raising() -> None:
    """2026-07-23 code-review patch: process_message previously called
    .result() unguarded, resting on an unenforced comment claiming
    SentinelAgent.analyze() never raises -- true for the two shipped
    agents, but not enforced by the bare Protocol process_message is
    deliberately typed against. A third-party agent violating that
    assumption must degrade to a coverage-gap evidence item, matching every
    other failure path in this pipeline, not crash process_message."""

    class _CrashingAgent:
        def analyze(self, input_data: str) -> AgentResult:
            raise RuntimeError("simulated third-party agent crash")

    crashing_agent: SentinelAgent = _CrashingAgent()

    report = process_message(
        "m1", "spf=pass", "content", crashing_agent, _neutral_agent, _config()
    )

    assert report["verdict"] in ("Malicious", "Benign", "Deferred")
    assert any("crashed" in item["finding"].lower() for item in report["evidence"])


def test_process_message_agent_missing_evidence_key_does_not_crash() -> None:
    """A Protocol-conforming agent that omits the optional `evidence` key
    entirely (legal per AgentResult's total=False) must not raise a
    KeyError inside process_message."""

    class _IncompleteAgent:
        def analyze(self, input_data: str) -> AgentResult:
            return AgentResult(
                source_name="incomplete",
                findings=[],
                blind_spots=[],
                raw_confidence=None,
                error=None,
            )

    incomplete_agent: SentinelAgent = _IncompleteAgent()

    report = process_message(
        "m1", "spf=pass", "content", incomplete_agent, _neutral_agent, _config()
    )

    assert report["verdict"] in ("Malicious", "Benign", "Deferred")


def test_bad_deferral_threshold_does_not_affect_cli_web_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad SENTINEL_DEFERRAL_THRESHOLD must not break config.load() (the shared
    entry point CLI/web dashboard call) — only triage's own process_message, which
    is the only consumer of this field, validates it."""
    from sentinel.config import load

    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-test")
    monkeypatch.setenv("SENTINEL_DEFERRAL_THRESHOLD", "1.5")

    config = load()  # must not raise — CLI/web dashboard startup unaffected

    assert config.anthropic_api_key == "ak-test"


# --- --replay -------------------------------------------------------------------


def _make_report(
    verdict: str = "Malicious",
    calibrated_confidence: float | None = 0.9,
    evidence: list[EvidenceItem] | None = None,
    schema_version: int = 1,
    message_hash: str = "idhash123",
    timestamp: str = "2026-07-22T00:00:00+00:00",
    coverage_gap_reason: str | None = None,
) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[typeddict-item]
        calibrated_confidence=calibrated_confidence,
        evidence=evidence if evidence is not None else [],
        schema_version=schema_version,
        message_hash=message_hash,
        timestamp=timestamp,
        coverage_gap_reason=coverage_gap_reason,
    )


def test_replay_matching_exits_zero(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    evidence = [make_evidence_item(name="spf", direction="malicious", weight=0.8)]
    raw_score = compute_raw_score(evidence)
    # calibrated_confidence == apply_calibration(raw_score), which numerically
    # equals raw_score under the Story 3.2 "identity" placeholder -- writing it
    # via apply_calibration (not raw_score directly) so this test keeps working
    # unchanged once a real calibration model replaces the placeholder.
    calibrated_confidence = apply_calibration(raw_score)
    verdict = determine_verdict(calibrated_confidence, deferral_band=store_config.deferral_threshold)
    report = _make_report(
        verdict=verdict, calibrated_confidence=calibrated_confidence, evidence=evidence
    )
    record = EvidenceRecord(
        message_id="m1",
        sender="alice@example.com",
        report=report,
        deferral_threshold_used=store_config.deferral_threshold,
    )
    persist_evidence_record(store_db_path, "contenthash1", record, store_config)

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "contenthash1", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0


def test_replay_mismatch_exits_nonzero(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    evidence = [make_evidence_item(name="spf", direction="malicious", weight=0.8)]
    # Stored verdict/score deliberately does NOT match what honest recomputation
    # from this evidence would produce (simulates a scoring-logic regression).
    report = _make_report(verdict="Benign", calibrated_confidence=0.1, evidence=evidence)
    record = EvidenceRecord(
        message_id="m1",
        sender=None,
        report=report,
        deferral_threshold_used=store_config.deferral_threshold,
    )
    persist_evidence_record(store_db_path, "contenthash2", record, store_config)

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "contenthash2", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0


def test_replay_not_found_exits_nonzero(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "no-such-hash", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0


def test_replay_unexpected_schema_version_exits_nonzero(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    report = _make_report(schema_version=2)  # unexpected/future version
    record = EvidenceRecord(
        message_id="m1",
        sender=None,
        report=report,
        deferral_threshold_used=store_config.deferral_threshold,
    )
    persist_evidence_record(store_db_path, "contenthash3", record, store_config)

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "contenthash3", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0


def test_replay_uses_stored_deferral_threshold_not_live_config(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    # dmarc=pass (benign, 0.45) vs spf=fail (malicious, 0.40) -> raw score ~0.4706.
    # With a narrow ORIGINAL deferral_threshold (0.01), this score is directional
    # (Benign), not deferred. If replay incorrectly used a WIDE LIVE config value
    # instead of the stored one, 0.4706 would fall inside the band and recompute
    # as Deferred -- a false mismatch. This test proves the stored value wins.
    evidence = [
        make_evidence_item(name="dmarc", direction="benign", weight=0.45),
        make_evidence_item(name="spf", direction="malicious", weight=0.40),
    ]
    raw_score = compute_raw_score(evidence)
    # See test_replay_matching_exits_zero's comment: written via
    # apply_calibration (identity today) rather than raw_score directly.
    calibrated_confidence = apply_calibration(raw_score)
    original_threshold_used = 0.01
    verdict = determine_verdict(calibrated_confidence, deferral_band=original_threshold_used)
    report = _make_report(
        verdict=verdict, calibrated_confidence=calibrated_confidence, evidence=evidence
    )
    record = EvidenceRecord(
        message_id="m1",
        sender=None,
        report=report,
        deferral_threshold_used=original_threshold_used,
    )
    persist_evidence_record(store_db_path, "contenthash4", record, store_config)

    live_config = replace(store_config, deferral_threshold=0.05)  # wide, would defer

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "contenthash4", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=live_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0


def test_replay_recomputes_calibration_not_raw_score(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    """Regression guard for the pre-Epic-3 landmine (deferred-work.md):
    _run_replay must recompute calibration during replay and compare
    calibrated-to-calibrated, not the stored calibrated_confidence against a
    freshly recomputed RAW score. Proven by mocking apply_calibration to a
    non-identity transform: the stored calibrated_confidence (0.75) and the
    raw score (1.0) are then deliberately DIFFERENT numbers. If _run_replay
    still compared against the raw score (the old landmine), this would
    report a false mismatch; replaying under the same (mocked) calibration
    must match instead."""
    evidence = [make_evidence_item(name="spf", direction="malicious", weight=0.8)]
    raw_score = compute_raw_score(evidence)
    assert raw_score == 1.0  # sanity: single fully-malicious item saturates the score

    mocker.patch(
        "sentinel.triage.worker.apply_calibration", side_effect=lambda x: 0.5 + (x - 0.5) * 0.5
    )
    calibrated_confidence = 0.5 + (raw_score - 0.5) * 0.5
    assert calibrated_confidence != raw_score  # the two quantities must genuinely differ here

    verdict = determine_verdict(calibrated_confidence, deferral_band=store_config.deferral_threshold)
    report = _make_report(
        verdict=verdict, calibrated_confidence=calibrated_confidence, evidence=evidence
    )
    record = EvidenceRecord(
        message_id="m1",
        sender=None,
        report=report,
        deferral_threshold_used=store_config.deferral_threshold,
    )
    persist_evidence_record(store_db_path, "contenthash-calib", record, store_config)

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "contenthash-calib", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0


def test_replay_coverage_gap_record_refuses_with_clear_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """[Story 6.1] A CoverageGap record has no evidence and no
    calibrated_confidence -- there is nothing to recompute and compare, so
    replay must refuse explicitly with a clear message, not crash trying
    to math.isclose(None, ...) or misleadingly "match" via
    compute_raw_score([]) happening to equal something. A non-zero exit
    code alone isn't proof of a clean refusal -- an unguarded crash caught
    only by main()'s generic catch-all would also exit non-zero, so this
    test also pins the exact, specific stderr message and rejects the
    generic "unexpected error" wording that catch-all uses."""
    report = _make_report(
        verdict="CoverageGap",
        calibrated_confidence=None,
        evidence=[],
        coverage_gap_reason="Failed to fetch raw message content: HttpError 404",
    )
    record = EvidenceRecord(
        message_id="m1",
        sender=None,
        report=report,
        deferral_threshold_used=store_config.deferral_threshold,
    )
    persist_evidence_record(store_db_path, "idhash123", record, store_config)

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "idhash123", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0
    err = capsys.readouterr().err.lower()
    assert "unexpected error" not in err
    assert "coveragegap" in err
    assert "nothing" in err or "no analysis" in err or "no evidence" in err


def test_replay_legacy_record_missing_deferral_threshold_used_exits_nonzero_with_clear_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A record persisted before Story 1.6 (no deferral_threshold_used key at
    all, since EvidenceRecord is a schema-less JSON blob) must produce a clear,
    specific stderr error and a non-zero exit -- not an unguarded KeyError
    caught only by main()'s generic catch-all. Regression guard (2026-07-22
    code-review follow-up)."""
    import json

    from cryptography.fernet import Fernet

    # Bypass persist_evidence_record (which always supplies
    # deferral_threshold_used) to simulate a genuinely pre-Story-1.6 record.
    from sentinel.triage.store import _connect, _require_fernet

    legacy_record = {
        "message_id": "m1",
        "sender": "alice@example.com",
        "report": _make_report(),
    }
    fernet: Fernet = _require_fernet(store_config)
    encrypted = fernet.encrypt(json.dumps(legacy_record).encode())
    conn = _connect(store_db_path)
    conn.execute(
        "INSERT INTO evidence_records "
        "(message_hash, verdict_json, created_at, expires_at, schema_version) "
        "VALUES (?, ?, '2020-01-01T00:00:00+00:00', '2099-01-01T00:00:00+00:00', 1)",
        ("legacyhash1", encrypted),
    )
    conn.commit()
    conn.close()

    mocker.patch(
        "sys.argv",
        ["sentinel-triage", "--replay", "legacyhash1", "--db-path", store_db_path],
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0


# --- run_poll_cycle --------------------------------------------------------------


@pytest.fixture(autouse=True)
def _stub_watchman_cipher(mocker):  # type: ignore[no-untyped-def]
    """run_poll_cycle now instantiates WatchmanAgent/CipherAgent once per
    cycle (Story 2.2) -- autouse so every run_poll_cycle test below is
    protected from real Anthropic/VT/AbuseIPDB/URLhaus network calls without
    editing each test individually. Mocked at the class level (same
    boundary-mocking convention as test_watchman.py/test_cipher.py). Returns
    both mocks so a test needing specific evidence can further configure
    `.return_value.analyze.return_value` itself."""
    stub_result = AgentResult(
        source_name="stub", findings=[], blind_spots=[], raw_confidence=None, error=None, evidence=[]
    )
    mock_watchman = mocker.patch("sentinel.triage.worker.WatchmanAgent")
    mock_watchman.return_value.analyze.return_value = stub_result
    mock_cipher = mocker.patch("sentinel.triage.worker.CipherAgent")
    mock_cipher.return_value.analyze.return_value = stub_result
    return mock_watchman, mock_cipher


def _gmail_config(store_config: Config) -> Config:
    return replace(
        store_config,
        gmail_monitored_mailbox="soc@example.com",
        gmail_credentials_path="secrets/gmail-service-account.json",
    )


def test_run_poll_cycle_persists_one_new_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    raw_content = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        {"raw": encoded},
    ]

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    content_hash = hashlib.sha256(raw_content).hexdigest()
    record = read_evidence_record(store_db_path, content_hash, config)
    assert record is not None
    assert record["message_id"] == "m1"
    assert record["report"]["schema_version"] == 1


def test_run_poll_cycle_skips_already_processed_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)
    # "m1" is already processed iff persist_evidence_record has already run
    # for it -- there is no separate claim step (2026-07-22, Story 1.7 follow-up).
    already_processed = EvidenceRecord(
        message_id="m1", sender=None, report=_make_report(), deferral_threshold_used=0.05
    )
    persist_evidence_record(store_db_path, "priorhash", already_processed, config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    spy = mocker.patch("sentinel.triage.worker.process_message")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    spy.assert_not_called()


def test_run_poll_cycle_is_message_processed_failure_is_per_message_not_cycle_level(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """If is_message_processed itself raises (e.g. a transient sqlite lock),
    that must be caught as a per-message failure -- not left to propagate out
    of run_poll_cycle, where run_continuous_loop would misclassify it as a
    cycle-level PERSISTENT FAILURE and kill the whole worker over a single
    message's bookkeeping hiccup. Regression guard (2026-07-22 code-review
    follow-up)."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    mocker.patch(
        "sentinel.triage.worker.is_message_processed",
        side_effect=RuntimeError("simulated database is locked"),
    )

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)  # must not raise/crash the cycle


def test_run_poll_cycle_saves_new_checkpoint(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    from sentinel.triage.store import load_history_checkpoint

    config = _gmail_config(store_config)
    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "5000"
    }

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    assert load_history_checkpoint(store_db_path) == "5000"


def test_run_poll_cycle_calls_purge_expired(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = _gmail_config(store_config)
    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    spy = mocker.patch("sentinel.triage.worker.purge_expired")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    spy.assert_called_once_with(store_db_path, config)


def test_run_poll_cycle_raw_fetch_failure_persists_coverage_gap(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Story 6.1] A raw-content-fetch failure (the message is unavailable,
    e.g. Gmail 404) is a CoverageGap, not a Deferred/0.5 -- no analysis ran,
    so there is nothing to be uncertain about."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},  # Authentication-Results metadata fetch
        RuntimeError("boom"),  # raw content fetch fails
        {"payload": {"headers": []}},  # Story 5.2.1 fallback marker/sender fetch
    ]

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    fallback_hash = hashlib.sha256(b"m1").hexdigest()
    record = read_evidence_record(store_db_path, fallback_hash, config)
    assert record is not None
    assert record["report"]["verdict"] == "CoverageGap"
    assert record["report"]["calibrated_confidence"] is None
    assert record["report"]["evidence"] == []
    assert record["report"]["coverage_gap_reason"] is not None
    assert "raw message content" in record["report"]["coverage_gap_reason"]
    assert record["sender"] is None


# [Story 6.1, AC4] The 5 real coverage-gap message IDs from the live
# 2026-08-13 production incident (cron.log-confirmed: both the header fetch
# and the raw content fetch returned Gmail's real 404 "Requested entity was
# not found" for each of these, meaning the message was deleted or moved
# out of the mailbox between the list call and the fetch call). The exact
# decrypted records aren't reachable from this repo (they live in the
# deployed instance's own data/evidence.db, confirmed separately not to be
# this repo's local dev database), so these fixtures reproduce the
# confirmed real failure PATTERN against the real IDs via mocking, rather
# than replaying literal stored bytes -- the same discipline this
# codebase already uses for every other Gmail-API-failure fixture in this
# file (see e.g. the RuntimeError("boom")-based tests above).
_REAL_COVERAGE_GAP_MESSAGE_IDS = [
    "19fedf6c147a8c64",
    "19fedf27012de50e",
    "19ff2718cf3ac070",
    "19ff54db173d218b",
    "19ff7e1b1d32d5ac",
]
_REAL_NEGATIVE_CONTROL_MESSAGE_ID = "19ff26dff54207bc"


def _gmail_404_error() -> HttpError:
    """Reproduces the real, exact Gmail API error shape observed in
    cron.log for all 5 coverage-gap incidents: HttpError 404, message
    "Requested entity was not found.", reason "notFound"."""
    import unittest.mock

    resp = unittest.mock.MagicMock(status=404, reason="Not Found")
    content = (
        b'{"error": {"code": 404, "message": "Requested entity was not found.", '
        b'"errors": [{"reason": "notFound"}]}}'
    )
    return HttpError(resp, content)


@pytest.mark.parametrize("message_id", _REAL_COVERAGE_GAP_MESSAGE_IDS)
def test_real_coverage_gap_message_ids_resolve_to_coverage_gap(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    message_id: str,
) -> None:
    """[Story 6.1, AC4] Each of the 5 real message IDs confirmed against
    cron.log to have failed BOTH the header fetch and the raw content
    fetch with Gmail's real 404 -- matching the "Observed pattern" from
    the live data: every real incident was a full fetch failure, never a
    partial (header-only or raw-only) one. Each must resolve to
    CoverageGap, not Deferred/0.500."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": message_id}}]}]
    }
    # Both the header metadata fetch AND the raw content fetch 404 --
    # matching the real observed pattern exactly (never just one).
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        _gmail_404_error(),  # Authentication-Results metadata fetch
        _gmail_404_error(),  # raw content fetch
        _gmail_404_error(),  # Story 5.2.1 fallback marker/sender fetch
    ]

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    expected_hash = hashlib.sha256(message_id.encode()).hexdigest()
    record = read_evidence_record(store_db_path, expected_hash, config)
    assert record is not None
    assert record["message_id"] == message_id
    assert record["report"]["verdict"] == "CoverageGap"
    assert record["report"]["calibrated_confidence"] is None
    assert record["report"]["evidence"] == []
    assert record["sender"] is None


def test_real_negative_control_message_id_stays_genuinely_deferred(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Story 6.1, AC4] Regression guard: the negative-control message ID is
    a REAL Deferred verdict from the live data with NO preceding ingest
    failure (both fetches succeed; the deferral comes from genuine,
    analyzed, conflicting/uncertain evidence). This must NOT be
    reclassified as CoverageGap -- proving this story's fix is scoped to
    actual fetch failures, not to the Deferred verdict generally."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)
    message_id = _REAL_NEGATIVE_CONTROL_MESSAGE_ID

    # Both fetches succeed (real content is read and analyzed) -- the
    # Authentication-Results header is PRESENT but unparseable into any
    # recognized SPF/DKIM/DMARC mechanism, and Watchman/Cipher (via
    # _neutral_agent) contribute nothing directional either. This
    # reliably triggers structural deferral Gate 1 (all-neutral evidence)
    # regardless of exact per-mechanism weight arithmetic -- a real,
    # genuine "nothing informative found" analysis, not a fetch failure.
    raw_content = (
        b"From: Your Local Chick-fil-A <noreply@email.chick-fil-a.com>\r\n"
        b"Subject: Rewards update\r\n\r\n"
        b"Check your account for updates."
    )
    encoded = base64.urlsafe_b64encode(raw_content).decode()

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": message_id}}]}]
    }
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {
            "payload": {
                "headers": [
                    {
                        "name": "Authentication-Results",
                        "value": "mx.google.com; nothing=parseable",
                    }
                ]
            }
        },
        {"raw": encoded},
    ]

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    content_hash = hashlib.sha256(raw_content).hexdigest()
    record = read_evidence_record(store_db_path, content_hash, config)
    assert record is not None
    assert record["message_id"] == message_id
    assert record["report"]["verdict"] == "Deferred"
    assert record["report"]["verdict"] != "CoverageGap"
    assert record["report"]["calibrated_confidence"] is not None
    assert record["report"]["evidence"] != []


def test_run_poll_cycle_raw_fetch_failure_still_recognizes_self_alert_via_fallback_fetch(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Review] If Sentinel's own alert email's raw-content fetch happens to
    fail transiently, the marker can't be read from raw bytes -- there are
    none. Without a fallback, it would fall through to the ordinary
    coverage-gap path and could be re-alerted on, reopening exactly the
    loop this story exists to close. A second, independent metadata-only
    fetch (fetch_headers_by_name) recovers the marker/sender in this case,
    so it is still recognized and neither persisted nor re-alerted on."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _alert_config(store_config, alert_smtp_username="me@gmail.com")

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},  # Authentication-Results metadata fetch
        RuntimeError("boom"),  # raw content fetch fails
        {  # Story 5.2.1 fallback marker/sender fetch
            "payload": {
                "headers": [
                    {"name": "X-Sentinel-Alert", "value": "1"},
                    {"name": "From", "value": "me@gmail.com"},
                ]
            }
        },
    ]
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    alert_spy.assert_not_called()
    fallback_hash = hashlib.sha256(b"m1").hexdigest()
    assert read_evidence_record(store_db_path, fallback_hash, config) is None
    assert is_message_processed(store_db_path, "m1") is False


def test_run_poll_cycle_raw_fetch_failure_fallback_check_itself_failing_does_not_crash(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """If the fallback metadata fetch ALSO fails (e.g. a sustained Gmail-side
    outage affecting both endpoints), this must not crash the message -- it
    falls through to the existing coverage-gap behavior (Story 6.1:
    verdict="CoverageGap") exactly as when only the raw-content fetch fails
    and the fallback isn't needed at all."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        RuntimeError("boom"),
        RuntimeError("fallback fetch also fails"),
    ]

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)  # must not raise

    fallback_hash = hashlib.sha256(b"m1").hexdigest()
    record = read_evidence_record(store_db_path, fallback_hash, config)
    assert record is not None
    assert record["report"]["verdict"] == "CoverageGap"


def test_run_poll_cycle_raw_fetch_failure_does_not_stop_remaining_messages(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [
            {"messagesAdded": [{"message": {"id": "m1"}}]},
            {"messagesAdded": [{"message": {"id": "m2"}}]},
        ]
    }
    raw_content_m2 = b"From: bob@example.com\r\nSubject: t2\r\n\r\nbody2"
    encoded_m2 = base64.urlsafe_b64encode(raw_content_m2).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},  # m1 header fetch ok
        RuntimeError("boom"),  # m1 raw fetch fails
        {"payload": {"headers": []}},  # m1 Story 5.2.1 fallback marker/sender fetch
        {"payload": {"headers": []}},  # m2 header fetch ok
        {"raw": encoded_m2},  # m2 raw fetch ok
    ]

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    content_hash_m2 = hashlib.sha256(raw_content_m2).hexdigest()
    record_m2 = read_evidence_record(store_db_path, content_hash_m2, config)
    assert record_m2 is not None
    assert record_m2["message_id"] == "m2"


def test_run_poll_cycle_persist_failure_does_not_permanently_mark_processed(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """If persist_evidence_record fails, the message must never be left
    marked-processed with no evidence record -- otherwise it is permanently
    lost, since no future poll cycle would ever retry it. Since Story 1.7's
    atomicity fix, this is now inherent to persist_evidence_record's single
    atomic commit (both rows land together or neither does), not a separate
    rollback step -- there is nothing to roll back, because nothing was ever
    written before the commit."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    raw_content = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        {"raw": encoded},
    ]
    mocker.patch(
        "sentinel.triage.worker.persist_evidence_record",
        side_effect=RuntimeError("simulated DB failure"),
    )

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)  # must not raise/crash the cycle

    # Nothing was ever committed for "m1" -- persist_evidence_record's atomic
    # write never completed, so a future poll cycle will correctly retry it.
    assert is_message_processed(store_db_path, "m1") is False


def test_run_poll_cycle_persist_failure_does_not_advance_checkpoint_past_it(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """If a message fails and is un-marked, the checkpoint must NOT advance past
    it -- history.list(startHistoryId=X) only returns events strictly after X, so
    saving the cycle's new historyId here would make the failed message's own
    history event permanently unreachable on every future cycle, silently
    breaking the "retried on a future poll cycle" promise the rollback above
    claims to provide. Same silent-data-loss class already fixed twice in this
    story, at a third, cycle-level trigger point (2026-07-22 code-review
    follow-up)."""
    from sentinel.triage.store import load_history_checkpoint, save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    raw_content = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        {"raw": encoded},
    ]
    mocker.patch(
        "sentinel.triage.worker.persist_evidence_record",
        side_effect=RuntimeError("simulated DB failure"),
    )

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    # Must stay at the OLD checkpoint ("999"), not advance to the new one
    # ("1000") -- otherwise the next cycle's history.list(startHistoryId="1000")
    # would never return m1's history event again.
    assert load_history_checkpoint(store_db_path) == "999"


def test_run_poll_cycle_print_failure_after_persist_does_not_misclassify_success(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A print() failure strictly AFTER a successful persist_evidence_record
    call must not be misclassified as a processing failure (any_failures=True,
    capping the checkpoint below unnecessarily) -- the evidence is already
    durably persisted at that point. Regression guard for moving the
    success-path print() into an `else` clause outside the try (originally a
    2026-07-22 code-review follow-up guarding against a false rollback; the
    rollback mechanism itself was later removed by Story 1.7's atomicity fix,
    but this same print-placement protection remains necessary)."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    raw_content = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        {"raw": encoded},
    ]

    real_print = print

    def flaky_print(*args: object, **kwargs: object) -> None:
        text = str(args[0]) if args else ""
        if "Persisted evidence record" in text:
            raise BrokenPipeError("simulated broken stderr")
        real_print(*args, **kwargs)  # type: ignore[arg-type]

    mocker.patch("builtins.print", side_effect=flaky_print)

    with pytest.raises(BrokenPipeError):
        run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    content_hash = hashlib.sha256(raw_content).hexdigest()
    record = read_evidence_record(store_db_path, content_hash, config)
    assert record is not None  # evidence survives the print() failure
    assert is_message_processed(store_db_path, "m1") is True


def test_run_poll_cycle_persist_failure_for_one_message_does_not_stop_remaining_messages(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A persist-time failure for one message must not stop the cycle from
    processing subsequent messages -- m1 fails, m2 must still be persisted."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [
            {"messagesAdded": [{"message": {"id": "m1"}}]},
            {"messagesAdded": [{"message": {"id": "m2"}}]},
        ]
    }
    raw_content_m1 = b"From: alice@example.com\r\nSubject: t1\r\n\r\nbody1"
    encoded_m1 = base64.urlsafe_b64encode(raw_content_m1).decode()
    raw_content_m2 = b"From: bob@example.com\r\nSubject: t2\r\n\r\nbody2"
    encoded_m2 = base64.urlsafe_b64encode(raw_content_m2).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},  # m1 header fetch ok
        {"raw": encoded_m1},  # m1 raw fetch ok (fails later, at persist time)
        {"payload": {"headers": []}},  # m2 header fetch ok
        {"raw": encoded_m2},  # m2 raw fetch ok
    ]

    def flaky_persist(
        db_path: str, content_hash: str, record: EvidenceRecord, config: Config
    ) -> None:
        if record["message_id"] == "m1":
            raise RuntimeError("simulated DB failure for m1")
        persist_evidence_record(db_path, content_hash, record, config)

    mocker.patch("sentinel.triage.worker.persist_evidence_record", side_effect=flaky_persist)

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)  # must not raise/crash the cycle

    content_hash_m2 = hashlib.sha256(raw_content_m2).hexdigest()
    record_m2 = read_evidence_record(store_db_path, content_hash_m2, config)
    assert record_m2 is not None
    assert record_m2["message_id"] == "m2"


# --- run_continuous_loop ----------------------------------------------------------


def test_run_continuous_loop_survives_a_per_message_failure_within_a_cycle(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A per-message failure inside a poll cycle must not propagate out of
    run_continuous_loop -- this proves Story 1.6's claim/rollback isolation
    survives being invoked through the new outer loop, end to end, not just
    in isolation via run_poll_cycle's own test suite."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _gmail_config(store_config)

    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [
            {"messagesAdded": [{"message": {"id": "m1"}}]},
            {"messagesAdded": [{"message": {"id": "m2"}}]},
        ]
    }
    raw_content_m1 = b"From: alice@example.com\r\nSubject: t1\r\n\r\nbody1"
    encoded_m1 = base64.urlsafe_b64encode(raw_content_m1).decode()
    raw_content_m2 = b"From: bob@example.com\r\nSubject: t2\r\n\r\nbody2"
    encoded_m2 = base64.urlsafe_b64encode(raw_content_m2).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},  # m1 header fetch ok
        {"raw": encoded_m1},  # m1 raw fetch ok (fails later, at persist time)
        {"payload": {"headers": []}},  # m2 header fetch ok
        {"raw": encoded_m2},  # m2 raw fetch ok
    ]

    def flaky_persist(
        db_path: str, content_hash: str, record: EvidenceRecord, config: Config
    ) -> None:
        if record["message_id"] == "m1":
            raise RuntimeError("simulated failure for m1")
        persist_evidence_record(db_path, content_hash, record, config)

    mocker.patch("sentinel.triage.worker.persist_evidence_record", side_effect=flaky_persist)
    mocker.patch("sentinel.triage.worker.time.sleep", side_effect=KeyboardInterrupt)
    mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(config, store_db_path)  # must not raise

    content_hash_m2 = hashlib.sha256(raw_content_m2).hexdigest()
    record_m2 = read_evidence_record(store_db_path, content_hash_m2, config)
    assert record_m2 is not None
    assert record_m2["message_id"] == "m2"


def test_run_continuous_loop_persistent_failure_propagates_with_distinct_log_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """If run_poll_cycle itself raises (a cycle-level, not per-message,
    failure -- e.g. revoked Gmail credentials), the loop must not swallow it
    and silently retry forever. It re-raises after a distinct log line so an
    operator can tell this apart from a per-message failure at a glance."""
    mocker.patch(
        "sentinel.triage.worker.run_poll_cycle",
        side_effect=RuntimeError("simulated persistent failure"),
    )
    mocker.patch("sentinel.triage.worker.signal.signal")

    with pytest.raises(RuntimeError, match="simulated persistent failure"):
        run_continuous_loop(store_config, store_db_path)

    captured = capsys.readouterr()
    assert "PERSISTENT" in captured.err
    assert "Failed to process message" not in captured.err


def test_run_continuous_loop_clean_shutdown_on_interrupt_during_sleep(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sentinel.triage.worker.run_poll_cycle")
    mocker.patch("sentinel.triage.worker.time.sleep", side_effect=KeyboardInterrupt)
    mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(store_config, store_db_path)  # must not raise

    captured = capsys.readouterr()
    assert "Shutting down" in captured.err


def test_run_continuous_loop_clean_shutdown_on_interrupt_during_cycle(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sentinel.triage.worker.run_poll_cycle", side_effect=KeyboardInterrupt)
    sleep_spy = mocker.patch("sentinel.triage.worker.time.sleep")
    mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(store_config, store_db_path)  # must not raise

    sleep_spy.assert_not_called()
    captured = capsys.readouterr()
    assert "Shutting down" in captured.err


def test_run_continuous_loop_ignores_further_sigterm_once_shutdown_begins(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A second SIGTERM landing while the shutdown except-block is still
    running (e.g. mid-print) must not raise a fresh KeyboardInterrupt that
    escapes the clean-shutdown path -- verified here by asserting SIGTERM is
    re-registered to SIG_IGN as soon as shutdown begins. Regression guard
    (2026-07-22 code-review follow-up)."""
    import signal as signal_module

    from sentinel.triage.worker import _handle_sigterm

    mocker.patch("sentinel.triage.worker.run_poll_cycle")
    mocker.patch("sentinel.triage.worker.time.sleep", side_effect=KeyboardInterrupt)
    signal_spy = mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(store_config, store_db_path)

    signal_spy.assert_any_call(signal_module.SIGTERM, _handle_sigterm)
    signal_spy.assert_any_call(signal_module.SIGTERM, signal_module.SIG_IGN)


def test_run_continuous_loop_sleeps_for_configured_poll_interval(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = replace(store_config, poll_interval_seconds=42)
    mocker.patch("sentinel.triage.worker.run_poll_cycle")
    sleep_spy = mocker.patch("sentinel.triage.worker.time.sleep", side_effect=KeyboardInterrupt)
    mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(config, store_db_path)

    sleep_spy.assert_called_once_with(42)


def test_run_continuous_loop_instantiates_agents_once_not_per_cycle(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """2026-07-23 code-review patch: WatchmanAgent/CipherAgent (and their
    underlying httpx.Client/anthropic.Anthropic clients, never explicitly
    closed anywhere in this codebase) were previously instantiated inside
    run_poll_cycle, meaning every poll cycle -- not just every message --
    created and abandoned a fresh pair. Must now be built once for the
    loop's entire lifetime and reused across every cycle."""
    config = store_config
    run_poll_cycle_spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")
    mock_watchman_cls = mocker.patch("sentinel.triage.worker.WatchmanAgent")
    mock_cipher_cls = mocker.patch("sentinel.triage.worker.CipherAgent")
    mocker.patch("sentinel.triage.worker.signal.signal")
    # 3 cycles, then interrupt -- proves reuse across MULTIPLE cycles, not
    # just that construction happens before the first one.
    mocker.patch(
        "sentinel.triage.worker.time.sleep",
        side_effect=[None, None, KeyboardInterrupt],
    )

    run_continuous_loop(config, store_db_path)

    mock_watchman_cls.assert_called_once_with(config)
    mock_cipher_cls.assert_called_once_with(config)
    assert run_poll_cycle_spy.call_count == 3
    for call in run_poll_cycle_spy.call_args_list:
        assert call.args[2] is mock_watchman_cls.return_value
        assert call.args[3] is mock_cipher_cls.return_value


@pytest.mark.parametrize("bad_interval", [0, -1, -300])
def test_run_continuous_loop_raises_config_error_on_nonpositive_poll_interval(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    bad_interval: int,
) -> None:
    """A non-positive SENTINEL_POLL_INTERVAL previously crashed on the first
    time.sleep() call (negative: ValueError) or produced a busy-loop
    hammering the Gmail API (zero). Validated lazily at first actual use,
    mirroring deferral_threshold/retention_days (2026-07-22 code-review
    follow-up)."""
    config = replace(store_config, poll_interval_seconds=bad_interval)
    run_spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")
    sleep_spy = mocker.patch("sentinel.triage.worker.time.sleep")

    with pytest.raises(ConfigError, match="SENTINEL_POLL_INTERVAL"):
        run_continuous_loop(config, store_db_path)

    run_spy.assert_not_called()
    sleep_spy.assert_not_called()


def test_run_continuous_loop_registers_sigterm_handler(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """systemctl stop sends SIGTERM, not SIGINT -- Python has no default
    handler for it (unlike SIGINT, which Python already turns into
    KeyboardInterrupt). Without an explicit registration, SIGTERM kills the
    process immediately, bypassing the clean-shutdown path entirely. This
    proves run_continuous_loop actually wires up the handler at startup, not
    just that the handler function itself behaves correctly in isolation
    (see test_handle_sigterm_raises_keyboard_interrupt)."""
    import signal as signal_module

    from sentinel.triage.worker import _handle_sigterm

    mocker.patch("sentinel.triage.worker.run_poll_cycle")
    mocker.patch("sentinel.triage.worker.time.sleep", side_effect=KeyboardInterrupt)
    signal_spy = mocker.patch("sentinel.triage.worker.signal.signal")

    run_continuous_loop(store_config, store_db_path)

    # assert_any_call, not assert_called_once_with: signal.signal is also
    # called a second time (SIG_IGN) once shutdown begins -- see
    # test_run_continuous_loop_ignores_further_sigterm_once_shutdown_begins.
    signal_spy.assert_any_call(signal_module.SIGTERM, _handle_sigterm)


def test_handle_sigterm_raises_keyboard_interrupt() -> None:
    """Unit test of the handler itself, independent of registration/delivery
    (real OS-level SIGTERM delivery is not portably testable -- e.g. os.kill
    with SIGTERM on Windows does not invoke a registered Python handler the
    way POSIX does, so this only tests the handler's own logic, not signal
    delivery mechanics)."""
    from sentinel.triage.worker import _handle_sigterm

    with pytest.raises(KeyboardInterrupt):
        _handle_sigterm(15, None)


# --- alert dispatch (Story 5.2) -----------------------------------------------


def _setup_single_message_poll(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    message_id: str = "m1",
    raw_content: bytes = b"From: alice@example.com\r\nSubject: Password reset\r\n\r\nbody",
):  # type: ignore[no-untyped-def]
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": message_id}}]}]
    }
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        {"raw": encoded},
    ]
    return service


def _alert_config(store_config: Config, **overrides) -> Config:  # type: ignore[no-untyped-def]
    config = _gmail_config(store_config)
    return replace(config, alert_enabled=True, **overrides)


@pytest.mark.parametrize("verdict", ["Deferred", "Malicious"])
def test_alert_fires_at_or_above_default_threshold(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    verdict: str,
) -> None:
    config = _alert_config(store_config)  # default threshold: Deferred
    _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict=verdict),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    alert_spy.assert_called_once()


def test_alert_does_not_fire_below_default_threshold(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = _alert_config(store_config)  # default threshold: Deferred
    _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Benign"),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    alert_spy.assert_not_called()


def test_alert_does_not_fire_deferred_when_threshold_is_malicious(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = _alert_config(store_config, alert_threshold="Malicious")
    _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Deferred"),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    alert_spy.assert_not_called()


def test_alert_fires_malicious_when_threshold_is_malicious(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = _alert_config(store_config, alert_threshold="Malicious")
    _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    alert_spy.assert_called_once()


def test_alert_disabled_suppresses_alert_regardless_of_verdict(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = _gmail_config(store_config)  # alert_enabled defaults to False
    _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    alert_spy.assert_not_called()


def test_alert_fires_exactly_once_for_one_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = _alert_config(store_config)
    _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    assert alert_spy.call_count == 1


def test_alert_does_not_refire_on_a_later_poll_cycle_for_the_same_message(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """AC7: re-runs must not re-alert on old records -- structurally
    guaranteed by the same is_message_processed check that already
    prevents re-processing, not a new mechanism."""
    config = _alert_config(store_config)
    service = _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)
    # Second cycle: same message reappears in history (e.g. a redelivery),
    # but is now already processed.
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    assert alert_spy.call_count == 1


def test_alert_send_failure_does_not_break_processing_or_persistence(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = _alert_config(store_config)
    _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )
    mocker.patch("sentinel.triage.worker.send_alert", side_effect=RuntimeError("smtp exploded"))

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)  # must not raise

    from sentinel.triage.store import load_history_checkpoint

    content_hash = hashlib.sha256(
        b"From: alice@example.com\r\nSubject: Password reset\r\n\r\nbody"
    ).hexdigest()
    record = read_evidence_record(store_db_path, content_hash, config)
    assert record is not None
    assert load_history_checkpoint(store_db_path) == "1000"


def test_invalid_alert_threshold_warns_and_does_not_fail_message_processing(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _alert_config(store_config, alert_threshold="bogus")
    _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)  # must not raise

    alert_spy.assert_not_called()
    content_hash = hashlib.sha256(
        b"From: alice@example.com\r\nSubject: Password reset\r\n\r\nbody"
    ).hexdigest()
    record = read_evidence_record(store_db_path, content_hash, config)
    assert record is not None
    # [Review] capsys.readouterr() drains the buffer -- capture ONCE, not
    # twice, or the second call always sees an empty string and the "or"
    # branch becomes permanently-vacuous dead code.
    err = capsys.readouterr().err.lower()
    assert "bogus" in err
    assert "invalid" in err


def test_alert_threshold_benign_is_rejected_as_invalid(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """[Review] "Benign" is a real key in the verdict-severity ranking
    dict (needed to rank verdicts at all) but is NOT a valid threshold
    (AC2: only "Deferred" or "Malicious"). Before this fix, using the
    same dict for both jobs meant this value passed validation and then,
    since its rank (0) is <= every verdict's rank, silently alerted on
    every single message -- including genuinely benign ones, defeating
    the entire feature."""
    config = _alert_config(store_config, alert_threshold="Benign")
    _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Benign"),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    alert_spy.assert_not_called()
    assert "invalid" in capsys.readouterr().err.lower()


def test_alert_payload_findings_are_sorted_capped_and_truncated(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    make_evidence_item,  # type: ignore[no-untyped-def]
) -> None:
    """[Review] The finding-construction path had zero test coverage --
    every prior alert test used empty evidence. Covers real multi-finding
    evidence: correct sort order (highest weight first), the top-2 cap,
    and length truncation of an unbounded finding string (Watchman's LLM
    output has no length constraint of its own)."""
    config = _alert_config(store_config)
    _setup_single_message_poll(mocker, store_db_path)
    long_finding = "A" * 500
    evidence = [
        make_evidence_item(
            name="low", finding="low weight finding", weight=0.1, direction="malicious"
        ),
        make_evidence_item(
            name="high", finding=long_finding, weight=0.9, direction="malicious"
        ),
        make_evidence_item(
            name="mid", finding="mid weight finding", weight=0.5, direction="benign"
        ),
        make_evidence_item(
            name="neutral", finding="irrelevant coverage gap", weight=0.0, direction="neutral"
        ),
    ]
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious", evidence=evidence),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    payload = alert_spy.call_args.args[1]
    assert len(payload["findings"]) == 2  # capped at _ALERT_MAX_FINDINGS, "neutral" excluded
    assert payload["findings"][0].startswith("[malicious] " + "A" * 10)  # highest weight first
    assert len(payload["findings"][0]) <= 200
    assert payload["findings"][0].endswith("…")
    assert payload["findings"][1].startswith("[benign] mid weight finding")


def test_alert_dispatch_unexpected_exception_before_send_does_not_crash_processing(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Review] Before this fix, only the send_alert call itself was
    wrapped in try/except -- an exception raised while building the
    payload (which run_poll_cycle's else: clause reaches OUTSIDE its own
    try/except, deliberately) would have propagated all the way out of
    run_poll_cycle and, via run_continuous_loop's exception handling,
    killed the entire live worker over a notification bug. Proven here by
    making payload construction itself fail."""
    config = _alert_config(store_config)
    _setup_single_message_poll(mocker, store_db_path)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )
    mocker.patch(
        "sentinel.triage.worker._sorted_directional_findings",
        side_effect=RuntimeError("boom before send_alert is ever reached"),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)  # must not raise

    alert_spy.assert_not_called()
    content_hash = hashlib.sha256(
        b"From: alice@example.com\r\nSubject: Password reset\r\n\r\nbody"
    ).hexdigest()
    record = read_evidence_record(store_db_path, content_hash, config)
    assert record is not None


def test_alert_payload_includes_subject_extracted_from_email_content(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    config = _alert_config(store_config)
    _setup_single_message_poll(
        mocker,
        store_db_path,
        raw_content=b"From: alice@example.com\r\nSubject: Urgent: verify your account\r\n\r\nbody",
    )
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    payload = alert_spy.call_args.args[1]
    assert payload["subject"] == "Urgent: verify your account"
    assert payload["sender"] == "alice@example.com"
    assert payload["verdict"] == "Malicious"


@pytest.mark.parametrize("alert_threshold", ["Deferred", "Malicious"])
def test_coverage_gap_never_fires_an_alert_regardless_of_threshold(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    alert_threshold: str,
) -> None:
    """[Story 6.1] Before this story, a raw-fetch failure ALWAYS persisted a
    Deferred/0.5 record, which met the default "Deferred" alert threshold
    and fired an alert on EVERY message-unavailable event -- an
    operationally noisy false positive with no real signal behind it (the
    message doesn't exist; there is nothing to alert about). CoverageGap
    has no entry in _ALERT_VERDICT_SEVERITY, so _verdict_meets_alert_
    threshold structurally can never return True for it -- proven here at
    BOTH configured thresholds, not just the default."""
    from sentinel.triage.store import save_history_checkpoint

    save_history_checkpoint(store_db_path, "999")
    config = _alert_config(store_config, alert_threshold=alert_threshold)
    service = mocker.MagicMock()
    mocker.patch("sentinel.triage.worker.build_gmail_service", return_value=service)
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]
    }
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {"payload": {"headers": []}},
        Exception("raw fetch failed"),
        {"payload": {"headers": []}},  # Story 5.2.1 fallback marker/sender fetch
    ]
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    alert_spy.assert_not_called()


# --- self-alert feedback-loop prevention (Story 5.2.1) -----------------------


def test_self_alert_marker_header_skips_triage_persistence_and_alert(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC2/AC4: a message carrying Sentinel's own alert marker header,
    genuinely sent from the configured alert account, must never be
    triaged, scored, persisted, or re-alerted on -- and the skip must be
    logged so the operator can see it was recognized and ignored."""
    config = _alert_config(store_config, alert_smtp_username="me@gmail.com")
    raw_content = (
        b"From: me@gmail.com\r\nSubject: Sentinel alert: Malicious\r\n"
        b"X-Sentinel-Alert: 1\r\n\r\n"
        b"Sentinel triage alert: Malicious (confidence=1.000)"
    )
    _setup_single_message_poll(mocker, store_db_path, raw_content=raw_content)
    process_spy = mocker.patch("sentinel.triage.worker.process_message")
    alert_spy = mocker.patch("sentinel.triage.worker.send_alert")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    process_spy.assert_not_called()
    alert_spy.assert_not_called()
    assert is_message_processed(store_db_path, "m1") is False
    assert "skip" in capsys.readouterr().err.lower()


def test_self_alert_skip_is_not_a_failure_and_checkpoint_still_advances(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A skipped self-alert must not be treated as a per-message failure --
    it should not cap the checkpoint the way a genuine processing failure
    does (see the any_failures mechanism), since there is nothing to retry."""
    from sentinel.triage.store import load_history_checkpoint

    config = _alert_config(store_config, alert_smtp_username="me@gmail.com")
    raw_content = (
        b"From: me@gmail.com\r\nSubject: Sentinel alert: Malicious\r\n"
        b"X-Sentinel-Alert: 1\r\n\r\nbody"
    )
    _setup_single_message_poll(mocker, store_db_path, raw_content=raw_content)

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    assert load_history_checkpoint(store_db_path) == "1000"


def test_forged_marker_header_from_unrelated_sender_does_not_bypass_triage(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Review] The marker header alone must never be sufficient to skip a
    message: it is parsed straight out of attacker-controlled inbound
    bytes. Since the header name/value are fixed and public (this is open
    source), a real phishing email that simply copies them would otherwise
    get a silent, complete bypass of triage -- worse than the feedback loop
    this story exists to close, since it defeats detection instead of
    merely mis-firing a notification. Proven here: a message carrying the
    exact marker header, but from a sender that does NOT match the
    configured alert-sending account, must still be triaged normally."""
    config = _alert_config(store_config, alert_smtp_username="me@gmail.com")
    raw_content = (
        b"From: phisher@evil.example\r\nSubject: Urgent: verify your account\r\n"
        b"X-Sentinel-Alert: 1\r\n\r\nClick here: http://evil.example/login"
    )
    _setup_single_message_poll(mocker, store_db_path, raw_content=raw_content)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    assert is_message_processed(store_db_path, "m1") is True


def test_forged_marker_header_when_alerting_never_configured_does_not_bypass_triage(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Review] Fails safe when alert_smtp_username is unset: with no
    configured sending account, this instance could never have produced a
    genuine self-alert, so the marker header carries no trust on its own
    and must not skip anything."""
    config = _alert_config(store_config)  # alert_smtp_username defaults to None
    raw_content = (
        b"From: phisher@evil.example\r\nSubject: Urgent: verify your account\r\n"
        b"X-Sentinel-Alert: 1\r\n\r\nClick here: http://evil.example/login"
    )
    _setup_single_message_poll(mocker, store_db_path, raw_content=raw_content)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    assert is_message_processed(store_db_path, "m1") is True


def test_self_alert_secondary_guard_sender_and_subject_match_skips_without_header(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """AC3: fallback guard for when the marker header is stripped somewhere
    in the mail path -- inbound sender matching the configured alert sender
    AND subject starting with the alert subject prefix is also treated as a
    self-alert. Also proves parseaddr normalization: a real self-sent Gmail
    message commonly carries a display name the bare configured address
    will never contain."""
    config = _alert_config(store_config, alert_smtp_username="me@gmail.com")
    raw_content = (
        b"From: Jackson Capreol <me@gmail.com>\r\n"
        b"Subject: Sentinel alert: Deferred\r\n\r\nbody"
    )
    _setup_single_message_poll(mocker, store_db_path, raw_content=raw_content)
    process_spy = mocker.patch("sentinel.triage.worker.process_message")

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    process_spy.assert_not_called()
    assert is_message_processed(store_db_path, "m1") is False


def test_self_alert_secondary_guard_matching_subject_but_different_sender_is_triaged(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """AC3/AC5: the secondary guard requires BOTH sender and subject to
    match -- subject alone (even the exact alert prefix) must not be
    enough, or a phisher could spoof the subject line to evade triage
    entirely."""
    config = _alert_config(store_config, alert_smtp_username="me@gmail.com")
    raw_content = (
        b"From: phisher@evil.example\r\nSubject: Sentinel alert: Malicious\r\n\r\nbody"
    )
    _setup_single_message_poll(mocker, store_db_path, raw_content=raw_content)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Malicious"),
    )

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    assert is_message_processed(store_db_path, "m1") is True


def test_self_alert_secondary_guard_matching_sender_but_different_subject_is_triaged(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """AC3/AC5: sender alone must not be enough either -- a normal message
    the operator sends themselves to their own monitored mailbox for an
    unrelated reason must still be triaged."""
    config = _alert_config(store_config, alert_smtp_username="me@gmail.com")
    raw_content = b"From: me@gmail.com\r\nSubject: Please review this\r\n\r\nbody"
    _setup_single_message_poll(mocker, store_db_path, raw_content=raw_content)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Benign"),
    )

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    assert is_message_processed(store_db_path, "m1") is True


def test_normal_message_mentioning_sentinel_and_alert_is_triaged_normally(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """AC5: guards against over-filtering -- a realistic normal email that
    merely mentions "Sentinel" or "alert" in its subject or body, from an
    unconfigured sender, with alerting's SMTP sender never configured (the
    common case for most operators), must still be triaged normally. The
    sender-only and subject-only boundary cases are isolated more tightly
    by test_self_alert_secondary_guard_matching_subject_but_different_
    sender_is_triaged and its sibling below."""
    config = _alert_config(store_config)  # alert_smtp_username defaults to None
    raw_content = (
        b"From: newsletter@example.com\r\n"
        b"Subject: Sentinel alert system now in beta\r\n\r\n"
        b"Read about our new Sentinel alert monitoring feature."
    )
    _setup_single_message_poll(mocker, store_db_path, raw_content=raw_content)
    mocker.patch(
        "sentinel.triage.worker.process_message",
        return_value=_make_report(verdict="Benign"),
    )

    run_poll_cycle(config, store_db_path, _neutral_agent, _neutral_agent)

    assert is_message_processed(store_db_path, "m1") is True


# --- main() / _run() CLI dispatch -------------------------------------------------


def test_default_mode_calls_run_continuous_loop(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    """No --replay/--once given -- AR8's default mode is the continuous poll
    loop, not a usage error (that placeholder was Story 1.6's explicit scope
    boundary, now filled in by this story)."""
    mocker.patch("sys.argv", ["sentinel-triage"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_continuous_loop")

    with pytest.raises(SystemExit) as exc:
        main()

    spy.assert_called_once()
    assert exc.value.code == 0


def test_once_calls_run_poll_cycle_and_exits_zero(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage", "--once"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")

    with pytest.raises(SystemExit) as exc:
        main()

    spy.assert_called_once()
    assert exc.value.code == 0


def test_once_without_db_path_falls_back_to_config_evidence_db_path(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    """[Review] --db-path previously defaulted to a separate CWD-relative
    literal, independent of config.evidence_db_path -- the two only
    coincided by accident of launch directory. Both reviewers flagged
    this as the same silent-path-divergence bug class AC2 exists to
    prevent, just reintroduced between --view and every other mode.
    Fixed: all modes now share the same absolute, config-resolved
    fallback when --db-path is omitted."""
    mocker.patch("sys.argv", ["sentinel-triage", "--once"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")

    with pytest.raises(SystemExit):
        main()

    assert spy.call_args.args[1] == store_config.evidence_db_path


def test_default_continuous_mode_without_db_path_falls_back_to_config_evidence_db_path(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_continuous_loop")

    with pytest.raises(SystemExit):
        main()

    assert spy.call_args.args[1] == store_config.evidence_db_path


def test_replay_without_db_path_falls_back_to_config_evidence_db_path(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    # _run_replay always sys.exit()s for real (never returns normally) --
    # mocked here, it does neither, so _run()'s own `return` after calling
    # it is what actually ends this call, with no SystemExit to catch.
    mocker.patch("sys.argv", ["sentinel-triage", "--replay", "somehash"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker._run_replay")

    main()

    assert spy.call_args.args[1] == store_config.evidence_db_path


def test_relative_evidence_db_path_exits_nonzero_with_clear_error(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC2: evidence_db_path must never be a bare CWD-relative path. If
    SENTINEL_EVIDENCE_DB_PATH is set to a relative value, that must fail
    loudly at dispatch time, not silently resolve against whatever CWD
    happens to be active (both reviewers reproduced this as a real gap
    in the SENTINEL_EVIDENCE_DB_PATH override path specifically)."""
    relative_config = replace(store_config, evidence_db_path="data/evidence.db")
    mocker.patch("sys.argv", ["sentinel-triage", "--once"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=relative_config)
    spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0
    spy.assert_not_called()
    assert "absolute" in capsys.readouterr().err.lower()


def test_replay_and_once_together_exits_nonzero_with_usage_error(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--replay and --once are mutually exclusive -- passing both must produce
    a clear usage error (argparse's own mutually-exclusive-group error), not
    silently dispatch to whichever branch _run() happens to check first.
    Regression guard (2026-07-22 code-review follow-up)."""
    mocker.patch(
        "sys.argv", ["sentinel-triage", "--replay", "somehash", "--once"]
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    replay_spy = mocker.patch("sentinel.triage.worker._run_replay")
    poll_spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0
    replay_spy.assert_not_called()
    poll_spy.assert_not_called()
    captured = capsys.readouterr()
    assert captured.err != ""


def test_config_error_exits_nonzero_before_dispatch(
    mocker,  # type: ignore[no-untyped-def]
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage", "--once"])
    mocker.patch(
        "sentinel.triage.worker.load_config",
        side_effect=ConfigError("Missing required environment variable: ANTHROPIC_API_KEY"),
    )
    spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0
    spy.assert_not_called()
    captured = capsys.readouterr()
    assert "ANTHROPIC_API_KEY" in captured.err


# --- --view CLI dispatch ------------------------------------------------------


def test_view_flag_calls_run_view_with_defaults_and_exits_zero(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage", "--view"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_view")

    with pytest.raises(SystemExit) as exc:
        main()

    spy.assert_called_once_with(store_config, store_config.evidence_db_path, 20, None)
    assert exc.value.code == 0


def test_view_with_limit_and_verdict_options_passes_them_through(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    mocker.patch(
        "sys.argv", ["sentinel-triage", "--view", "--limit", "5", "--verdict", "Deferred"]
    )
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_view")

    with pytest.raises(SystemExit) as exc:
        main()

    spy.assert_called_once_with(store_config, store_config.evidence_db_path, 5, "Deferred")
    assert exc.value.code == 0


def test_view_respects_explicit_db_path_override(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
    store_db_path: str,
) -> None:
    """[Review] --db-path was previously silently ignored by --view --
    documented as a top-level flag with no indication it was a no-op
    under this mode. Fixed: --view now honors an explicit --db-path the
    same as every other mode."""
    mocker.patch("sys.argv", ["sentinel-triage", "--view", "--db-path", store_db_path])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_view")

    with pytest.raises(SystemExit):
        main()

    spy.assert_called_once_with(store_config, store_db_path, 20, None)


def test_verdict_invalid_choice_exits_nonzero_with_usage_error(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """[Review] --verdict was an unvalidated free-text string -- a typo'd
    or wrong-case value silently produced zero results, indistinguishable
    from a correctly-spelled filter with genuinely no matches. Fixed via
    argparse choices=, giving a clear usage error instead."""
    mocker.patch("sys.argv", ["sentinel-triage", "--view", "--verdict", "malicious"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_view")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0
    spy.assert_not_called()
    assert "invalid choice" in capsys.readouterr().err.lower()


def test_view_and_replay_together_exits_nonzero_with_usage_error(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage", "--view", "--replay", "somehash"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    view_spy = mocker.patch("sentinel.triage.worker.run_view")
    replay_spy = mocker.patch("sentinel.triage.worker._run_replay")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0
    view_spy.assert_not_called()
    replay_spy.assert_not_called()
    assert capsys.readouterr().err != ""


def test_view_and_once_together_exits_nonzero_with_usage_error(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage", "--view", "--once"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    view_spy = mocker.patch("sentinel.triage.worker.run_view")
    once_spy = mocker.patch("sentinel.triage.worker.run_poll_cycle")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0
    view_spy.assert_not_called()
    once_spy.assert_not_called()
    assert capsys.readouterr().err != ""


def test_help_lists_view_limit_and_verdict_options(
    mocker,  # type: ignore[no-untyped-def]
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC1: --view must be discoverable via --help."""
    mocker.patch("sys.argv", ["sentinel-triage", "--help"])

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--view" in out
    assert "--limit" in out
    assert "--verdict" in out


# --- --test-alert CLI dispatch --------------------------------------------------


def test_help_lists_test_alert_option(
    mocker,  # type: ignore[no-untyped-def]
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage", "--help"])

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    assert "--test-alert" in capsys.readouterr().out


def test_test_alert_flag_calls_run_test_alert_and_exits_zero_on_success(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage", "--test-alert"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    spy = mocker.patch("sentinel.triage.worker.run_test_alert", return_value=True)

    with pytest.raises(SystemExit) as exc:
        main()

    spy.assert_called_once_with(store_config)
    assert exc.value.code == 0


def test_test_alert_flag_exits_nonzero_on_failure(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    mocker.patch("sys.argv", ["sentinel-triage", "--test-alert"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    mocker.patch("sentinel.triage.worker.run_test_alert", return_value=False)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0


@pytest.mark.parametrize("other_flag", ["--once", "--view", "--replay somehash"])
def test_test_alert_and_another_mode_together_exits_nonzero_with_usage_error(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
    other_flag: str,
) -> None:
    argv = ["sentinel-triage", "--test-alert", *other_flag.split()]
    mocker.patch("sys.argv", argv)
    mocker.patch("sentinel.triage.worker.load_config", return_value=store_config)
    test_alert_spy = mocker.patch("sentinel.triage.worker.run_test_alert")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code != 0
    test_alert_spy.assert_not_called()
    assert capsys.readouterr().err != ""


def test_test_alert_never_touches_gmail_evidence_store_or_db_path_validation(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
) -> None:
    """The whole point of --test-alert is to exercise only the alert-send
    path -- it must not construct a Gmail service, touch the evidence
    store, or even go through the evidence_db_path resolution/validation
    every other mode requires. Proven here with a deliberately INVALID
    (relative) evidence_db_path that would make --view/--once/--replay
    fail at dispatch time -- --test-alert must not care."""
    config = replace(store_config, evidence_db_path="a/relative/path.db")
    mocker.patch("sys.argv", ["sentinel-triage", "--test-alert"])
    mocker.patch("sentinel.triage.worker.load_config", return_value=config)
    gmail_spy = mocker.patch("sentinel.triage.worker.build_gmail_service")
    read_spy = mocker.patch("sentinel.triage.worker.read_recent_evidence_records")
    persist_spy = mocker.patch("sentinel.triage.worker.persist_evidence_record")
    mocker.patch("sentinel.triage.worker.send_test_alert", return_value=(True, "ok"))

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0  # did NOT hit the "evidence_db_path must be absolute" exit(2)
    gmail_spy.assert_not_called()
    read_spy.assert_not_called()
    persist_spy.assert_not_called()


def test_run_test_alert_prints_result_and_returns_success(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch(
        "sentinel.triage.worker.send_test_alert",
        return_value=(True, "Test alert sent successfully to alerts@example.com."),
    )

    result = run_test_alert(store_config)

    assert result is True
    assert "alerts@example.com" in capsys.readouterr().err


def test_run_test_alert_prints_failure_message_and_returns_false(
    mocker,  # type: ignore[no-untyped-def]
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch(
        "sentinel.triage.worker.send_test_alert",
        return_value=(False, "SMTP channel is not fully configured."),
    )

    result = run_test_alert(store_config)

    assert result is False
    assert "not fully configured" in capsys.readouterr().err


# --- run_view -------------------------------------------------------------------


def _persist(
    db_path: str,
    config: Config,
    message_hash: str,
    verdict: str = "Malicious",
    sender: str | None = "alice@example.com",
    evidence: list[EvidenceItem] | None = None,
    timestamp: str = "2026-08-09T00:00:00+00:00",
    calibrated_confidence: float | None = 0.9,
    coverage_gap_reason: str | None = None,
) -> None:
    report = _make_report(
        verdict=verdict,
        evidence=evidence,
        timestamp=timestamp,
        calibrated_confidence=calibrated_confidence,
        coverage_gap_reason=coverage_gap_reason,
    )
    record = EvidenceRecord(
        message_id=message_hash,
        sender=sender,
        report=report,
        deferral_threshold_used=config.deferral_threshold,
    )
    persist_evidence_record(db_path, message_hash, record, config)


def test_run_view_renders_table_with_required_columns(
    store_db_path: str,
    store_config: Config,
    make_evidence_item,  # type: ignore[no-untyped-def]
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = replace(store_config, evidence_db_path=store_db_path)
    _persist(
        store_db_path,
        config,
        "hash1",
        verdict="Malicious",
        sender="phisher@evil.example",
        evidence=[
            make_evidence_item(
                name="watchman_finding",
                finding="Suspicious login URL requesting credentials",
                weight=0.7,
                direction="malicious",
            )
        ],
        timestamp="2026-08-09T12:00:00+00:00",
    )

    run_view(config, store_db_path, 20, None)

    err = capsys.readouterr().err
    assert "2026-08-09T12:00:00" in err
    assert "phisher@evil.example" in err
    assert "Malicious" in err
    assert "Suspicious login URL" in err
    assert "1 shown, 0 skipped" in err


def test_run_view_renders_coverage_gap_without_confidence_value(
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """[Story 6.1, AC5] A CoverageGap record has calibrated_confidence=None
    -- the CONF column must render a placeholder (not crash trying to
    format None as ':.3f', and not show 0.000 or 0.500, either of which
    would misleadingly look like a real measured value)."""
    config = replace(store_config, evidence_db_path=store_db_path)
    _persist(
        store_db_path,
        config,
        "hash1",
        verdict="CoverageGap",
        sender=None,
        evidence=[],
        calibrated_confidence=None,
        coverage_gap_reason="Failed to fetch raw message content: HttpError 404",
        timestamp="2026-08-13T09:00:00+00:00",
    )

    run_view(config, store_db_path, 20, None)

    err = capsys.readouterr().err
    assert "CoverageGap" in err
    assert "0.000" not in err
    assert "0.500" not in err
    assert "N/A" in err
    assert "Failed to fetch raw message content" in err
    assert "1 shown, 0 skipped" in err


def test_run_view_verdict_filter_matches_coverage_gap(
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """[Story 6.1] --verdict CoverageGap must be a valid filter value,
    isolating coverage-gap records from everything else."""
    config = replace(store_config, evidence_db_path=store_db_path)
    _persist(store_db_path, config, "hash1", verdict="Malicious")
    _persist(
        store_db_path,
        config,
        "hash2",
        verdict="CoverageGap",
        sender=None,
        evidence=[],
        calibrated_confidence=None,
        coverage_gap_reason="Failed to fetch raw message content: HttpError 404",
        timestamp="2026-08-13T09:05:00+00:00",
    )

    run_view(config, store_db_path, 20, "CoverageGap")

    err = capsys.readouterr().err
    assert "1 shown, 0 skipped" in err  # hash1's Malicious record correctly filtered out
    assert "CoverageGap" in err


def test_run_view_renders_genuinely_legacy_record_missing_coverage_gap_reason_key(
    store_db_path: str,
    store_config: Config,
    make_evidence_item,  # type: ignore[no-untyped-def]
    capsys: pytest.CaptureFixture[str],
) -> None:
    """[Story 6.1 follow-up, Edge Case Hunter] Every existing coverage-gap
    test builds its report via _make_report/_persist, which always passes
    coverage_gap_reason explicitly (None or a string) -- the KEY is always
    present. A genuine pre-Story-6.1 record never had this key AT ALL, which
    is a different shape than {"coverage_gap_reason": None}: dict.get()
    handles both, but report["coverage_gap_reason"] only survives the first.
    This constructs a record with the key genuinely absent (bypassing the
    TypedDict constructor via a raw encrypted insert, mirroring test_store.py's
    test_read_recent_skips_malformed_but_decryptable_record_and_counts_it) and
    round-trips it through the real store.py encrypt/decrypt path and the
    real run_view/_format_view_table renderer -- so a future accidental
    change from .get() to [...] at worker.py's report.get("coverage_gap_reason")
    call site would fail this test with a KeyError, not silently pass."""
    import json
    import sqlite3

    from cryptography.fernet import Fernet

    config = replace(store_config, evidence_db_path=store_db_path)
    legacy_report = {
        "verdict": "Deferred",
        "calibrated_confidence": 0.5,
        "evidence": [
            make_evidence_item(
                name="spf", finding="borderline signal", weight=0.3, direction="malicious"
            )
        ],
        "schema_version": 1,
        "message_hash": "legacy-hash",
        "timestamp": "2026-01-01T00:00:00+00:00",
        # coverage_gap_reason deliberately absent -- not set to None, absent.
    }
    legacy_record = {
        "message_id": "legacy-m1",
        "sender": "legacy@example.com",
        "report": legacy_report,
        "deferral_threshold_used": 0.05,
    }
    fernet = Fernet(config.evidence_encryption_key.encode())  # type: ignore[union-attr]
    encrypted = fernet.encrypt(json.dumps(legacy_record).encode())
    conn = sqlite3.connect(store_db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS evidence_records ("
        "message_hash TEXT PRIMARY KEY, verdict_json BLOB NOT NULL, "
        "created_at TEXT NOT NULL, expires_at TEXT NOT NULL, schema_version INTEGER NOT NULL)"
    )
    conn.execute(
        "INSERT INTO evidence_records "
        "(message_hash, verdict_json, created_at, expires_at, schema_version) "
        "VALUES (?, ?, ?, ?, ?)",
        ("legacy-hash", encrypted, "2026-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00", 1),
    )
    conn.commit()
    conn.close()

    record = read_evidence_record(store_db_path, "legacy-hash", config)
    assert record is not None
    assert "coverage_gap_reason" not in record["report"]

    run_view(config, store_db_path, 20, None)

    err = capsys.readouterr().err
    assert "Deferred" in err
    assert "borderline signal" in err
    assert "1 shown, 0 skipped" in err


def test_run_view_empty_database_prints_clean_message_not_error(
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = replace(store_config, evidence_db_path=store_db_path)
    _persist(store_db_path, config, "temp-hash")
    import sqlite3

    conn = sqlite3.connect(store_db_path)
    conn.execute("DELETE FROM evidence_records")
    conn.commit()
    conn.close()

    run_view(config, store_db_path, 20, None)

    err = capsys.readouterr().err
    assert "no" in err.lower() or "0 shown" in err
    assert "0 shown, 0 skipped" in err


def test_run_view_missing_database_file_prints_clean_message_not_traceback(
    tmp_path: Path,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_path = str(tmp_path / "never-created.db")
    config = replace(store_config, evidence_db_path=missing_path)

    run_view(config, missing_path, 20, None)

    err = capsys.readouterr().err
    assert "no evidence database" in err.lower()


def test_run_view_undecryptable_record_skipped_and_reported(
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from cryptography.fernet import Fernet

    config = replace(store_config, evidence_db_path=store_db_path)
    _persist(store_db_path, config, "hash-good")
    other_key_config = replace(config, evidence_encryption_key=Fernet.generate_key().decode())
    _persist(store_db_path, other_key_config, "hash-bad-key")

    run_view(config, store_db_path, 20, None)

    err = capsys.readouterr().err
    assert "1 shown, 1 skipped" in err


def test_run_view_verdict_filter_shows_only_matching(
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = replace(store_config, evidence_db_path=store_db_path)
    _persist(store_db_path, config, "hash-malicious", verdict="Malicious", sender="a@example.com")
    _persist(store_db_path, config, "hash-benign", verdict="Benign", sender="b@example.com")

    run_view(config, store_db_path, 20, "Benign")

    err = capsys.readouterr().err
    assert "b@example.com" in err
    assert "a@example.com" not in err
    assert "1 shown, 0 skipped" in err


def test_run_view_respects_limit_showing_most_recent_first(
    store_db_path: str,
    store_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = replace(store_config, evidence_db_path=store_db_path)
    _persist(store_db_path, config, "hash-a", sender="a@example.com")
    _persist(store_db_path, config, "hash-b", sender="b@example.com")
    _persist(store_db_path, config, "hash-c", sender="c@example.com")
    import sqlite3

    conn = sqlite3.connect(store_db_path)
    conn.execute(
        "UPDATE evidence_records SET created_at = ? WHERE message_hash = ?",
        ("2026-01-01T00:00:00+00:00", "hash-a"),
    )
    conn.execute(
        "UPDATE evidence_records SET created_at = ? WHERE message_hash = ?",
        ("2026-01-02T00:00:00+00:00", "hash-b"),
    )
    conn.execute(
        "UPDATE evidence_records SET created_at = ? WHERE message_hash = ?",
        ("2026-01-03T00:00:00+00:00", "hash-c"),
    )
    conn.commit()
    conn.close()

    run_view(config, store_db_path, 2, None)

    err = capsys.readouterr().err
    assert "c@example.com" in err
    assert "b@example.com" in err
    assert "a@example.com" not in err
    assert "2 shown, 0 skipped" in err


# --- structural / boundary checks --------------------------------------------


def test_worker_imports_no_network_listening_library() -> None:
    source_path = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "triage" / "worker.py"
    tree = ast.parse(source_path.read_text())
    forbidden = {"fastapi", "uvicorn", "http.server", "socketserver", "flask", "aiohttp.web"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden, f"worker.py imports {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden, f"worker.py imports from {node.module}"


def test_triage_imports_no_remediation_capable_library() -> None:
    """AC3 (FR32): no path in the triage pipeline may execute containment,
    remediation, or any response action. This can't be proven exhaustively,
    but structurally removing the *capability* -- no email-sending, no
    shell-out, no raw OS-level file/process control -- makes it as close to
    true as an import-boundary test can get. Complements Story 1.3's
    test_build_gmail_service_uses_readonly_scope_and_single_mailbox_subject,
    which proves the Gmail client itself can't mutate the mailbox."""
    triage_dir = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "triage"
    forbidden = {"smtplib", "subprocess", "os"}
    for source_path in triage_dir.glob("*.py"):
        tree = ast.parse(source_path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in forbidden, (
                        f"{source_path.name} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden, (
                    f"{source_path.name} imports from {node.module}"
                )


_LIVE_TRIAGE_AGENT_FORBIDDEN_KWARGS = {"temperature", "cache", "budget"}


def _live_triage_agent_construction_kwargs(tree: ast.AST) -> list[str]:
    """Scans an AST for WatchmanAgent(...)/CipherAgent(...) calls and returns
    a description of any temperature/cache/budget keyword argument found --
    the three Story 4.2 params that must never reach worker.py's live-triage
    agent construction sites (AC5). Structural, not behavioral: proves the
    SOURCE CODE never wires these in, matching this codebase's established
    permanent-guard standard (test_triage_imports_no_remediation_capable_
    library above; the held_out/tuning AST guards in fit_real_calibration_
    model.py's and run_evaluation_harness.py's own test suites)."""
    violations: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"WatchmanAgent", "CipherAgent"}
        ):
            for kw in node.keywords:
                if kw.arg in _LIVE_TRIAGE_AGENT_FORBIDDEN_KWARGS:
                    violations.append(f"{node.func.id}(..., {kw.arg}=...)")
    return violations


def test_worker_never_passes_temperature_cache_budget_to_live_triage_agents() -> None:
    """[Story 4.2, AC5] Permanent structural guard: worker.py's live-triage
    WatchmanAgent(config)/CipherAgent(config) call sites (run_continuous_
    loop, --once dispatch) must never pass temperature/cache/budget --
    doing so would silently wire live triage into the real-corpus-script-
    only mechanisms (pinned temperature, Cipher caching, the API call
    ceiling) AC5 requires stay opt-in, with no other test positioned to
    catch it. This is the proof for the specific claim Task 3's Dev Notes
    make ("structurally unreachable from process_message") -- not just
    asserted in a summary."""
    source_path = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "triage" / "worker.py"
    tree = ast.parse(source_path.read_text())

    violations = _live_triage_agent_construction_kwargs(tree)

    assert violations == [], (
        f"worker.py passes a Story 4.2 param to a live-triage agent construction: {violations!r} "
        "-- this would silently change live triage behavior, violating AC5"
    )


def test_live_triage_agent_guard_detects_temperature_kwarg() -> None:
    poisoned = ast.parse("WatchmanAgent(config, temperature=0)")
    assert _live_triage_agent_construction_kwargs(poisoned) == ["WatchmanAgent(..., temperature=...)"]


def test_live_triage_agent_guard_detects_cache_kwarg() -> None:
    poisoned = ast.parse("CipherAgent(config, cache=cache)")
    assert _live_triage_agent_construction_kwargs(poisoned) == ["CipherAgent(..., cache=...)"]


def test_live_triage_agent_guard_detects_budget_kwarg() -> None:
    poisoned = ast.parse("WatchmanAgent(config, budget=budget)")
    assert _live_triage_agent_construction_kwargs(poisoned) == ["WatchmanAgent(..., budget=...)"]
