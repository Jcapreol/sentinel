"""Single-message triage pipeline (investigate -> score -> verdict -> report)
plus the sentinel-triage CLI entry point and its four modes: the default
continuous poll loop (run_continuous_loop), --once (one poll cycle),
--replay <message_hash> (audit a stored verdict), and --view (read-only
recent-verdicts table, Story 5.1).
"""

import argparse
import hashlib
import math
import signal
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from types import FrameType
from typing import Literal

from sentinel.alerter import AlertPayload, send_alert
from sentinel.cipher import CipherAgent
from sentinel.config import Config, ConfigError
from sentinel.config import load as load_config
from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.headers import investigate_header_authentication
from sentinel.triage.ingest import (
    FetchFailed,
    build_gmail_service,
    extract_email_content,
    extract_sender_and_content_hash,
    fetch_headers_for_messages,
    fetch_raw_message_bytes,
    poll_new_messages,
)
from sentinel.triage.report import TriageReport
from sentinel.triage.script_guard import ApiCallBudgetExceededError
from sentinel.triage.scoring import (
    InconclusiveScoreError,
    apply_calibration,
    compute_raw_score,
    determine_verdict,
)
from sentinel.triage.store import (
    EvidenceRecord,
    is_message_processed,
    load_history_checkpoint,
    persist_evidence_record,
    purge_expired,
    read_evidence_record,
    read_recent_evidence_records,
    save_history_checkpoint,
)
from sentinel.verdict import SentinelAgent
from sentinel.watchman import WatchmanAgent


def _require_valid_deferral_threshold(config: Config) -> None:
    if not (0.0 <= config.deferral_threshold <= 1.0):
        raise ConfigError(
            f"SENTINEL_DEFERRAL_THRESHOLD must be within [0.0, 1.0], got "
            f"{config.deferral_threshold!r}"
        )


def _require_valid_poll_interval(config: Config) -> None:
    """Validated lazily at first actual use (run_continuous_loop), mirroring
    deferral_threshold/retention_days -- poll_interval_seconds is a
    triage-only concern and load_config() is shared by the CLI/web
    dashboard, which never read it (2026-07-22 code-review follow-up: a
    negative value crashed on the first time.sleep() call; zero produced a
    busy-loop hammering the Gmail API)."""
    if config.poll_interval_seconds <= 0:
        raise ConfigError(
            f"SENTINEL_POLL_INTERVAL must be a positive integer, got "
            f"{config.poll_interval_seconds!r}"
        )


def gather_evidence_and_raw_score(
    auth_results_header: str | None,
    email_content: str,
    watchman: SentinelAgent,
    cipher: SentinelAgent,
) -> tuple[list[EvidenceItem], float]:
    """Pure refactor extracted from process_message (Story 3.3): header +
    Watchman + Cipher evidence gathering, merged into a raw_score via
    compute_raw_score. Deliberately stops here -- does NOT call
    apply_calibration/determine_verdict -- so this is reusable by
    fit_real_calibration_model.py's corpus-fitting script, which needs the
    raw score as fit_calibration_mapping's training input and cannot call
    apply_calibration first (the calibration model being fit doesn't exist
    yet -- that would be circular). process_message remains the only caller
    that goes on to compute calibrated_confidence/verdict from this."""
    header_evidence = investigate_header_authentication(auth_results_header)

    # Watchman (LLM behavioral analysis) and Cipher (VT/AbuseIPDB/URLhaus
    # reputation lookups) run concurrently, mirroring main.py's run_analysis
    # precedent exactly. Both shipped SentinelAgent implementations are
    # guaranteed to never raise and always populate `evidence` -- but
    # this function is deliberately typed against the bare SentinelAgent
    # Protocol (not the concrete classes), which enforces neither guarantee.
    # A third-party agent violating either one degrades to a coverage-gap
    # evidence item here, matching every other failure path in this
    # pipeline, rather than crashing (2026-07-23 code-review patch).
    with ThreadPoolExecutor(max_workers=2) as executor:
        watchman_future = executor.submit(watchman.analyze, email_content)
        cipher_future = executor.submit(cipher.analyze, email_content)
        try:
            watchman_evidence = watchman_future.result().get("evidence", [])
        except ApiCallBudgetExceededError:
            # Story 4.2: must propagate uncaught -- the generic except below
            # would otherwise convert a real-corpus script's budget-ceiling
            # abort into an ordinary "crashed unexpectedly" coverage-gap
            # item, letting the run silently continue past its configured
            # budget (AC3). Only fires for the two real-corpus scripts --
            # worker.py's own live-triage WatchmanAgent(config)/
            # CipherAgent(config) never construct a budget object, so this
            # branch is unreachable from process_message.
            #
            # Known, accepted limitation (code review, 2026-08-03): cipher_future
            # is already running concurrently at this point and is NOT cancelled
            # or awaited before this re-raises -- ThreadPoolExecutor cannot
            # forcibly cancel an in-flight task. Cipher's own budget check may
            # already have passed before Watchman's rejection is known here, so
            # a few extra real API calls (VT/AbuseIPDB/URLhaus, up to 3) can
            # slip through uncounted at the moment of abort. Deliberately not
            # fixed with cross-thread cancellation coordination -- the bound is
            # small (one file's worth of in-flight calls, not a systemic
            # overshoot) and real coordination is disproportionate complexity
            # for a boundary case. See deferred-work.md.
            raise
        except Exception as e:
            watchman_evidence = [
                EvidenceItem(
                    name="watchman_analysis",
                    finding=f"Watchman analysis crashed unexpectedly: {type(e).__name__} — "
                    "behavioral analysis unavailable",
                    weight=0.0,
                    direction="neutral",
                )
            ]
        try:
            cipher_evidence = cipher_future.result().get("evidence", [])
        except ApiCallBudgetExceededError:
            raise  # Story 4.2: see the identical guard above for watchman_evidence
        except Exception as e:
            cipher_evidence = [
                EvidenceItem(
                    name="cipher_analysis",
                    finding=f"Cipher analysis crashed unexpectedly: {type(e).__name__} — "
                    "threat intelligence lookup unavailable",
                    weight=0.0,
                    direction="neutral",
                )
            ]

    evidence = header_evidence + watchman_evidence + cipher_evidence
    raw_score = compute_raw_score(evidence)
    return evidence, raw_score


def check_structural_deferral(
    evidence: list[EvidenceItem], raw_score: float, deferral_band: float
) -> bool:
    """Two structural pre-calibration deferral gates (2026-07-30 calibration
    saturation incident), extracted out of process_message so process_message
    (the live pipeline) and run_evaluation_harness.py (the offline
    release-gate measurement) can never structurally diverge again. Before
    this extraction, the harness called apply_calibration/determine_verdict/
    gather_evidence_and_raw_score directly, bypassing process_message
    entirely -- so it never exercised either gate below, and its reported
    ECE/AUC-ROC/deferral rate stayed bit-for-bit identical before and after
    both gates were added to the live pipeline. Both callers now call this
    same function. Returns True if either gate fires; the caller builds
    whatever "Deferred" shape it needs (a TriageReport for process_message,
    a calibrated_confidence of 0.5 for the harness's pairs -- matching
    process_message's own convention for a structurally-deferred report)
    rather than this function producing one, since the two callers need
    different result shapes.

    Gate 1 (all-neutral evidence): if every evidence item found is
    direction="neutral" -- no real signal anywhere, not even a failed or
    conflicting check -- this is a zero-evidence case. Previously this
    relied entirely on calibrated_confidence landing within deferral_band of
    the neutral prior via determine_verdict -- correct only as long as
    apply_calibration behaved like an (approximately) monotonic,
    non-saturating curve. A real fitted isotonic model can legitimately be a
    hard step function that never outputs anything near 0.5 (see
    deferred-work.md's corpus-composition entry) -- apply_calibration(0.5)
    landing on 1.0 rather than ~0.5 silently defeated deferral_band-based
    protection entirely, giving a message with NO real evidence a confident
    "Malicious" verdict. This check operates on `direction` only,
    structurally, with no dependency on calibrated_confidence or
    deferral_band at all -- it can't be defeated by any future calibration
    curve's shape.

    Gate 2 (conflicting-but-uncertain evidence): weak-but-PRESENT
    directional evidence that nearly cancels (e.g. dmarc=pass vs spf=fail)
    is real signal, so Gate 1 correctly does not catch it -- but the real
    fitted calibration curve is not yet trustworthy to preserve that
    uncertainty either. The committed corpus (fit_real_calibration_model.py,
    2026-07-28) contains no ambiguous/conflicting-evidence examples, so PAVA
    had nothing to fit a middle output to and produced a pure 0.0/1.0 step
    function -- a raw_score of ~0.47 (barely leaning malicious) calibrates
    to a confident-looking 1.0, indistinguishable from a raw_score of 1.0.
    Checking raw_score directly -- before apply_calibration ever runs --
    routes around that untrustworthy curve entirely. This is deliberately a
    stopgap, not a permanent design choice: it exists because the
    calibration corpus lacks ambiguous/conflicting-evidence examples
    (tracked in deferred-work.md). Once that corpus is broadened, a real fit
    should again be able to preserve this uncertainty on its own, and this
    gate should be revisited.
    """
    if all(item["direction"] == "neutral" for item in evidence):
        return True
    return math.isclose(raw_score, 0.5, abs_tol=1e-9) or abs(raw_score - 0.5) < deferral_band


def process_message(
    message_id: str,
    auth_results_header: str | None | FetchFailed,
    email_content: str,
    watchman: SentinelAgent,
    cipher: SentinelAgent,
    config: Config,
) -> TriageReport:
    _require_valid_deferral_threshold(config)
    message_hash = hashlib.sha256(message_id.encode()).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()

    if isinstance(auth_results_header, FetchFailed):
        # A fetch failure carries no header data — never evidence, always a
        # deferred/coverage-gap outcome, the same way InconclusiveScoreError is
        # routed. Short-circuits before investigate_header_authentication /
        # compute_raw_score / determine_verdict — and now the Watchman/Cipher
        # calls below, too — are ever reached.
        return TriageReport(
            verdict="Deferred",
            calibrated_confidence=0.5,
            evidence=[
                EvidenceItem(
                    name="header_fetch",
                    finding="Failed to fetch the Authentication-Results header — "
                    "coverage gap, not evidence of a missing header",
                    weight=0.0,
                    direction="neutral",
                )
            ],
            schema_version=1,
            message_hash=message_hash,
            timestamp=timestamp,
        )

    evidence, raw_score = gather_evidence_and_raw_score(
        auth_results_header, email_content, watchman, cipher
    )

    # [Fix] Two structural pre-calibration deferral gates (all-neutral
    # evidence, and conflicting-but-uncertain evidence) -- see
    # check_structural_deferral's docstring for the full incident writeup.
    # Both route directly to Deferred BEFORE apply_calibration/
    # determine_verdict ever run, independent of how the calibration curve
    # behaves, present or future. Shared with run_evaluation_harness.py's
    # _score_one_file so the live pipeline and the offline release-gate
    # measurement can never structurally diverge on this again.
    if check_structural_deferral(evidence, raw_score, config.deferral_threshold):
        return TriageReport(
            verdict="Deferred",
            calibrated_confidence=0.5,
            evidence=evidence,
            schema_version=1,
            message_hash=message_hash,
            timestamp=timestamp,
        )

    calibrated_confidence = apply_calibration(raw_score)

    verdict: Literal["Malicious", "Benign", "Deferred"]
    try:
        verdict = determine_verdict(calibrated_confidence, deferral_band=config.deferral_threshold)
    except InconclusiveScoreError:
        verdict = "Deferred"

    return TriageReport(
        verdict=verdict,
        calibrated_confidence=calibrated_confidence,
        evidence=evidence,
        schema_version=1,
        message_hash=message_hash,
        timestamp=timestamp,
    )


_ALERT_VERDICT_SEVERITY = {"Benign": 0, "Deferred": 1, "Malicious": 2}
# [Review] Deliberately a SEPARATE set from _ALERT_VERDICT_SEVERITY above,
# not derived from its keys -- the severity dict needs a "Benign" entry to
# rank verdicts at all, but "Benign" is never a valid THRESHOLD (AC2: only
# "Deferred" or "Malicious"). Using the severity dict's keys for both jobs
# meant SENTINEL_ALERT_THRESHOLD=Benign passed validation and then, since
# rank 0 is <= every verdict's rank, silently alerted on every message,
# including genuinely benign ones -- found in review, regression-tested.
_ALERT_VALID_THRESHOLDS = {"Deferred", "Malicious"}
_ALERT_MAX_FINDINGS = 2
_ALERT_FINDING_MAX_LEN = 200


def _verdict_meets_alert_threshold(verdict: str, threshold: str) -> bool:
    """[Story 5.2] Explicit severity ranking, not string/enum-order
    comparison -- TriageReport["verdict"]'s Literal declaration order
    ("Malicious", "Benign", "Deferred") is not severity order. Returns
    False (never raises) for an unrecognized verdict -- an invalid verdict
    must never crash message processing (the record is already persisted
    by the time this runs), it must just fail to alert. `threshold`'s own
    validity is checked separately by the caller (_ALERT_VALID_THRESHOLDS),
    before this function is ever called."""
    verdict_rank = _ALERT_VERDICT_SEVERITY.get(verdict)
    threshold_rank = _ALERT_VERDICT_SEVERITY.get(threshold)
    if verdict_rank is None or threshold_rank is None:
        return False
    return verdict_rank >= threshold_rank


def _extract_subject_line(email_content: str) -> str | None:
    """email_content's first line is expected to be "Subject: {subject}"
    (see ingest.py's extract_email_content) -- parsed back out here only
    for the alert payload, never persisted or exposed elsewhere. [Review]
    A crafted RFC 2047 encoded-word Subject can decode to text containing
    an embedded newline; partition("\\n") then only sees the portion
    before it -- a safe, silent truncation (nothing after the embedded
    newline is used for anything), not a parse failure or injection risk,
    just not literally "always" the exact original subject verbatim."""
    first_line, _, _ = email_content.partition("\n")
    if not first_line.startswith("Subject: "):
        return None
    subject = first_line[len("Subject: "):]
    return subject if subject else None


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _maybe_dispatch_alert(
    config: Config, report: TriageReport, sender: str | None, subject: str | None
) -> None:
    """[Story 5.2] Called only from run_poll_cycle's success path, after
    persist_evidence_record has already committed -- alerting must never
    affect whether a message counts as successfully processed. Never
    raises: this function's own body is deliberately covered end-to-end by
    ONE try/except, not just the final send_alert call -- run_poll_cycle's
    `else:` clause that calls this is itself deliberately OUTSIDE the
    surrounding try/except (so a broken stderr print isn't misclassified
    as a processing failure), which means an exception raised anywhere in
    this function would otherwise propagate all the way out of
    run_poll_cycle and, via run_continuous_loop's "any exception is a
    PERSISTENT FAILURE" handling, kill the entire live worker process over
    a notification bug -- found in review; not reachable today (every
    caller passes a fully-populated TriageReport), but a real gap between
    what this function claimed and what was structurally enforced."""
    try:
        if not config.alert_enabled:
            return
        if config.alert_threshold not in _ALERT_VALID_THRESHOLDS:
            print(
                f"[worker] WARNING: SENTINEL_ALERT_THRESHOLD={config.alert_threshold!r} is "
                "invalid (must be 'Deferred' or 'Malicious') -- skipping alert check.",
                file=sys.stderr,
            )
            return
        if not _verdict_meets_alert_threshold(report["verdict"], config.alert_threshold):
            return

        findings = [
            _truncate(f"[{item['direction']}] {item['finding']}", _ALERT_FINDING_MAX_LEN)
            for item in _sorted_directional_findings(report["evidence"])[:_ALERT_MAX_FINDINGS]
        ]
        payload = AlertPayload(
            timestamp=report["timestamp"],
            sender=sender,
            subject=subject,
            verdict=report["verdict"],
            calibrated_confidence=report["calibrated_confidence"],
            findings=findings,
        )
        send_alert(config, payload)
    except Exception as e:
        print(
            f"[worker] WARNING: alert dispatch raised unexpectedly: "
            f"{type(e).__name__}: {e}",
            file=sys.stderr,
        )


def run_poll_cycle(
    config: Config, db_path: str, watchman: SentinelAgent, cipher: SentinelAgent
) -> None:
    """`watchman`/`cipher` are caller-provided (not instantiated here) so a
    caller invoking this repeatedly -- run_continuous_loop's `while True`
    loop -- can build each agent exactly once and reuse it across every
    cycle. CipherAgent/WatchmanAgent hold an httpx.Client/anthropic.Anthropic
    client with no explicit .close() anywhere in this codebase (the old
    one-shot CLI never needed one); instantiating fresh ones inside this
    function would leak a pair of unclosed clients every poll interval for
    the worker's entire lifetime (2026-07-23 code-review patch -- the
    original per-cycle placement only eliminated the per-message version of
    this leak, not the per-cycle one)."""
    service = build_gmail_service(config)
    mailbox = config.gmail_monitored_mailbox
    if mailbox is None:
        # build_gmail_service already fail-fast validates this — reachable only
        # if that invariant is ever broken. A plain `assert` would silently
        # evaporate under `python -O`; this raises unconditionally instead.
        raise RuntimeError(
            "config.gmail_monitored_mailbox is None after build_gmail_service "
            "succeeded — this should be unreachable"
        )

    since_history_id = load_history_checkpoint(db_path)
    messages, new_history_id = poll_new_messages(service, mailbox, since_history_id)

    any_failures = False
    for message in messages:
        message_id = message["id"]

        # is_message_processed is deliberately INSIDE this try (not checked
        # before it): if the read itself raises (e.g. a transient sqlite
        # lock), that must be treated as a per-message failure like any
        # other -- not escalated to run_continuous_loop as a cycle-level
        # "PERSISTENT FAILURE", which would kill the whole worker over a
        # single message's bookkeeping hiccup (2026-07-22 code-review
        # follow-up). `continue` from inside a `try` skips both `except` and
        # `else` (verified: no exception occurred, and control never falls
        # through to the end of the try body), so the "already processed"
        # skip below is neither a failure nor a persisted-success.
        #
        # Nothing below writes to the store until persist_evidence_record's
        # single atomic commit at the very end, which durably records both
        # the evidence AND the processed-message-id together. A failure
        # anywhere in this block -- including a hard process kill -- simply
        # means nothing was recorded for this message, and it is naturally
        # retried by a future poll cycle (is_message_processed above will
        # correctly report it as not yet processed).
        try:
            if is_message_processed(db_path, message_id):
                print(
                    f"[worker] Skipping already-processed message {message_id!r}",
                    file=sys.stderr,
                )
                continue

            header_results = fetch_headers_for_messages(service, mailbox, [message])
            auth_results_header = header_results[message_id]

            try:
                raw_bytes = fetch_raw_message_bytes(service, mailbox, message_id)
            except Exception as e:
                print(
                    f"[worker] Failed to fetch raw content for message {message_id!r}: "
                    f"{type(e).__name__}: {e} — persisting a Deferred coverage-gap "
                    "record; tamper-evidence hash unavailable for this one record",
                    file=sys.stderr,
                )
                sender = None
                subject = None  # no email content was ever fetched on this path
                # Deliberate, narrow exception to "message_hash is always a content
                # hash" (Story 1.5's invariant) — we never got the content to hash,
                # so we fall back to an ID-based hash. Named explicitly in the
                # persisted evidence item below, not silently substituted.
                content_hash = hashlib.sha256(message_id.encode()).hexdigest()
                report = TriageReport(
                    verdict="Deferred",
                    calibrated_confidence=0.5,
                    evidence=[
                        EvidenceItem(
                            name="raw_content_fetch",
                            finding="Failed to fetch raw message content — coverage "
                            "gap, tamper-evidence hash unavailable for this record",
                            weight=0.0,
                            direction="neutral",
                        )
                    ],
                    schema_version=1,
                    message_hash=content_hash,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            else:
                sender, content_hash = extract_sender_and_content_hash(raw_bytes)
                email_content = extract_email_content(raw_bytes)
                subject = _extract_subject_line(email_content)
                report = process_message(
                    message_id, auth_results_header, email_content, watchman, cipher, config
                )

            record = EvidenceRecord(
                message_id=message_id,
                sender=sender,
                report=report,
                deferral_threshold_used=config.deferral_threshold,
            )
            persist_evidence_record(db_path, content_hash, record, config)
        except Exception as e:
            any_failures = True
            print(
                f"[worker] Failed to process message {message_id!r}: "
                f"{type(e).__name__}: {e} — this message was never marked "
                "processed, so it will be retried on a future poll cycle",
                file=sys.stderr,
            )
            continue
        else:
            # Deliberately outside the try above: if this print() itself were
            # to raise (e.g. a broken stderr pipe), the except block would
            # wrongly log this as a processing failure (any_failures = True,
            # capping the checkpoint below) for a message whose evidence was
            # already durably persisted.
            print(
                f"[worker] Persisted evidence record {content_hash} for message "
                f"{message_id!r} (verdict={report['verdict']})",
                file=sys.stderr,
            )
            _maybe_dispatch_alert(config, report, sender, subject)

    # If any message failed above, it was never written to the store at all
    # (persist_evidence_record's atomic commit never happened) -- so do NOT
    # advance the checkpoint to new_history_id. history.list() only returns
    # events strictly after the saved checkpoint, so advancing past a failed
    # message's own history event would make it permanently unreachable on
    # every future cycle, silently breaking the "retried on a future poll
    # cycle" promise above (2026-07-22 code-review follow-up). Keeping the
    # OLD checkpoint means the next cycle cheaply re-scans the same range:
    # already-persisted messages are skipped via is_message_processed's ID
    # check before any expensive work, and the failed message is genuinely
    # handed back for another attempt. since_history_id is only None on a
    # mailbox's very first cycle, which always returns zero messages (see
    # poll_new_messages), so any_failures can never be True here when
    # since_history_id is None -- the `is not None` check is for mypy only.
    checkpoint_to_save = (
        since_history_id
        if any_failures and since_history_id is not None
        else new_history_id
    )
    save_history_checkpoint(db_path, checkpoint_to_save)
    purge_expired(db_path, config)


def _handle_sigterm(signum: int, frame: FrameType | None) -> None:
    """SIGTERM -- what `systemctl stop` actually sends -- has no default
    Python handler, unlike SIGINT/Ctrl+C, which Python already turns into
    KeyboardInterrupt automatically. Without this, SIGTERM kills the process
    immediately, bypassing run_continuous_loop's clean-shutdown path
    entirely. Raising KeyboardInterrupt here routes SIGTERM through the exact
    same except KeyboardInterrupt blocks already used for Ctrl+C -- same log
    line, same clean exit, one code path for both."""
    raise KeyboardInterrupt()


def run_continuous_loop(config: Config, db_path: str) -> None:
    """sentinel-triage's default (no-flag) mode: calls run_poll_cycle on an
    interval until interrupted (Ctrl+C/SIGINT or systemctl stop/SIGTERM) or a
    persistent (cycle-level) failure occurs.

    Per-message failures never reach this function as an exception -- they're
    already isolated inside run_poll_cycle (Story 1.6). If run_poll_cycle
    itself raises, that's a persistent failure (e.g. revoked Gmail
    credentials): log it distinctly from a per-message failure, then re-raise
    so the process exits. Restart-on-crash is deliberately an ops concern
    (systemd unit), not something this loop retries internally.
    """
    _require_valid_poll_interval(config)
    signal.signal(signal.SIGTERM, _handle_sigterm)
    # Instantiated once for the loop's entire lifetime, not once per cycle --
    # see run_poll_cycle's docstring for why (2026-07-23 code-review patch).
    watchman = WatchmanAgent(config)
    cipher = CipherAgent(config)
    while True:
        try:
            run_poll_cycle(config, db_path, watchman, cipher)
        except KeyboardInterrupt:
            # Ignore further SIGTERM immediately: a second SIGTERM landing
            # while this block is still running (e.g. mid-print) would
            # otherwise raise a fresh KeyboardInterrupt that escapes this
            # except clause entirely, bypassing the clean-shutdown path
            # (2026-07-22 code-review follow-up). Does not cover a second
            # Ctrl+C/SIGINT, which Python's own default handler delivers
            # independently of this registration.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            print("[worker] Shutting down (received interrupt)", file=sys.stderr)
            return
        except Exception as e:
            print(
                f"[worker] PERSISTENT FAILURE — poll cycle could not complete: "
                f"{type(e).__name__}: {e}. This is not a per-message issue; "
                "the worker is stopping rather than silently retrying a "
                "cycle-level failure. Most often this means revoked/expired "
                "Gmail credentials or a connectivity problem, but see the "
                "exception details above — it may not be.",
                file=sys.stderr,
            )
            raise

        try:
            time.sleep(config.poll_interval_seconds)
        except KeyboardInterrupt:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            print("[worker] Shutting down (received interrupt)", file=sys.stderr)
            return


def _run_replay(message_hash: str, db_path: str, config: Config) -> None:
    record = read_evidence_record(db_path, message_hash, config)
    if record is None:
        print(
            f"sentinel-triage: no stored record found for message_hash {message_hash!r}",
            file=sys.stderr,
        )
        sys.exit(1)

    original_report = record["report"]
    if original_report["schema_version"] != 1:
        print(
            f"sentinel-triage: stored record has schema_version "
            f"{original_report['schema_version']!r}, but this build only "
            f"understands version 1 — refusing to replay rather than risk "
            f"misinterpreting the data.",
            file=sys.stderr,
        )
        sys.exit(1)

    if "deferral_threshold_used" not in record:
        # This field was added by Story 1.6 — a record persisted before this
        # story shipped won't have it (EvidenceRecord is a schema-less JSON
        # blob, so old records round-trip with whatever keys they were
        # originally written with). schema_version alone doesn't catch this,
        # since it only versions the nested `report`, not the EvidenceRecord
        # wrapper itself.
        print(
            f"sentinel-triage: stored record for {message_hash!r} predates "
            "deferral_threshold_used tracking (persisted before Story 1.6) — "
            "refusing to replay rather than guess which threshold was "
            "originally in effect.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Story 3.2 resolves the pre-Epic-3 landmine tracked in deferred-work.md
    # (option (b) of the two documented there): replay now recomputes
    # calibration too and compares calibrated-to-calibrated, not
    # calibrated-to-raw. There is only one calibration model version in
    # existence so far (the identity placeholder), so "which version was
    # active at original-processing time" (option (a)) is not yet a
    # meaningful distinction to test against -- revisit if/when a second
    # calibration_model_v2.json (or a versioned-model-selection mechanism)
    # is ever introduced.
    recomputed_score = compute_raw_score(original_report["evidence"])
    recomputed_calibrated = apply_calibration(recomputed_score)
    verdict: Literal["Malicious", "Benign", "Deferred"]
    try:
        verdict = determine_verdict(
            recomputed_calibrated, deferral_band=record["deferral_threshold_used"]
        )
    except InconclusiveScoreError:
        verdict = "Deferred"
    recomputed_verdict = verdict

    print(f"Original verdict:   {original_report['verdict']}")
    print(f"Recomputed verdict: {recomputed_verdict}")
    print(f"Original score:     {original_report['calibrated_confidence']:.4f}")
    print(f"Recomputed score:   {recomputed_calibrated:.4f}")

    mismatch = original_report["verdict"] != recomputed_verdict or not math.isclose(
        original_report["calibrated_confidence"], recomputed_calibrated, abs_tol=1e-9
    )
    if mismatch:
        print(
            "sentinel-triage: MISMATCH — recomputed values differ from stored originals",
            file=sys.stderr,
        )
        sys.exit(1)

    print("sentinel-triage: replay matches stored originals", file=sys.stderr)
    sys.exit(0)


_VIEW_FINDING_MAX_LEN = 50


def _sorted_directional_findings(evidence: list[EvidenceItem]) -> list[EvidenceItem]:
    """All directional (malicious/benign) findings, highest-weight first.
    Neutral (coverage-gap/no-signal) items are excluded: they're never the
    interesting part of a finding at a glance. Shared by --view's table
    (Story 5.1, top-1, truncated) and the alert payload (Story 5.2,
    top-2, untruncated) so the "what's the most notable finding" logic
    exists in exactly one place."""
    directional = [item for item in evidence if item["direction"] != "neutral"]
    directional.sort(key=lambda item: item["weight"], reverse=True)
    return directional


def _format_finding_summary(evidence: list[EvidenceItem]) -> str:
    """Short summary of a record's most notable finding for the --view
    table (AC3) -- the highest-weight directional finding, truncated,
    with a "(+N more)" suffix if there are others."""
    directional = _sorted_directional_findings(evidence)
    if not directional:
        return "(no directional findings)"
    top = directional[0]
    finding_text = top["finding"]
    if len(finding_text) > _VIEW_FINDING_MAX_LEN:
        finding_text = finding_text[: _VIEW_FINDING_MAX_LEN - 1] + "…"
    summary = f"[{top['direction']}] {finding_text}"
    if len(directional) > 1:
        summary += f" (+{len(directional) - 1} more)"
    return summary


def _format_view_table(records: list[tuple[str, EvidenceRecord]]) -> str:
    header = f"{'TIMESTAMP':<26} {'SENDER':<30} {'VERDICT':<10} {'CONF':>6}  TOP FINDING"
    lines = [header, "-" * len(header)]
    for _message_hash, record in records:
        report = record["report"]
        sender = (record["sender"] or "(unknown sender)")[:30]
        timestamp = report["timestamp"][:25]
        verdict = report["verdict"]
        confidence = f"{report['calibrated_confidence']:.3f}"
        finding_summary = _format_finding_summary(report["evidence"])
        lines.append(
            f"{timestamp:<26} {sender:<30} {verdict:<10} {confidence:>6}  {finding_summary}"
        )
    return "\n".join(lines)


def run_view(config: Config, db_path: str, limit: int, verdict_filter: str | None) -> None:
    """Story 5.1: read-only recent-verdicts table. Never writes to stdout
    (project-context.md's stdout rule reserves it for _run_replay alone) --
    everything here goes to stderr, matching run_poll_cycle/
    run_continuous_loop's existing human-readable-operational-output
    convention. Never raises on a missing, locked, or
    record-level-unusable database -- all are reported as a clean
    message, per AC4/AC5's "must never crash" requirement. db_path is
    caller-resolved (see _run) rather than read off config directly here,
    matching every other mode's existing (config, db_path, ...) calling
    convention."""
    try:
        records, skipped = read_recent_evidence_records(db_path, config)
    except sqlite3.OperationalError as exc:
        # [Review] Distinguish "no file yet" from "file exists but the
        # connection still failed" (locked by a concurrently-running
        # sentinel-triage process, permission denied, corrupt file) --
        # both raise the identical sqlite3.OperationalError, and
        # conflating them under one "doesn't exist yet" message would
        # actively misdirect an operator debugging a transient lock.
        if not Path(db_path).exists():
            print(f"sentinel-triage: no evidence database found at {db_path!r} yet.", file=sys.stderr)
        else:
            print(
                f"sentinel-triage: could not open evidence database at {db_path!r}: {exc}",
                file=sys.stderr,
            )
        return

    if verdict_filter is not None:
        records = [r for r in records if r[1]["report"]["verdict"] == verdict_filter]
    shown = records[: max(limit, 0)]

    if shown:
        print(_format_view_table(shown), file=sys.stderr)
    elif limit <= 0:
        print(f"No records shown (--limit {limit}).", file=sys.stderr)
    else:
        print("No evidence records found.", file=sys.stderr)

    print(f"{len(shown)} shown, {skipped} skipped (undecryptable)", file=sys.stderr)


def main() -> None:
    try:
        _run()
    except SystemExit:
        raise
    except Exception as exc:
        print(
            f"sentinel-triage: unexpected error — {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


def _run() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel-triage",
        description="SENTINEL — autonomous phishing triage worker. Default "
        "(no flags): continuous poll loop, polling every "
        "SENTINEL_POLL_INTERVAL seconds until interrupted.",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--replay", metavar="MESSAGE_HASH", help="Recompute and diff a stored verdict"
    )
    mode_group.add_argument(
        "--once", action="store_true", help="Perform exactly one poll cycle and exit"
    )
    mode_group.add_argument(
        "--view",
        action="store_true",
        help="Display recent triage verdicts as a read-only table and exit",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Path to the evidence store SQLite file "
        "(default: config's evidence_db_path, an absolute, CWD-independent path)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="With --view, max records to show, most recent first (default: 20)",
    )
    parser.add_argument(
        "--verdict",
        default=None,
        choices=["Malicious", "Benign", "Deferred"],
        help="With --view, show only records matching this verdict",
    )
    args = parser.parse_args()

    try:
        config = load_config()
    except ConfigError as exc:
        print(f"sentinel-triage: {exc}", file=sys.stderr)
        sys.exit(2)

    # [Review] --db-path previously defaulted to a CWD-relative literal
    # ("data/evidence.db") independently of config.evidence_db_path's own
    # absolute default -- the two coincided only by accident of whatever
    # directory a mode happened to be launched from, silently reproducing
    # AC2's "never a bare CWD-relative path" bug at the seam between --view
    # and every other mode. Unified: an explicit --db-path is honored
    # verbatim by every mode (unchanged from before); omitting it now falls
    # back to the same absolute, config-resolved path for all four modes,
    # not just --view.
    if args.db_path is not None:
        db_path = args.db_path
    else:
        if not Path(config.evidence_db_path).is_absolute():
            print(
                f"sentinel-triage: evidence_db_path must be an absolute path, got "
                f"{config.evidence_db_path!r} — check SENTINEL_EVIDENCE_DB_PATH",
                file=sys.stderr,
            )
            sys.exit(2)
        db_path = config.evidence_db_path

    if args.replay is not None:
        _run_replay(args.replay, db_path, config)
        return  # unreachable in practice; kept for explicit control flow

    if args.once:
        run_poll_cycle(config, db_path, WatchmanAgent(config), CipherAgent(config))
        sys.exit(0)

    if args.view:
        run_view(config, db_path, args.limit, args.verdict)
        sys.exit(0)

    run_continuous_loop(config, db_path)
    sys.exit(0)


if __name__ == "__main__":
    main()
