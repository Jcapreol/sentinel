"""Single-message triage pipeline (investigate -> score -> verdict -> report)
plus the sentinel-triage CLI entry point: --once (one poll cycle) and
--replay <message_hash> (audit a stored verdict). The continuous default-loop
mode is not implemented here — it requires Story 1.7's per-message failure
isolation, which does not exist yet.
"""

import argparse
import hashlib
import math
import sys
from datetime import datetime, timezone
from typing import Literal

from sentinel.config import Config, ConfigError
from sentinel.config import load as load_config
from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.headers import investigate_header_authentication
from sentinel.triage.ingest import (
    FetchFailed,
    build_gmail_service,
    extract_sender_and_content_hash,
    fetch_headers_for_messages,
    fetch_raw_message_bytes,
    poll_new_messages,
)
from sentinel.triage.report import TriageReport
from sentinel.triage.scoring import InconclusiveScoreError, compute_raw_score, determine_verdict
from sentinel.triage.store import (
    EvidenceRecord,
    load_history_checkpoint,
    mark_message_processed,
    persist_evidence_record,
    purge_expired,
    read_evidence_record,
    save_history_checkpoint,
    unmark_message_processed,
)

_DEFAULT_DB_PATH = "data/evidence.db"


def _require_valid_deferral_threshold(config: Config) -> None:
    if not (0.0 <= config.deferral_threshold <= 1.0):
        raise ConfigError(
            f"SENTINEL_DEFERRAL_THRESHOLD must be within [0.0, 1.0], got "
            f"{config.deferral_threshold!r}"
        )


def process_message(
    message_id: str, auth_results_header: str | None | FetchFailed, config: Config
) -> TriageReport:
    _require_valid_deferral_threshold(config)
    message_hash = hashlib.sha256(message_id.encode()).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()

    if isinstance(auth_results_header, FetchFailed):
        # A fetch failure carries no header data — never evidence, always a
        # deferred/coverage-gap outcome, the same way InconclusiveScoreError is
        # routed. Short-circuits before investigate_header_authentication /
        # compute_raw_score / determine_verdict are ever called.
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

    evidence = investigate_header_authentication(auth_results_header)
    raw_score = compute_raw_score(evidence)

    verdict: Literal["Malicious", "Benign", "Deferred"]
    try:
        verdict = determine_verdict(raw_score, deferral_band=config.deferral_threshold)
    except InconclusiveScoreError:
        verdict = "Deferred"

    return TriageReport(
        verdict=verdict,
        calibrated_confidence=raw_score,
        evidence=evidence,
        schema_version=1,
        message_hash=message_hash,
        timestamp=timestamp,
    )


def run_poll_cycle(config: Config, db_path: str) -> None:
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
        if not mark_message_processed(db_path, message_id):
            print(
                f"[worker] Skipping already-processed message {message_id!r}",
                file=sys.stderr,
            )
            continue

        # Everything from here through persist_evidence_record is wrapped:
        # mark_message_processed above already claimed message_id. If anything
        # below raises before persist_evidence_record confirms success, the
        # claim MUST be rolled back (unmark_message_processed) — otherwise the
        # message is permanently lost: marked processed, but no evidence
        # record ever exists, and no future poll cycle will ever retry it.
        try:
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
                report = process_message(message_id, auth_results_header, config)

            record = EvidenceRecord(
                message_id=message_id,
                sender=sender,
                report=report,
                deferral_threshold_used=config.deferral_threshold,
            )
            persist_evidence_record(db_path, content_hash, record, config)
        except Exception as e:
            # unmark_message_processed's own call is wrapped separately below:
            # if the rollback itself fails, that is a different, worse failure
            # mode than the one that triggered it (see the nested try/except).
            try:
                unmark_message_processed(db_path, message_id)
            except Exception as rollback_error:
                print(
                    f"[worker] CRITICAL: failed to roll back the processed-claim "
                    f"for message {message_id!r} after a processing failure "
                    f"({type(e).__name__}: {e}) — rollback itself failed with "
                    f"{type(rollback_error).__name__}: {rollback_error}. This "
                    "message is now stuck marked-processed with no evidence "
                    "record and will NOT be retried automatically.",
                    file=sys.stderr,
                )
            else:
                any_failures = True
                print(
                    f"[worker] Failed to process message {message_id!r}: "
                    f"{type(e).__name__}: {e} — un-marking as processed so it is "
                    "retried on a future poll cycle",
                    file=sys.stderr,
                )
            continue
        else:
            # Deliberately outside the try above: if this print() itself were to
            # raise (e.g. a broken stderr pipe), the except block would wrongly
            # roll back a message whose evidence was already durably persisted.
            print(
                f"[worker] Persisted evidence record {content_hash} for message "
                f"{message_id!r} (verdict={report['verdict']})",
                file=sys.stderr,
            )

    # If any message failed and was rolled back above, do NOT advance the
    # checkpoint to new_history_id -- history.list() only returns events
    # strictly after the saved checkpoint, so advancing past a failed
    # message's own history event would make it permanently unreachable on
    # every future cycle, silently breaking the "retried on a future poll
    # cycle" promise the rollback above claims to provide (2026-07-22
    # code-review follow-up). Keeping the OLD checkpoint means the next cycle
    # cheaply re-scans the same range: already-persisted messages are skipped
    # via mark_message_processed's ID check before any expensive work, and the
    # failed message is genuinely handed back for another attempt. since_history_id
    # is only None on a mailbox's very first cycle, which always returns zero
    # messages (see poll_new_messages), so any_failures can never be True here
    # when since_history_id is None -- the `is not None` check is for mypy only.
    checkpoint_to_save = (
        since_history_id
        if any_failures and since_history_id is not None
        else new_history_id
    )
    save_history_checkpoint(db_path, checkpoint_to_save)
    purge_expired(db_path, config)


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

    # PRE-EPIC-3 LANDMINE (see deferred-work.md, scoped to Story 3.2): this
    # compares original_report["calibrated_confidence"] against a freshly
    # recomputed RAW score. That only works today because calibrated_confidence
    # is currently a placeholder equal to the raw score. Once real calibration
    # ships, calibrated_confidence will correctly diverge from the raw score by
    # design, and every --replay call will report a false mismatch here.
    recomputed_score = compute_raw_score(original_report["evidence"])
    verdict: Literal["Malicious", "Benign", "Deferred"]
    try:
        verdict = determine_verdict(
            recomputed_score, deferral_band=record["deferral_threshold_used"]
        )
    except InconclusiveScoreError:
        verdict = "Deferred"
    recomputed_verdict = verdict

    print(f"Original verdict:   {original_report['verdict']}")
    print(f"Recomputed verdict: {recomputed_verdict}")
    print(f"Original score:     {original_report['calibrated_confidence']:.4f}")
    print(f"Recomputed score:   {recomputed_score:.4f}")

    mismatch = original_report["verdict"] != recomputed_verdict or not math.isclose(
        original_report["calibrated_confidence"], recomputed_score, abs_tol=1e-9
    )
    if mismatch:
        print(
            "sentinel-triage: MISMATCH — recomputed values differ from stored originals",
            file=sys.stderr,
        )
        sys.exit(1)

    print("sentinel-triage: replay matches stored originals", file=sys.stderr)
    sys.exit(0)


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
        description="SENTINEL — autonomous phishing triage worker",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--replay", metavar="MESSAGE_HASH", help="Recompute and diff a stored verdict"
    )
    mode_group.add_argument(
        "--once", action="store_true", help="Perform exactly one poll cycle and exit"
    )
    parser.add_argument(
        "--db-path", default=_DEFAULT_DB_PATH, help="Path to the evidence store SQLite file"
    )
    args = parser.parse_args()

    try:
        config = load_config()
    except ConfigError as exc:
        print(f"sentinel-triage: {exc}", file=sys.stderr)
        sys.exit(2)

    if args.replay is not None:
        _run_replay(args.replay, args.db_path, config)
        return  # unreachable in practice; kept for explicit control flow

    if args.once:
        run_poll_cycle(config, args.db_path)
        sys.exit(0)

    print(
        "sentinel-triage: no mode specified. Use --once for a single poll cycle "
        "or --replay <message_hash> to audit a stored verdict. Continuous "
        "unattended polling requires Story 1.7's failure-isolation wrapper and "
        "is not yet available.",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
