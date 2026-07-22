"""Single-message triage pipeline: investigate -> score -> verdict -> report.

No polling loop, CLI entry point, or persistence lives here yet — those are
later stories' scope (1.5 persistence, 1.6 CLI modes, 1.7 operational safety).
"""

import hashlib
from datetime import datetime, timezone
from typing import Literal

from sentinel.config import Config, ConfigError
from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.headers import investigate_header_authentication
from sentinel.triage.ingest import FetchFailed
from sentinel.triage.report import TriageReport
from sentinel.triage.scoring import InconclusiveScoreError, compute_raw_score, determine_verdict


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
