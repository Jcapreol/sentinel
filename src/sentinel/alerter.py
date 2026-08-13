"""Alert dispatch on Deferred-or-worse triage verdicts (Story 5.2).

Lives here, NOT under src/sentinel/triage/, deliberately: SMTP sending
needs smtplib, which is permanently forbidden anywhere under
src/sentinel/triage/*.py (test_triage_imports_no_remediation_capable_
library, AC3/FR32, scans every file in that directory). Mirrors where
cipher.py/watchman.py already sit -- a "logic layer" module
triage/worker.py calls into, not a triage/ file itself.
"""

import smtplib
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Protocol, TypedDict

from sentinel.config import Config

_SMTP_TIMEOUT_SECONDS = 10
# [Review] Gmail (and most providers) document two SMTP submission ports
# with genuinely different protocols, not just different numbers: 587 is
# plaintext-connect-then-STARTTLS, 465 is implicit TLS from the first byte
# (smtplib.SMTP_SSL, not smtplib.SMTP). Config's test data already used
# 465 as an "example" value before this existed -- plaintext-then-starttls
# against port 465 fails outright, every time, silently (caught generically
# by send_alert's except Exception, but non-functional with no specific
# diagnostic).
_IMPLICIT_TLS_PORT = 465

# [Story 5.2.1] Every alert this module sends carries this header + value --
# the primary signal worker.py uses to recognize and skip its own alert
# emails landing back in the monitored inbox. Without it, an alert email is
# indistinguishable from a real inbound message: it lands, the next poll
# triages it, its own body says "Malicious", so it scores Malicious and
# fires another alert -- forever. A fixed name/value is sufficient for this
# single-instance deployment (see this story's Dev Notes).
SELF_ALERT_HEADER_NAME = "X-Sentinel-Alert"
SELF_ALERT_HEADER_VALUE = "1"
# Shared with worker.py's secondary (sender+subject) self-alert guard, which
# checks an inbound Subject against this same prefix -- imported rather than
# duplicated so the two can never drift apart.
SELF_ALERT_SUBJECT_PREFIX = "Sentinel alert:"


class AlertPayload(TypedDict):
    timestamp: str
    sender: str | None
    subject: str | None
    verdict: str
    # [Story 6.1] None for a CoverageGap verdict (no analysis ran, so
    # there is no confidence to report) -- see TriageReport's own
    # calibrated_confidence docstring in triage/report.py. In practice a
    # CoverageGap report never actually reaches send_alert (it has no
    # entry in worker.py's _ALERT_VERDICT_SEVERITY ranking, so
    # _verdict_meets_alert_threshold always returns False for it), but
    # this field's type and _format_alert_body's rendering stay correct
    # regardless, as defense in depth rather than relying on that one
    # upstream gate alone.
    calibrated_confidence: float | None
    findings: list[str]


class Alerter(Protocol):
    def send(self, payload: AlertPayload) -> None: ...


def _format_alert_body(payload: AlertPayload) -> str:
    confidence_display = (
        f"{payload['calibrated_confidence']:.3f}"
        if payload["calibrated_confidence"] is not None
        else "N/A"
    )
    lines = [
        f"Sentinel triage alert: {payload['verdict']} "
        f"(confidence={confidence_display})",
        "",
        f"Timestamp: {payload['timestamp']}",
        f"Sender: {payload['sender'] or '(unknown)'}",
    ]
    if payload["subject"]:
        lines.append(f"Subject: {payload['subject']}")
    lines.append("")
    lines.append("Findings:")
    if payload["findings"]:
        for finding in payload["findings"]:
            lines.append(f"  {finding}")
    else:
        lines.append("  (none)")
    return "\n".join(lines)


class EmailAlerter:
    """SMTP email channel. Constructed only once send_alert has confirmed
    host/username/password/recipient are all present -- takes individually
    typed str/int fields, not the whole Config object, so mypy --strict
    narrows them without needing redundant runtime assertions here."""

    def __init__(self, host: str, port: int, username: str, password: str, recipient: str) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._recipient = recipient

    def send(self, payload: AlertPayload) -> None:
        message = EmailMessage()
        message["Subject"] = f"{SELF_ALERT_SUBJECT_PREFIX} {payload['verdict']}"
        message["From"] = self._username
        message["To"] = self._recipient
        message[SELF_ALERT_HEADER_NAME] = SELF_ALERT_HEADER_VALUE
        message.set_content(_format_alert_body(payload))

        if self._port == _IMPLICIT_TLS_PORT:
            with smtplib.SMTP_SSL(self._host, self._port, timeout=_SMTP_TIMEOUT_SECONDS) as smtp:
                smtp.login(self._username, self._password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(self._host, self._port, timeout=_SMTP_TIMEOUT_SECONDS) as smtp:
                smtp.starttls()
                smtp.login(self._username, self._password)
                smtp.send_message(message)


_SMTP_NOT_CONFIGURED_MESSAGE = (
    "SMTP channel is not fully configured (need SENTINEL_ALERT_SMTP_HOST/"
    "USERNAME/PASSWORD/RECIPIENT)."
)


def _build_email_alerter(config: Config) -> tuple[Alerter, str] | None:
    """Returns (alerter, recipient) if host/username/password/recipient
    are all present, else None. Shared by send_alert (fire-and-forget,
    prints its own warning on None) and send_test_alert (--test-alert,
    returns the same condition as part of its (bool, str) result instead)
    so the "is this channel usable at all" check exists in exactly one
    place."""
    host = config.alert_smtp_host
    username = config.alert_smtp_username
    password = config.alert_smtp_password
    recipient = config.alert_smtp_recipient
    if host is None or username is None or password is None or recipient is None:
        return None
    return EmailAlerter(host, config.alert_smtp_port, username, password, recipient), recipient


def send_alert(config: Config, payload: AlertPayload) -> None:
    """Fire-and-forget: never raises. AC6's "must never crash or block
    message processing" guarantee lives here -- every failure mode
    (misconfigured channel, network error, timeout, bad credentials) is
    caught and logged as a single warning line, never propagated."""
    built = _build_email_alerter(config)
    if built is None:
        print(
            f"[alerter] WARNING: alerting is enabled but the {_SMTP_NOT_CONFIGURED_MESSAGE} "
            "-- skipping this alert.",
            file=sys.stderr,
        )
        return
    alerter, _recipient = built
    try:
        alerter.send(payload)
    except Exception as e:
        print(
            f"[alerter] WARNING: failed to send alert: {type(e).__name__}: {e}",
            file=sys.stderr,
        )


def send_test_alert(config: Config) -> tuple[bool, str]:
    """[sentinel-triage --test-alert] Sends one synthetic alert through
    the exact same EmailAlerter path send_alert uses (including the
    port-465-implicit-TLS branch) -- but unlike send_alert's deliberately
    silent-on-success, warn-and-continue contract, this returns an
    explicit (success, message) for the CLI to print. Does not print
    anything itself: the caller decides how/where to display the result.
    Never touches Gmail, the evidence store, or the triage pipeline --
    this function's only job is exercising the alert-send path on
    demand."""
    built = _build_email_alerter(config)
    if built is None:
        return False, _SMTP_NOT_CONFIGURED_MESSAGE
    alerter, recipient = built

    payload = AlertPayload(
        timestamp=datetime.now(timezone.utc).isoformat(),
        sender="sentinel-triage --test-alert",
        subject=None,
        verdict="Malicious",
        calibrated_confidence=1.0,
        findings=[
            "[malicious] This is a synthetic test alert -- no real message was triaged."
        ],
    )
    try:
        alerter.send(payload)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    return True, f"Test alert sent successfully to {recipient}."
