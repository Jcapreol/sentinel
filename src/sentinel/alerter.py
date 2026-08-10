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


class AlertPayload(TypedDict):
    timestamp: str
    sender: str | None
    subject: str | None
    verdict: str
    calibrated_confidence: float
    findings: list[str]


class Alerter(Protocol):
    def send(self, payload: AlertPayload) -> None: ...


def _format_alert_body(payload: AlertPayload) -> str:
    lines = [
        f"Sentinel triage alert: {payload['verdict']} "
        f"(confidence={payload['calibrated_confidence']:.3f})",
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
        message["Subject"] = f"Sentinel alert: {payload['verdict']}"
        message["From"] = self._username
        message["To"] = self._recipient
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


def send_alert(config: Config, payload: AlertPayload) -> None:
    """Fire-and-forget: never raises. AC6's "must never crash or block
    message processing" guarantee lives here -- every failure mode
    (misconfigured channel, network error, timeout, bad credentials) is
    caught and logged as a single warning line, never propagated."""
    host = config.alert_smtp_host
    username = config.alert_smtp_username
    password = config.alert_smtp_password
    recipient = config.alert_smtp_recipient
    if host is None or username is None or password is None or recipient is None:
        print(
            "[alerter] WARNING: alerting is enabled but the SMTP channel is "
            "not fully configured (need SENTINEL_ALERT_SMTP_HOST/USERNAME/"
            "PASSWORD/RECIPIENT) -- skipping this alert.",
            file=sys.stderr,
        )
        return

    alerter: Alerter = EmailAlerter(host, config.alert_smtp_port, username, password, recipient)
    try:
        alerter.send(payload)
    except Exception as e:
        print(
            f"[alerter] WARNING: failed to send alert: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
