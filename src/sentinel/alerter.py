"""Alert dispatch on Deferred-or-worse triage verdicts (Story 5.2). Email
body rendered for a non-technical reader (Story 12.1) -- plain-language
opening statement, sender/subject prominent, findings described by what
was checked rather than which vendor checked it, a dashboard-detail-view
link, numeric confidence kept but demoted out of the opening line.

Lives here, NOT under src/sentinel/triage/, deliberately: SMTP sending
needs smtplib, which is permanently forbidden anywhere under
src/sentinel/triage/*.py (test_triage_imports_no_remediation_capable_
library, AC3/FR32, scans every file in that directory). Mirrors where
cipher.py/watchman.py already sit -- a "logic layer" module
triage/worker.py calls into, not a triage/ file itself.

[Story 12.1] sender/subject/finding text are all ultimately attacker-
controlled (message headers and analyzer findings derived from message
content) -- every one of them is passed through _sanitize_single_line
before it ever reaches the rendered body, so a crafted embedded line break
can never make attacker-controlled text look like a separate, fabricated
section of this email. See _sanitize_single_line's own docstring for the
concrete mechanism (a confirmed-reachable RFC 5322 header-folding
continuation line in "From") this defends against, and for why the
neutralized character class is broader than just CR/LF.
"""

import smtplib
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Protocol, TypedDict
from urllib.parse import quote

from sentinel.config import Config
from sentinel.triage.evidence import EvidenceItem

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
    # [Story 12.1] The structured items themselves (not pre-flattened
    # "[direction] text" strings, as before this story) -- rendering a
    # finding in plain language (AC3) needs the analyzer identity
    # (item["name"]) to look up a human-facing description, which a
    # flattened string had already discarded. Selection (which findings,
    # how many) stays worker.py's job; only the human-readable rendering
    # of each selected item moved here, to the one module already
    # responsible for how an alert reads to a human.
    findings: list[EvidenceItem]
    # [Story 12.1, AC4] The record's message_hash, for a link to its
    # dashboard detail view -- None for an alert with no real underlying
    # record (send_test_alert, send_health_alert), in which case no
    # dashboard-link section is rendered at all (a link to a record that
    # doesn't exist would be worse than no link).
    message_hash: str | None
    # [Story 12.1, Review] True only for send_test_alert's synthetic
    # payload. AC1's new opening line ("Sentinel flagged an email as
    # likely PHISHING...") reads exactly like a genuine, urgent warning --
    # found in review: unlike the OLD format (a bland "Sentinel triage
    # alert: Malicious (confidence=1.000)" line), a --test-alert email now
    # has nothing distinguishing it from a real one until the findings
    # section, three paragraphs in. A test email previewed, forwarded, or
    # seen out of context by someone other than the operator who triggered
    # it now reads as a real, urgent phishing warning. A required field
    # (not defaulted) so every payload construction site -- worker.py's
    # real alerts, send_health_alert, send_test_alert, and every test that
    # builds a payload directly -- states its intent explicitly rather
    # than silently inheriting whatever a shared default happened to be.
    is_test: bool


class Alerter(Protocol):
    def send(self, payload: AlertPayload) -> None: ...


# [Story 12.1, Review] The first line of a test alert's body, ahead of
# even the normal opening line -- see AlertPayload["is_test"]'s own
# docstring for why this exists: without it, a test email reads exactly
# like a real, urgent phishing warning to anyone who sees it out of
# context (previewed, forwarded, or glanced at after the operator who
# triggered it has moved on).
_TEST_ALERT_BANNER = "TEST ALERT -- this did not come from a real email. Sent to verify Sentinel's alert delivery."

# [Story 12.1, AC1] Plain-language opening line per verdict/status -- no
# jargon, no numeric confidence (AC5 keeps confidence in the email, just
# not here). Keyed on the same strings AlertPayload["verdict"] already
# carries in practice: the two real triage verdicts that ever reach
# send_alert (Malicious/Deferred -- Benign/CoverageGap never meet
# worker.py's alert threshold) plus the two heartbeat status labels
# send_health_alert repurposes this same field for (Story 8.1). Anything
# else (CoverageGap under the defense-in-depth path documented on
# AlertPayload above, or a genuinely unrecognized value) falls back to
# _DEFAULT_OPENING_LINE rather than crashing or mis-describing what
# happened.
_OPENING_LINES: dict[str, str] = {
    "Malicious": (
        "Sentinel flagged an email as likely PHISHING. Do not click any "
        "links, open attachments, or reply."
    ),
    "Deferred": (
        "Sentinel flagged an email as suspicious but could not confirm it "
        "either way. Take a close look before you click any links, open "
        "attachments, or reply."
    ),
    "Unhealthy": (
        "Sentinel's mail monitor has stopped checking your inbox and needs attention."
    ),
    "Recovered": "Sentinel's mail monitor is checking your inbox again after an outage.",
}
_DEFAULT_OPENING_LINE = "Sentinel sent an alert."

# [Story 12.1, AC3] What each analyzer's EvidenceItem["name"] means in plain
# language -- "describe what was checked, not which vendor checked it."
# The vendor/product name (URLhaus, VirusTotal, SPF, ...) stays visible --
# it's already part of item["finding"]'s own text (see cipher.py/headers.py)
# -- just not the first thing a reader sees. Exhaustive as of this story
# against every EvidenceItem-constructing site in the codebase (cipher.py,
# watchman.py, triage/headers.py); an unrecognized name (a future analyzer,
# or a synthetic item from send_health_alert with no analyzer behind it at
# all) falls back to showing the finding text with no leading label at all
# in _format_finding_line, rather than a misleading generic placeholder.
_CHECK_DESCRIPTIONS: dict[str, str] = {
    "spf_check": "Sender address verification (SPF)",
    "dkim_check": "Message signature check (DKIM)",
    "dmarc_check": "Sender domain policy check (DMARC)",
    "header_auth_check": "Email authentication check",
    "urlhaus_finding": "Link safety check",
    "virustotal_finding": "Link and file reputation check",
    "abuseipdb_finding": "Sending server reputation check",
    "watchman_finding": "Message content review",
    "watchman_analysis": "Message content review",
}

# [Story 12.1, AC4] Matches dashboard-design.md's D3 SSH-tunnel convention
# (`ssh -L 8000:localhost:8000 ...`) and web/main.py's DEFAULT_HOST/
# DEFAULT_PORT -- not imported from sentinel.web.main directly: that module
# pulls in FastAPI/uvicorn, a dependency this SMTP-sending module has no
# other reason to carry. Duplicated as a small, stable literal instead;
# revisit if the dashboard's bind address/port ever becomes configurable.
_DASHBOARD_BASE_URL = "http://localhost:8000"

# [Story 12.1] Moved from triage/worker.py's _ALERT_FINDING_MAX_LEN --
# truncating a finding for DISPLAY is a rendering concern, which now lives
# entirely in this module; worker.py's own _ALERT_MAX_FINDINGS (which
# findings are selected at all, and how many) is a separate, unrelated
# concern and stays there.
_FINDING_MAX_LEN = 200


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _sanitize_single_line(text: str) -> str:
    """[Story 12.1, AC6] sender/subject/finding text all ultimately derive
    from attacker-controlled message content. Confirmed reachable for
    "From" specifically: email.message_from_bytes uses the default
    compat32 policy everywhere in this codebase (no policy is ever set),
    and under compat32, Message.get() does NOT decode RFC 2047
    encoded-words -- an encoded-word's base64/quoted-printable alphabet
    can never contain a raw CR/LF anyway, so that mechanism was never
    actually reachable. The real, confirmed mechanism is RFC 5322 header
    FOLDING: a crafted "From" header with a continuation line round-trips
    through .get("From") with the fold's line break intact, e.g.
    'Attacker <a@x>\\r\\n Verdict: Benign -- this is safe' -- and
    ingest.extract_sender_and_content_hash reads it with no truncation of
    its own, unlike Subject, whose extraction (worker._extract_subject_
    line) already truncates at the first "\\n" as a side effect of how it
    parses the subject line back out of email_content. This alert body is
    a single text/plain payload built by joining lines with "\\n" -- an
    unneutralized embedded line break in any attacker-controlled field
    would let it inject what LOOKS like a separate, fabricated section of
    THIS email (e.g. a fake "Verdict: Benign -- this is safe" line), which
    is a uniquely bad outcome for a tool whose entire purpose is warning
    about exactly this kind of deception.

    [Review] A first version of this function only replaced "\\r\\n",
    "\\r", "\\n" -- missing vertical tab (\\x0b), form feed (\\x0c), and
    the Unicode forced-break characters (\\x85, \\u2028, \\u2029, and
    others), all of which Python's own str.splitlines() -- the same
    line-boundary definition various terminals and renderers honor --
    already treats as line breaks, and which a real, reachable header
    value can carry the same way "\\r\\n" can. Uses splitlines() itself,
    reusing Python's own definition of a line boundary rather than an
    ad hoc, inevitably-incomplete list of literal characters, so this
    covers the whole class rather than only the ones an earlier version
    happened to enumerate. Collapsed onto a single line -- never dropped,
    so the content stays visible -- before it ever reaches
    _format_alert_body, regardless of what any upstream caller already
    guarantees."""
    return " ".join(text.splitlines())


def _format_finding_line(item: EvidenceItem) -> str:
    detail = _truncate(_sanitize_single_line(item["finding"]), _FINDING_MAX_LEN)
    description = _CHECK_DESCRIPTIONS.get(item["name"])
    if description is None:
        return f"  - {detail}"
    return f"  - {description}: {detail}"


def _format_alert_body(payload: AlertPayload) -> str:
    """[Story 12.1] Rewritten for a non-technical reader (Notes for dev:
    "a small business owner, not an analyst") -- AC1 leads with a plain-
    language statement of what happened and what to do; AC2 puts sender/
    subject immediately after it; AC3 renders findings with a plain-
    language description leading, analyzer/vendor detail still present but
    not first; AC4 links to the record's dashboard detail view, stating
    plainly that it needs the tunnel rather than presenting a link that
    silently fails for the reader; AC5 keeps the numeric confidence, just
    not in the opening line -- it moved to the technical footer at the
    bottom, alongside the verdict and timestamp the original format led
    with."""
    confidence_display = (
        f"{payload['calibrated_confidence']:.3f}"
        if payload["calibrated_confidence"] is not None
        else "N/A"
    )
    opening_line = _OPENING_LINES.get(payload["verdict"], _DEFAULT_OPENING_LINE)
    sender_display = (
        _sanitize_single_line(payload["sender"]) if payload["sender"] else "(unknown sender)"
    )

    lines = []
    if payload["is_test"]:
        lines.append(_TEST_ALERT_BANNER)
        lines.append("")
    lines.extend([opening_line, "", f"From: {sender_display}"])
    if payload["subject"]:
        lines.append(f"Subject: {_sanitize_single_line(payload['subject'])}")

    if payload["findings"]:
        lines.append("")
        lines.append("What Sentinel checked:")
        lines.extend(_format_finding_line(item) for item in payload["findings"])

    if payload["message_hash"]:
        lines.append("")
        lines.append(
            "Full details are on the Sentinel dashboard. This link only opens while "
            "you're connected through the tunnel to the monitoring computer:"
        )
        lines.append(f"  {_DASHBOARD_BASE_URL}/verdicts/{quote(payload['message_hash'], safe='')}")

    lines.append("")
    lines.append("---")
    lines.append(f"Verdict: {payload['verdict']}    Confidence: {confidence_display}")
    lines.append(f"Timestamp: {payload['timestamp']}")
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
        subject = f"{SELF_ALERT_SUBJECT_PREFIX} {payload['verdict']}"
        if payload["is_test"]:
            # [Story 12.1, Review] Appended, not prepended -- the self-alert
            # secondary guard (_is_self_alert in worker.py) matches on
            # subject.startswith(SELF_ALERT_SUBJECT_PREFIX); this must stay
            # true for a test alert too, so it's still correctly recognized
            # and skipped if it ever lands back in the monitored mailbox.
            subject += " (TEST)"
        message["Subject"] = subject
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
        # [Story 12.1] name="urlhaus_finding" (a real, recognized analyzer
        # name, not a synthetic placeholder) so --test-alert exercises the
        # exact same plain-language finding-rendering path a real phishing
        # alert would, rather than a simplified stand-in -- the finding
        # TEXT itself still says plainly that it's synthetic.
        findings=[
            EvidenceItem(
                name="urlhaus_finding",
                finding="This is a synthetic test alert -- no real message was triaged.",
                weight=1.0,
                direction="malicious",
            )
        ],
        # No real evidence record backs this alert -- see AlertPayload's
        # own docstring for why None means "omit the dashboard-link
        # section" rather than linking to a record that doesn't exist.
        message_hash=None,
        is_test=True,
    )
    try:
        alerter.send(payload)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    return True, f"Test alert sent successfully to {recipient}."


def send_health_alert(config: Config, status: str, detail: str) -> None:
    """[Story 8.1] A heartbeat/liveness alert -- also does not originate
    from a triage verdict, exactly like send_test_alert above, and reuses
    the identical technique: repurpose AlertPayload's fields rather than
    add a parallel alerting path. `verdict` becomes a short status label
    ("Unhealthy"/"Recovered"), not a real triage verdict; `findings` carries
    the descriptive detail (the failure cause for an Unhealthy alert, or a
    recovery summary); `sender` is a fixed descriptive string (there is no
    real email sender to report); `calibrated_confidence` is None (no
    numeric score applies).

    Deliberately does NOT check config.alert_enabled -- that flag gates
    VERDICT alerts specifically (worker.py's _maybe_dispatch_alert checks
    it before ever calling send_alert). Heartbeat alerts have their own,
    independent gate (config.alert_heartbeat_enabled, checked by the caller
    in triage/health.py before this function is ever reached) -- see this
    story's AC7 answer for why they must not share the same flag.

    Fire-and-forget like send_alert itself: never raises, since a failure
    to SEND a health alert must not become a new crash inside the health-
    check machinery that exists specifically to catch failures."""
    payload = AlertPayload(
        timestamp=datetime.now(timezone.utc).isoformat(),
        sender="sentinel-triage (heartbeat monitor)",
        subject=None,
        verdict=status,
        calibrated_confidence=None,
        # [Story 12.1] name="heartbeat_status" matches nothing in
        # _CHECK_DESCRIPTIONS by design -- this isn't an analyzer finding
        # about an email, it's an operational status detail, and
        # _format_finding_line renders an unrecognized name as plain text
        # with no leading label rather than a misleading "what was
        # checked" description.
        findings=[
            EvidenceItem(name="heartbeat_status", finding=detail, weight=1.0, direction="neutral")
        ],
        # No evidence record corresponds to a heartbeat status -- see
        # AlertPayload's own docstring.
        message_hash=None,
        is_test=False,
    )
    send_alert(config, payload)
