from dataclasses import replace

import pytest

from sentinel.alerter import (
    SELF_ALERT_HEADER_NAME,
    SELF_ALERT_HEADER_VALUE,
    SELF_ALERT_SUBJECT_PREFIX,
    AlertPayload,
    EmailAlerter,
    send_alert,
    send_health_alert,
    send_test_alert,
)
from sentinel.config import Config
from sentinel.triage.evidence import EvidenceItem
from sentinel.triage.ingest import extract_header_value


def _configured(fake_config: Config) -> Config:
    return replace(
        fake_config,
        alert_smtp_host="smtp.gmail.com",
        alert_smtp_port=587,
        alert_smtp_username="me@gmail.com",
        alert_smtp_password="app-password",
        alert_smtp_recipient="alerts@example.com",
    )


def _email_alerter() -> EmailAlerter:
    return EmailAlerter(
        host="smtp.gmail.com",
        port=587,
        username="me@gmail.com",
        password="app-password",
        recipient="alerts@example.com",
    )


def _payload(
    subject: str | None = "Password reset required",
    message_hash: str | None = "8eab2236deadbeef",
) -> AlertPayload:
    return AlertPayload(
        timestamp="2026-08-09T12:00:00+00:00",
        sender="phisher@evil.example",
        subject=subject,
        verdict="Malicious",
        calibrated_confidence=0.91,
        findings=[
            EvidenceItem(
                name="urlhaus_finding",
                finding="Suspicious login URL requesting credentials",
                weight=0.6,
                direction="malicious",
            ),
            EvidenceItem(
                name="watchman_finding",
                finding="Generic greeting inconsistent with a real corporate email",
                weight=0.4,
                direction="malicious",
            ),
        ],
        message_hash=message_hash,
        is_test=False,
    )


# --- send_alert: missing configuration ---------------------------------------


@pytest.mark.parametrize(
    "field",
    ["alert_smtp_host", "alert_smtp_username", "alert_smtp_password", "alert_smtp_recipient"],
)
def test_send_alert_skips_and_warns_when_a_required_field_is_missing(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
    capsys: pytest.CaptureFixture[str],
    field: str,
) -> None:
    config = replace(_configured(fake_config), **{field: None})
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")

    send_alert(config, _payload())

    smtp_cls.assert_not_called()
    err = capsys.readouterr().err
    assert "not fully configured" in err.lower()


def test_send_alert_only_warns_once_per_call_not_multiple_lines(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = replace(_configured(fake_config), alert_smtp_host=None)

    send_alert(config, _payload())

    err = capsys.readouterr().err
    assert err.count("not fully configured") == 1


# --- send_alert: successful dispatch -------------------------------------------


def test_send_alert_constructs_and_sends_via_smtp(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    config = _configured(fake_config)
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value

    send_alert(config, _payload())

    smtp_cls.assert_called_once_with("smtp.gmail.com", 587, timeout=mocker.ANY)
    smtp_instance.starttls.assert_called_once()
    smtp_instance.login.assert_called_once_with("me@gmail.com", "app-password")
    smtp_instance.send_message.assert_called_once()
    sent_message = smtp_instance.send_message.call_args.args[0]
    assert sent_message["From"] == "me@gmail.com"
    assert sent_message["To"] == "alerts@example.com"


def test_email_alerter_uses_implicit_tls_for_port_465(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    """[Review] Port 465 (implicit TLS/SSL) is a common, plausible Gmail
    SMTP configuration -- the test data for the config-parsing tests
    already used 465 as an "example" value before this fix, without it
    actually working: plaintext-connect-then-starttls (what EmailAlerter
    always did) is wrong for 465 and fails outright, silently (caught
    generically by send_alert, but non-functional with no specific
    diagnostic). smtplib.SMTP_SSL is the correct client for this port."""
    config = replace(_configured(fake_config), alert_smtp_port=465)
    smtp_ssl_cls = mocker.patch("sentinel.alerter.smtplib.SMTP_SSL")
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_ssl_instance = smtp_ssl_cls.return_value.__enter__.return_value

    send_alert(config, _payload())

    smtp_ssl_cls.assert_called_once_with("smtp.gmail.com", 465, timeout=mocker.ANY)
    smtp_cls.assert_not_called()
    smtp_ssl_instance.starttls.assert_not_called()
    smtp_ssl_instance.login.assert_called_once_with("me@gmail.com", "app-password")
    smtp_ssl_instance.send_message.assert_called_once()


def test_email_alerter_message_body_includes_all_payload_fields(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()

    alerter.send(_payload())

    sent_message = smtp_instance.send_message.call_args.args[0]
    body = sent_message.get_content()
    assert "Malicious" in body
    assert "0.910" in body
    assert "phisher@evil.example" in body
    assert "Password reset required" in body
    assert "Link safety check: Suspicious login URL requesting credentials" in body


def test_email_alerter_stamps_self_alert_marker_header(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """[Story 5.2.1] Every alert email must carry a distinguishing header so
    worker.py can recognize and skip its own alerts landing back in the
    monitored inbox (AC1) -- without this, an alert email is indistinguishable
    from a real inbound message and the next poll cycle re-triages it,
    scores it Malicious (its own body says so), and re-alerts forever."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = EmailAlerter(
        host="smtp.gmail.com",
        port=587,
        username="me@gmail.com",
        password="app-password",
        recipient="alerts@example.com",
    )

    alerter.send(_payload())

    sent_message = smtp_instance.send_message.call_args.args[0]
    assert sent_message[SELF_ALERT_HEADER_NAME] == SELF_ALERT_HEADER_VALUE


def test_self_alert_marker_survives_send_to_parse_round_trip(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """[Review] The two ends of the loop-closing guarantee were previously
    only proven correct in isolation: this test's sibling above asserts on
    the in-memory EmailMessage object EmailAlerter builds, while worker.py's
    self-alert tests hand-author raw bytes with the header pre-baked in.
    Neither proves the header actually survives real MIME serialization and
    re-parsing. This wires the two ends together: the exact EmailMessage
    object EmailAlerter.send() constructs, serialized via .as_bytes() (real
    MIME encoding, not a shortcut), then read back via
    ingest.extract_header_value -- the exact function worker.py's self-alert
    check calls on real inbound raw bytes."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = EmailAlerter(
        host="smtp.gmail.com",
        port=587,
        username="me@gmail.com",
        password="app-password",
        recipient="alerts@example.com",
    )

    alerter.send(_payload())

    sent_message = smtp_instance.send_message.call_args.args[0]
    raw_bytes = sent_message.as_bytes()
    assert extract_header_value(raw_bytes, SELF_ALERT_HEADER_NAME) == SELF_ALERT_HEADER_VALUE


def test_health_alert_marker_survives_send_to_parse_round_trip(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    """[Story 8.1, Notes for dev] "Confirm the existing X-Sentinel-Alert
    header plus sender-match logic covers [health alerts] too." Sibling of
    test_self_alert_marker_survives_send_to_parse_round_trip above, same
    real-MIME-round-trip technique, but going through send_health_alert's
    actual construction path (not a hand-built AlertPayload) -- confirms
    the marker isn't somehow lost by health alerts' different payload
    shape (verdict repurposed as a status label, sender a fixed
    descriptive string, no real subject)."""
    config = _configured(fake_config)
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value

    send_health_alert(config, status="Unhealthy", detail="No successful poll for 35 minutes.")

    sent_message = smtp_instance.send_message.call_args.args[0]
    raw_bytes = sent_message.as_bytes()
    assert extract_header_value(raw_bytes, SELF_ALERT_HEADER_NAME) == SELF_ALERT_HEADER_VALUE
    # The secondary (sender+subject) guard's two conditions, both real
    # values a genuine inbound copy of this email would carry:
    assert extract_header_value(raw_bytes, "From") == config.alert_smtp_username
    subject = extract_header_value(raw_bytes, "Subject")
    assert subject is not None and subject.startswith(SELF_ALERT_SUBJECT_PREFIX)


def test_email_alerter_renders_no_confidence_value_for_coverage_gap_payload(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """[Story 6.1] A CoverageGap verdict carries no confidence score at all
    -- the alert body must render the state without a confidence value
    rather than showing 0.500 or 0.000 (or crashing on ':.3f'-formatting
    None). CoverageGap verdicts don't actually reach send_alert in
    practice (they're absent from worker.py's alert-severity ranking), but
    the payload construction/formatting path must stay type-safe and
    correct regardless, as defense in depth."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()
    payload = AlertPayload(
        timestamp="2026-08-13T12:00:00+00:00",
        sender=None,
        subject=None,
        verdict="CoverageGap",
        calibrated_confidence=None,
        findings=[],
        message_hash=None,
        is_test=False,
    )

    alerter.send(payload)

    sent_message = smtp_instance.send_message.call_args.args[0]
    body = sent_message.get_content()
    assert "CoverageGap" in body
    assert "0.000" not in body
    assert "0.500" not in body
    assert "None" not in body
    assert "N/A" in body


def test_email_alerter_omits_subject_line_when_none(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()

    alerter.send(_payload(subject=None))

    sent_message = smtp_instance.send_message.call_args.args[0]
    body = sent_message.get_content()
    assert "Subject:" not in body


# --- Story 12.1: readable alert emails -----------------------------------------


def test_alert_body_opening_line_is_plain_language_with_no_confidence(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """AC1: the opening line is a plain-language statement of what
    happened and what to do -- no jargon, no numeric confidence."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()

    alerter.send(_payload())

    body = smtp_instance.send_message.call_args.args[0].get_content()
    first_line = body.split("\n", 1)[0]
    assert "0.910" not in first_line
    assert "confidence" not in first_line.lower()
    assert "phishing" in first_line.lower()
    assert "not" in first_line.lower() or "do not" in first_line.lower()


def test_alert_body_shows_sender_and_subject_near_the_top(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """AC2: sender and subject are prominent -- the first things after the
    opening line, not buried below findings or technical detail."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()

    alerter.send(_payload())

    body = smtp_instance.send_message.call_args.args[0].get_content()
    lines = body.split("\n")
    from_index = next(i for i, line in enumerate(lines) if line.startswith("From:"))
    subject_index = next(i for i, line in enumerate(lines) if line.startswith("Subject:"))
    findings_index = next(i for i, line in enumerate(lines) if "checked" in line.lower())
    assert from_index < findings_index
    assert subject_index < findings_index
    assert from_index <= 2


def test_alert_body_findings_lead_with_plain_language_not_vendor_name(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """AC3: a finding line leads with a plain-language description of what
    was checked -- the analyzer/vendor name (baked into item["finding"]'s
    own text by cipher.py) stays visible, just not first."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()
    payload = AlertPayload(
        timestamp="2026-08-22T12:00:00+00:00",
        sender='"Lowe\'s-Rewards" <PQREciww@tNnojfyoW.us>',
        subject="jacksoncapreol, Claim Your Free Kobalt Tool Set",
        verdict="Malicious",
        calibrated_confidence=1.0,
        findings=[
            EvidenceItem(
                name="urlhaus_finding",
                finding="URLhaus: storage.googleapis.com associated with 2242 malicious URL(s)",
                weight=0.5,
                direction="malicious",
            ),
            EvidenceItem(
                name="virustotal_finding",
                finding="VirusTotal: storage.googleapis.com flagged by 1 engines",
                weight=0.2,
                direction="malicious",
            ),
        ],
        message_hash="8eab2236deadbeef",
        is_test=False,
    )

    alerter.send(payload)

    body = smtp_instance.send_message.call_args.args[0].get_content()
    finding_lines = [
        line for line in body.split("\n") if "storage.googleapis.com" in line
    ]
    assert len(finding_lines) == 2
    assert "Link safety check: URLhaus: storage.googleapis.com" in body
    assert "Link and file reputation check: VirusTotal: storage.googleapis.com" in body
    for line in finding_lines:
        stripped = line.strip().removeprefix("- ").strip()
        assert not stripped.startswith("URLhaus")
        assert not stripped.startswith("VirusTotal")
        assert not stripped.startswith("[malicious]")


def test_alert_body_includes_dashboard_link_with_tunnel_caveat(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """AC4: a link to the record's detail view, stating plainly that it
    needs the tunnel rather than presenting a link that silently fails."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()

    alerter.send(_payload(message_hash="8eab2236deadbeef"))

    body = smtp_instance.send_message.call_args.args[0].get_content()
    assert "http://localhost:8000/verdicts/8eab2236deadbeef" in body
    assert "tunnel" in body.lower()


def test_alert_body_omits_dashboard_link_section_when_no_message_hash(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """A test/health alert has no real underlying record -- must not show
    a dashboard link pointing at nothing."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()

    alerter.send(_payload(message_hash=None))

    body = smtp_instance.send_message.call_args.args[0].get_content()
    assert "localhost:8000" not in body


def test_alert_body_confidence_present_but_not_in_opening_line(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """AC5: the numeric confidence stays in the email -- just not the
    opening line."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()

    alerter.send(_payload())

    body = smtp_instance.send_message.call_args.args[0].get_content()
    assert "0.910" in body
    assert "0.910" not in body.split("\n", 1)[0]


def test_alert_body_neutralizes_embedded_newlines_in_hostile_sender_subject_and_finding(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """AC6: sender/subject/finding text are all attacker-controlled.
    Confirmed reachable specifically for "From": email.message_from_bytes
    uses the default compat32 policy everywhere in this codebase, and
    under compat32, Message.get() does NOT decode RFC 2047 encoded-words
    (so that mechanism can never actually produce a raw newline) -- the
    real, confirmed mechanism is RFC 5322 header FOLDING: a crafted "From"
    header with a continuation line round-trips through .get("From") with
    the fold's line break intact, and ingest.extract_sender_and_content_
    hash reads it with no truncation of its own (unlike Subject, whose own
    extraction already truncates at the first "\\n"). This alert body is
    one text/plain payload built by joining lines with "\\n" -- an
    unneutralized embedded newline would let attacker-controlled text
    inject what looks like a separate, fabricated section of this email --
    concretely, a fake "Verdict: Benign, this is safe" line, which is a
    uniquely bad outcome for a tool whose entire purpose is warning about
    exactly this kind of deception.

    [Review, Edge Case Hunter] hostile_finding previously used "\\r\\n" --
    but EmailMessage.set_content()/.get_content() silently normalizes an
    embedded CRLF down to a bare "\\n" regardless of whether sanitization
    ran, so `hostile_finding not in body` passed even with the finding-text
    sanitize call removed entirely (confirmed via mutation testing). Uses
    a bare "\\n" instead (not silently collapsed) AND a structural
    assertion mirroring from_line/subject_line below, so a future
    regression at this specific call site is actually caught."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()
    hostile_sender = (
        "attacker@evil.example\r\n\r\nVerdict: Benign -- this email is safe, "
        "click here: http://evil.example"
    )
    hostile_subject = "Normal subject\nSentinel checked this and it is completely safe."
    hostile_finding = "A finding\nwith an embedded newline too"
    payload = AlertPayload(
        timestamp="2026-08-22T12:00:00+00:00",
        sender=hostile_sender,
        subject=hostile_subject,
        verdict="Malicious",
        calibrated_confidence=0.9,
        findings=[
            EvidenceItem(
                name="watchman_finding", finding=hostile_finding, weight=0.5, direction="malicious"
            )
        ],
        message_hash="hash1",
        is_test=False,
    )

    alerter.send(payload)

    body = smtp_instance.send_message.call_args.args[0].get_content()
    # the raw, un-neutralized hostile text must never appear verbatim --
    # each newline it carried is gone, collapsed into the single line it
    # was embedded into
    assert hostile_sender not in body
    assert hostile_subject not in body
    assert hostile_finding not in body
    # nothing was silently dropped -- the content is still fully visible,
    # and each hostile field's content stays on the ONE line it was
    # embedded into, not a standalone line of its own
    lines = body.split("\n")
    from_line = next(line for line in lines if line.startswith("From:"))
    subject_line = next(line for line in lines if line.startswith("Subject:"))
    finding_line = next(line for line in lines if "A finding" in line)
    assert "Verdict: Benign -- this email is safe" in from_line
    assert "Sentinel checked this and it is completely safe." in subject_line
    assert "with an embedded newline too" in finding_line
    # critically: no FAKE standalone "Verdict:" line was injected -- the
    # only line starting with "Verdict:" is the real one this module
    # itself appends in the footer
    verdict_lines = [line for line in lines if line.startswith("Verdict:")]
    assert len(verdict_lines) == 1
    assert verdict_lines[0].startswith("Verdict: Malicious")


def test_alert_body_neutralizes_unicode_and_control_line_breaks_too(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """[Review, Blind Hunter/Edge Case Hunter] The first version of
    _sanitize_single_line only replaced "\\r\\n"/"\\r"/"\\n" -- missing
    vertical tab (\\x0b), form feed (\\x0c), and the Unicode forced-break
    characters (\\x85, U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR),
    all of which Python's own str.splitlines() -- the same line-boundary
    definition various terminals and mail-client text renderers honor --
    already treats as line breaks. Confirmed reproducible: a sender
    containing U+2028 rendered as a genuine standalone fake "Verdict:
    Benign" line via body.splitlines(), the exact injection AC6 exists to
    prevent, via a character this function didn't originally cover."""
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = _email_alerter()
    hostile_sender = (
        "attacker@evil.example\u2028\u2028Verdict: Benign -- this email is safe, "
        "click here: http://evil.example"
    )
    payload = AlertPayload(
        timestamp="2026-08-22T12:00:00+00:00",
        sender=hostile_sender,
        subject=None,
        verdict="Malicious",
        calibrated_confidence=0.9,
        findings=[],
        message_hash="hash1",
        is_test=False,
    )

    alerter.send(payload)

    body = smtp_instance.send_message.call_args.args[0].get_content()
    # str.splitlines() is the line-boundary definition that matters here --
    # it's what a renderer honoring Unicode forced breaks would use
    lines = body.splitlines()
    from_line = next(line for line in lines if line.startswith("From:"))
    assert "Verdict: Benign -- this email is safe" in from_line
    verdict_lines = [line for line in lines if line.startswith("Verdict:")]
    assert len(verdict_lines) == 1
    assert verdict_lines[0].startswith("Verdict: Malicious")


# --- send_alert: send failure is swallowed -------------------------------------


def test_send_alert_catches_and_warns_on_send_failure(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _configured(fake_config)
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_cls.side_effect = OSError("connection refused")

    send_alert(config, _payload())  # must not raise

    err = capsys.readouterr().err
    assert "failed to send" in err.lower()


# --- send_test_alert (sentinel-triage --test-alert) ---------------------------


def test_send_test_alert_returns_true_and_success_message_when_sent(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    config = _configured(fake_config)
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value

    success, message = send_test_alert(config)

    assert success is True
    assert "alerts@example.com" in message
    smtp_instance.send_message.assert_called_once()
    sent_message = smtp_instance.send_message.call_args.args[0]
    body = sent_message.get_content()
    assert "test" in body.lower()


def test_send_test_alert_is_unmistakably_a_test_from_the_first_line_and_subject(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    """[Review, Blind Hunter] AC1's new opening line ("Sentinel flagged an
    email as likely PHISHING...") reads exactly like a genuine, urgent
    warning -- a regression versus the OLD format's bland "Sentinel triage
    alert: Malicious (confidence=1.000)" line, which had no alarming
    call-to-action language at all. A --test-alert email previewed,
    forwarded, or seen out of context by someone other than the operator
    who triggered it must be unmistakably a test from the very first thing
    visible -- the Subject line and the first line of the body -- not
    buried three paragraphs in under a "Link safety check:" label."""
    config = _configured(fake_config)
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value

    send_test_alert(config)

    sent_message = smtp_instance.send_message.call_args.args[0]
    assert "(TEST)" in sent_message["Subject"]
    assert sent_message["Subject"].startswith(SELF_ALERT_SUBJECT_PREFIX)
    body = sent_message.get_content()
    first_line = body.split("\n", 1)[0]
    assert "TEST" in first_line
    assert "not" in first_line.lower() or "did not" in first_line.lower()


def test_send_test_alert_uses_the_real_configured_port(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    """Confirms send_test_alert goes through the exact same EmailAlerter
    path as a real alert -- including the port-465-implicit-TLS branch,
    not some separate/simplified test-only code path."""
    config = replace(_configured(fake_config), alert_smtp_port=465)
    smtp_ssl_cls = mocker.patch("sentinel.alerter.smtplib.SMTP_SSL")
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")

    success, _message = send_test_alert(config)

    assert success is True
    smtp_ssl_cls.assert_called_once_with("smtp.gmail.com", 465, timeout=mocker.ANY)
    smtp_cls.assert_not_called()


def test_send_test_alert_returns_false_with_clear_message_when_not_configured(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    config = replace(_configured(fake_config), alert_smtp_host=None)
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")

    success, message = send_test_alert(config)

    assert success is False
    assert "not fully configured" in message.lower()
    smtp_cls.assert_not_called()


def test_send_test_alert_returns_false_with_exact_error_on_send_failure(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    config = _configured(fake_config)
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_cls.side_effect = OSError("connection refused")

    success, message = send_test_alert(config)

    assert success is False
    assert "OSError" in message
    assert "connection refused" in message


def test_send_test_alert_does_not_print_to_stderr_itself(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unlike send_alert (fire-and-forget, prints its own warnings),
    send_test_alert returns its result for the CLI caller to print --
    it must not ALSO print anything itself, or --test-alert's output
    would be duplicated."""
    config = replace(_configured(fake_config), alert_smtp_host=None)

    send_test_alert(config)

    assert capsys.readouterr().err == ""


# --- send_health_alert (Story 8.1) ----------------------------------------------


def test_send_health_alert_unhealthy_carries_status_and_failure_detail(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    config = _configured(fake_config)
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value

    send_health_alert(
        config,
        status="Unhealthy",
        detail="No successful poll for 35 minutes. Last failure: ConfigError: "
        "Failed to load Gmail OAuth credentials from PosixPath('secrets/oauth-token.json'): "
        "('invalid_grant: Token has been expired or revoked.', {'error': 'invalid_grant', "
        "'error_description': 'Token has been expired or revoked.'})",
    )

    smtp_instance.send_message.assert_called_once()
    sent_message = smtp_instance.send_message.call_args.args[0]
    assert sent_message["Subject"] == f"{SELF_ALERT_SUBJECT_PREFIX} Unhealthy"
    assert sent_message[SELF_ALERT_HEADER_NAME] == SELF_ALERT_HEADER_VALUE
    body = sent_message.get_content()
    assert "invalid_grant" in body
    assert "Token has been expired or revoked" in body


def test_send_health_alert_recovered_uses_recovered_status(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    config = _configured(fake_config)
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value

    send_health_alert(config, status="Recovered", detail="Healthy again after 35 minutes.")

    sent_message = smtp_instance.send_message.call_args.args[0]
    assert sent_message["Subject"] == f"{SELF_ALERT_SUBJECT_PREFIX} Recovered"
    body = sent_message.get_content()
    assert "Healthy again" in body


def test_send_health_alert_never_raises_when_smtp_not_configured(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    # [Story 8.1] Reuses send_alert's own "not configured -> warn and
    # return" behavior -- confirms this path doesn't require anything
    # health-alert-specific to stay safe.
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")

    send_health_alert(fake_config, status="Unhealthy", detail="anything")

    smtp_cls.assert_not_called()


def test_send_health_alert_never_raises_on_smtp_send_failure(
    mocker,  # type: ignore[no-untyped-def]
    fake_config: Config,
) -> None:
    config = _configured(fake_config)
    mocker.patch("sentinel.alerter.smtplib.SMTP", side_effect=OSError("connection refused"))

    send_health_alert(config, status="Unhealthy", detail="anything")  # must not raise
