from dataclasses import replace

import pytest

from sentinel.alerter import AlertPayload, EmailAlerter, send_alert
from sentinel.config import Config


def _configured(fake_config: Config) -> Config:
    return replace(
        fake_config,
        alert_smtp_host="smtp.gmail.com",
        alert_smtp_port=587,
        alert_smtp_username="me@gmail.com",
        alert_smtp_password="app-password",
        alert_smtp_recipient="alerts@example.com",
    )


def _payload(subject: str | None = "Password reset required") -> AlertPayload:
    return AlertPayload(
        timestamp="2026-08-09T12:00:00+00:00",
        sender="phisher@evil.example",
        subject=subject,
        verdict="Malicious",
        calibrated_confidence=0.91,
        findings=[
            "[malicious] Suspicious login URL requesting credentials",
            "[malicious] Generic greeting inconsistent with a real corporate email",
        ],
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
    alerter = EmailAlerter(
        host="smtp.gmail.com",
        port=587,
        username="me@gmail.com",
        password="app-password",
        recipient="alerts@example.com",
    )

    alerter.send(_payload())

    sent_message = smtp_instance.send_message.call_args.args[0]
    body = sent_message.get_content()
    assert "Malicious" in body
    assert "0.910" in body
    assert "phisher@evil.example" in body
    assert "Password reset required" in body
    assert "[malicious] Suspicious login URL requesting credentials" in body


def test_email_alerter_omits_subject_line_when_none(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    smtp_cls = mocker.patch("sentinel.alerter.smtplib.SMTP")
    smtp_instance = smtp_cls.return_value.__enter__.return_value
    alerter = EmailAlerter(
        host="smtp.gmail.com",
        port=587,
        username="me@gmail.com",
        password="app-password",
        recipient="alerts@example.com",
    )

    alerter.send(_payload(subject=None))

    sent_message = smtp_instance.send_message.call_args.args[0]
    body = sent_message.get_content()
    assert "Subject:" not in body


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
