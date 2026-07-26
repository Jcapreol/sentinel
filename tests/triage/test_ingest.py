import ast
import base64
import hashlib
import subprocess
from pathlib import Path

import pytest
from googleapiclient.errors import HttpError

from sentinel.config import Config, ConfigError
from sentinel.triage.ingest import (
    FetchFailed,
    build_gmail_service,
    extract_auth_results_header_from_eml,
    extract_email_content,
    extract_sender_and_content_hash,
    fetch_headers_for_messages,
    fetch_raw_message_bytes,
    get_authentication_results_header,
    poll_new_messages,
)


def _gmail_config(
    credentials_path: str | None = "secrets/gmail-service-account.json",
    mailbox: str | None = "soc@example.com",
) -> Config:
    return Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        gmail_credentials_path=credentials_path,
        gmail_monitored_mailbox=mailbox,
    )


# --- build_gmail_service -----------------------------------------------------


def test_build_gmail_service_fails_fast_on_missing_credentials_path() -> None:
    config = _gmail_config(credentials_path=None)
    with pytest.raises(ConfigError, match="GMAIL_SERVICE_ACCOUNT_KEY_PATH"):
        build_gmail_service(config)


def test_build_gmail_service_fails_fast_on_missing_mailbox() -> None:
    config = _gmail_config(mailbox=None)
    with pytest.raises(ConfigError, match="GMAIL_MONITORED_MAILBOX"):
        build_gmail_service(config)


def test_build_gmail_service_uses_readonly_scope_and_single_mailbox_subject(mocker) -> None:  # type: ignore[no-untyped-def]
    mock_creds = mocker.MagicMock()
    mock_from_file = mocker.patch(
        "sentinel.triage.ingest.service_account.Credentials.from_service_account_file",
        return_value=mock_creds,
    )
    mocker.patch("sentinel.triage.ingest.build")
    config = _gmail_config(credentials_path="secrets/key.json", mailbox="soc@example.com")

    build_gmail_service(config)

    mock_from_file.assert_called_once_with(
        "secrets/key.json",
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )
    mock_creds.with_subject.assert_called_once_with("soc@example.com")


def test_build_gmail_service_wraps_credential_load_failure_as_config_error(mocker) -> None:  # type: ignore[no-untyped-def]
    mocker.patch(
        "sentinel.triage.ingest.service_account.Credentials.from_service_account_file",
        side_effect=OSError("no such file or directory"),
    )
    config = _gmail_config(credentials_path="secrets/missing.json")

    with pytest.raises(ConfigError, match="secrets/missing.json"):
        build_gmail_service(config)


# --- poll_new_messages --------------------------------------------------------


def test_poll_first_call_establishes_baseline_without_returning_messages(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }

    messages, history_id = poll_new_messages(service, "soc@example.com", since_history_id=None)

    assert messages == []
    assert history_id == "1000"


def test_poll_subsequent_call_returns_new_messages_since_last_history_id(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1050"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [
            {"messagesAdded": [{"message": {"id": "m1", "threadId": "t1"}}]},
            {"messagesAdded": [{"message": {"id": "m2", "threadId": "t2"}}]},
        ],
    }

    messages, history_id = poll_new_messages(service, "soc@example.com", since_history_id="1000")

    assert len(messages) == 2
    assert {m["id"] for m in messages} == {"m1", "m2"}
    assert history_id == "1050"


def test_poll_follows_pagination_until_exhausted(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "2000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.side_effect = [
        {
            "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}],
            "nextPageToken": "page2",
        },
        {
            "history": [{"messagesAdded": [{"message": {"id": "m2"}}]}],
        },
    ]

    messages, history_id = poll_new_messages(service, "soc@example.com", since_history_id="1000")

    assert len(messages) == 2
    assert {m["id"] for m in messages} == {"m1", "m2"}
    assert history_id == "2000"


def test_poll_reraises_non_retryable_non_404_http_errors(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    resp = mocker.MagicMock(status=400)
    service.users.return_value.history.return_value.list.return_value.execute.side_effect = (
        HttpError(resp, b"bad request")
    )

    with pytest.raises(HttpError):
        poll_new_messages(service, "soc@example.com", since_history_id="999")


def test_poll_does_not_retry_on_401(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    resp = mocker.MagicMock(status=401)
    service.users.return_value.history.return_value.list.return_value.execute.side_effect = (
        HttpError(resp, b"unauthorized")
    )
    sleep = mocker.patch("sentinel.triage.ingest.time.sleep")

    with pytest.raises(HttpError):
        poll_new_messages(service, "soc@example.com", since_history_id="999")

    sleep.assert_not_called()


def test_poll_does_not_retry_on_403(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    resp = mocker.MagicMock(status=403)
    service.users.return_value.history.return_value.list.return_value.execute.side_effect = (
        HttpError(resp, b"forbidden")
    )
    sleep = mocker.patch("sentinel.triage.ingest.time.sleep")

    with pytest.raises(HttpError):
        poll_new_messages(service, "soc@example.com", since_history_id="999")

    sleep.assert_not_called()


def test_poll_retries_on_429_then_succeeds(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    resp = mocker.MagicMock(status=429)
    service.users.return_value.history.return_value.list.return_value.execute.side_effect = [
        HttpError(resp, b"rate limited"),
        {"history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]},
    ]
    sleep = mocker.patch("sentinel.triage.ingest.time.sleep")

    messages, history_id = poll_new_messages(service, "soc@example.com", since_history_id="999")

    assert [m["id"] for m in messages] == ["m1"]
    assert history_id == "1000"
    sleep.assert_called_once()


def test_poll_retries_on_5xx_then_succeeds(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    resp = mocker.MagicMock(status=503)
    service.users.return_value.history.return_value.list.return_value.execute.side_effect = [
        HttpError(resp, b"service unavailable"),
        HttpError(resp, b"service unavailable"),
        {"history": [{"messagesAdded": [{"message": {"id": "m1"}}]}]},
    ]
    sleep = mocker.patch("sentinel.triage.ingest.time.sleep")

    messages, history_id = poll_new_messages(service, "soc@example.com", since_history_id="999")

    assert [m["id"] for m in messages] == ["m1"]
    assert sleep.call_count == 2


def test_poll_exhausts_retries_and_raises(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "1000"
    }
    resp = mocker.MagicMock(status=500)
    service.users.return_value.history.return_value.list.return_value.execute.side_effect = (
        HttpError(resp, b"server error")
    )
    mocker.patch("sentinel.triage.ingest.time.sleep")

    with pytest.raises(HttpError):
        poll_new_messages(service, "soc@example.com", since_history_id="999")


def test_poll_getprofile_retries_on_429_then_succeeds(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    resp = mocker.MagicMock(status=429)
    service.users.return_value.getProfile.return_value.execute.side_effect = [
        HttpError(resp, b"rate limited"),
        {"historyId": "5000"},
    ]
    sleep = mocker.patch("sentinel.triage.ingest.time.sleep")

    messages, history_id = poll_new_messages(service, "soc@example.com", since_history_id=None)

    assert messages == []
    assert history_id == "5000"
    sleep.assert_called_once()


def test_poll_recovers_from_expired_history_id_without_raising(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "3000"
    }
    resp = mocker.MagicMock(status=404)
    service.users.return_value.history.return_value.list.return_value.execute.side_effect = (
        HttpError(resp, b"not found")
    )

    messages, history_id = poll_new_messages(service, "soc@example.com", since_history_id="1")

    assert messages == []
    assert history_id == "3000"


def test_poll_getprofile_http_error_reraises_with_diagnostic(mocker, capsys) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    resp = mocker.MagicMock(status=403)
    service.users.return_value.getProfile.return_value.execute.side_effect = HttpError(
        resp, b"forbidden"
    )

    with pytest.raises(HttpError):
        poll_new_messages(service, "soc@example.com", since_history_id=None)

    captured = capsys.readouterr()
    assert "getProfile failed" in captured.err


def test_poll_deduplicates_message_ids_across_history_records(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.getProfile.return_value.execute.return_value = {
        "historyId": "4000"
    }
    service.users.return_value.history.return_value.list.return_value.execute.return_value = {
        "history": [
            {"messagesAdded": [{"message": {"id": "m1"}}]},
            {"messagesAdded": [{"message": {"id": "m1"}}]},
            {"messagesAdded": [{"message": {"id": "m2"}}]},
        ],
    }

    messages, history_id = poll_new_messages(service, "soc@example.com", since_history_id="1000")

    assert [m["id"] for m in messages] == ["m1", "m2"]
    assert history_id == "4000"


# --- get_authentication_results_header ---------------------------------------


def test_get_header_returns_value_when_present(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
        "payload": {
            "headers": [
                {"name": "Authentication-Results", "value": "mx.google.com; spf=pass"}
            ]
        }
    }

    result = get_authentication_results_header(service, "soc@example.com", "m1")

    assert result == "mx.google.com; spf=pass"


def test_get_header_returns_none_when_absent(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
        "payload": {"headers": []}
    }

    result = get_authentication_results_header(service, "soc@example.com", "m1")

    assert result is None


def test_get_header_returns_none_not_string_when_value_key_missing(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
        "payload": {"headers": [{"name": "Authentication-Results"}]}
    }

    result = get_authentication_results_header(service, "soc@example.com", "m1")

    assert result is None
    assert result != "None"


def test_get_header_isolated_across_messages(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        {
            "payload": {
                "headers": [{"name": "Authentication-Results", "value": "mx.google.com; spf=pass"}]
            }
        },
        {
            "payload": {
                "headers": [{"name": "Authentication-Results", "value": "mx.google.com; spf=fail"}]
            }
        },
    ]

    result1 = get_authentication_results_header(service, "soc@example.com", "m1")
    result2 = get_authentication_results_header(service, "soc@example.com", "m2")

    assert result1 == "mx.google.com; spf=pass"
    assert result2 == "mx.google.com; spf=fail"


def test_get_header_returns_first_when_multiple_trusted_headers_present(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
        "payload": {
            "headers": [
                {
                    "name": "Authentication-Results",
                    "value": "mx.google.com; spf=pass (most recent trusted hop)",
                },
                {
                    "name": "Authentication-Results",
                    "value": "mx.google.com; spf=fail (earlier trusted hop)",
                },
            ]
        }
    }

    result = get_authentication_results_header(service, "soc@example.com", "m1")

    assert result == "mx.google.com; spf=pass (most recent trusted hop)"


def test_get_header_ignores_untrusted_authserv_id_even_when_listed_first(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
        "payload": {
            "headers": [
                {
                    "name": "Authentication-Results",
                    "value": "attacker.example.com; spf=pass (crafted, sorts first)",
                },
                {
                    "name": "Authentication-Results",
                    "value": "mx.google.com; spf=fail (the real verdict)",
                },
            ]
        }
    }

    result = get_authentication_results_header(service, "soc@example.com", "m1")

    assert result == "mx.google.com; spf=fail (the real verdict)"


def test_get_header_returns_none_when_only_untrusted_authserv_id_present(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
        "payload": {
            "headers": [
                {"name": "Authentication-Results", "value": "attacker.example.com; spf=pass"},
            ]
        }
    }

    result = get_authentication_results_header(service, "soc@example.com", "m1")

    assert result is None


def test_get_header_retries_on_429_then_succeeds(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    resp = mocker.MagicMock(status=429)
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        HttpError(resp, b"rate limited"),
        {
            "payload": {
                "headers": [{"name": "Authentication-Results", "value": "mx.google.com; spf=pass"}]
            }
        },
    ]
    sleep = mocker.patch("sentinel.triage.ingest.time.sleep")

    result = get_authentication_results_header(service, "soc@example.com", "m1")

    assert result == "mx.google.com; spf=pass"
    sleep.assert_called_once()


# --- fetch_headers_for_messages (AC7) -----------------------------------------


def test_fetch_headers_for_messages_isolates_per_message_failure(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    mocker.patch(
        "sentinel.triage.ingest.get_authentication_results_header",
        side_effect=[RuntimeError("boom"), "spf=pass"],
    )

    results = fetch_headers_for_messages(
        service, "soc@example.com", [{"id": "m1"}, {"id": "m2"}]
    )

    # A fetch failure must be structurally distinct from a genuinely missing
    # header (None) — headers.py treats None as real evidence of "no header
    # present." Conflating the two would score a transient fetch error as a
    # confident verdict from data that was never actually collected.
    assert isinstance(results["m1"], FetchFailed)
    assert results["m1"] is not None
    assert results["m2"] == "spf=pass"


def test_fetch_headers_for_messages_retry_exhaustion_yields_fetchfailed_not_crash_or_none(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    # Sustained rate limiting on messages.get() must fail safe to FetchFailed —
    # never crash fetch_headers_for_messages, and never silently collapse to
    # None (which headers.py would treat as a genuine "no header" result).
    service = mocker.MagicMock()
    resp = mocker.MagicMock(status=429)
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = (
        HttpError(resp, b"rate limited")
    )
    sleep = mocker.patch("sentinel.triage.ingest.time.sleep")

    results = fetch_headers_for_messages(service, "soc@example.com", [{"id": "m1"}])

    assert isinstance(results["m1"], FetchFailed)
    assert results["m1"] is not None
    # Proves retries actually happened before giving up, not just that any
    # exception is caught — sleep is called once per retry attempt.
    assert sleep.call_count == 3


def test_fetch_headers_for_messages_all_succeed(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    mocker.patch(
        "sentinel.triage.ingest.get_authentication_results_header",
        side_effect=["spf=pass", "spf=fail"],
    )

    results = fetch_headers_for_messages(
        service, "soc@example.com", [{"id": "m1"}, {"id": "m2"}]
    )

    assert results == {"m1": "spf=pass", "m2": "spf=fail"}


def test_fetch_headers_for_messages_skips_message_missing_id(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    mock_get_header = mocker.patch(
        "sentinel.triage.ingest.get_authentication_results_header",
        return_value="spf=pass",
    )

    results = fetch_headers_for_messages(
        service, "soc@example.com", [{"threadId": "t1"}, {"id": "m2"}]
    )

    assert results == {"m2": "spf=pass"}
    mock_get_header.assert_called_once_with(service, "soc@example.com", "m2")


# --- fetch_raw_message_bytes / extract_sender_and_content_hash ----------------


def test_fetch_raw_message_bytes_decodes_base64url(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    raw_content = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
        "raw": encoded
    }

    result = fetch_raw_message_bytes(service, "soc@example.com", "m1")

    assert result == raw_content


def test_fetch_raw_message_bytes_handles_unpadded_base64url(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    raw_content = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode().rstrip("=")
    service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
        "raw": encoded
    }

    result = fetch_raw_message_bytes(service, "soc@example.com", "m1")

    assert result == raw_content


def test_fetch_raw_message_bytes_retries_on_429_then_succeeds(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    raw_content = b"From: alice@example.com\r\n\r\nbody"
    encoded = base64.urlsafe_b64encode(raw_content).decode()
    resp = mocker.MagicMock(status=429)
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = [
        HttpError(resp, b"rate limited"),
        {"raw": encoded},
    ]
    sleep = mocker.patch("sentinel.triage.ingest.time.sleep")

    result = fetch_raw_message_bytes(service, "soc@example.com", "m1")

    assert result == raw_content
    sleep.assert_called_once()


def test_fetch_raw_message_bytes_does_not_retry_on_403(mocker) -> None:  # type: ignore[no-untyped-def]
    service = mocker.MagicMock()
    resp = mocker.MagicMock(status=403)
    service.users.return_value.messages.return_value.get.return_value.execute.side_effect = (
        HttpError(resp, b"forbidden")
    )
    sleep = mocker.patch("sentinel.triage.ingest.time.sleep")

    with pytest.raises(HttpError):
        fetch_raw_message_bytes(service, "soc@example.com", "m1")

    sleep.assert_not_called()


def test_extract_sender_and_content_hash_returns_sender_and_hash() -> None:
    raw_bytes = b"From: alice@example.com\r\nSubject: test\r\n\r\nbody"

    sender, content_hash = extract_sender_and_content_hash(raw_bytes)

    assert sender == "alice@example.com"
    assert content_hash == hashlib.sha256(raw_bytes).hexdigest()


def test_extract_sender_and_content_hash_no_from_header_still_hashes() -> None:
    raw_bytes = b"Subject: test\r\n\r\nbody"

    sender, content_hash = extract_sender_and_content_hash(raw_bytes)

    assert sender is None
    assert content_hash == hashlib.sha256(raw_bytes).hexdigest()


# --- extract_email_content -----------------------------------------------------


def test_extract_email_content_plain_text_single_part() -> None:
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: Urgent invoice overdue\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please pay immediately via http://evil.example.com/pay"
    )

    content = extract_email_content(raw_bytes)

    assert "Subject: Urgent invoice overdue" in content
    assert "Please pay immediately via http://evil.example.com/pay" in content


def test_extract_email_content_prefers_text_plain_part_in_multipart() -> None:
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b'Content-Type: multipart/alternative; boundary="BOUNDARY"\r\n\r\n'
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"plain body text\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><body>html body text</body></html>\r\n"
        b"--BOUNDARY--\r\n"
    )

    content = extract_email_content(raw_bytes)

    assert "plain body text" in content
    assert "<html>" not in content


def test_extract_email_content_falls_back_to_html_when_no_text_plain_part() -> None:
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><body>click <a href='http://evil.example.com'>here</a></body></html>"
    )

    content = extract_email_content(raw_bytes)

    assert "click" in content
    assert "here" in content
    assert "<html>" not in content
    assert "<a href" not in content


def test_extract_email_content_no_text_part_returns_best_effort_empty_body() -> None:
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n\r\n'
        b"--BOUNDARY\r\n"
        b"Content-Type: application/pdf\r\n\r\n"
        b"%PDF-1.4 binary garbage\r\n"
        b"--BOUNDARY--\r\n"
    )

    content = extract_email_content(raw_bytes)

    assert "Subject: test" in content


def test_extract_email_content_includes_subject_header() -> None:
    raw_bytes = b"Subject: Account verification needed\r\n\r\nbody text"

    content = extract_email_content(raw_bytes)

    assert "Account verification needed" in content


def test_extract_email_content_missing_subject_does_not_raise() -> None:
    raw_bytes = b"From: alice@example.com\r\n\r\nbody text"

    content = extract_email_content(raw_bytes)

    assert "body text" in content


def test_extract_email_content_never_raises_on_garbage_bytes() -> None:
    raw_bytes = b"\xff\xfe\x00\x01 not a valid email at all"

    content = extract_email_content(raw_bytes)

    assert isinstance(content, str)


def test_extract_email_content_preserves_href_url_when_stripping_html_tags() -> None:
    """2026-07-23 code-review patch: a blanket tag-removal regex previously
    deleted <a href="..."> entirely, losing the malicious URL for an
    HTML-only phishing email using generic anchor text ("click here") --
    defeating CipherAgent's IOC extraction, the core purpose of Story 2.2."""
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b'<html><body>click <a href="http://evil.example.com/pay">here</a></body></html>'
    )

    content = extract_email_content(raw_bytes)

    assert "http://evil.example.com/pay" in content


def test_extract_email_content_non_text_single_part_body_is_not_decoded_as_text() -> None:
    """2026-07-23 code-review patch: a non-multipart, non-text body (e.g.
    application/pdf) was previously force-decoded as UTF-8 plain text,
    feeding decoded binary noise into the LLM prompt."""
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: application/pdf\r\n\r\n"
        b"%PDF-1.4 \xff\xfe binary garbage not text"
    )

    content = extract_email_content(raw_bytes)

    assert "PDF" not in content
    assert "binary garbage" not in content


def test_extract_email_content_decodes_rfc2047_encoded_subject() -> None:
    """2026-07-23 code-review patch: RFC 2047 MIME-encoded-word Subject
    headers were previously returned verbatim (base64-looking gibberish),
    hiding urgency/homoglyph phishing language placed in the subject line."""
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: =?UTF-8?B?VXJnZW50IEFjdGlvbiBSZXF1aXJlZCE=?=\r\n\r\n"
        b"body text"
    )

    content = extract_email_content(raw_bytes)

    assert "Urgent Action Required!" in content
    assert "=?UTF-8?B?" not in content


def test_extract_email_content_body_failure_does_not_discard_subject(mocker) -> None:  # type: ignore[no-untyped-def]
    """2026-07-23 code-review patch: the function-wide try/except was
    all-or-nothing -- a failure extracting the body discarded an
    already-successfully-extracted Subject too, contradicting the
    docstring's 'best-effort' claim."""
    mocker.patch("sentinel.triage.ingest._extract_body", side_effect=RuntimeError("boom"))
    raw_bytes = b"Subject: Account verification needed\r\n\r\nbody text"

    content = extract_email_content(raw_bytes)

    assert "Account verification needed" in content


def test_extract_email_content_skips_attachment_parts() -> None:
    """2026-07-23 code-review patch: a text/plain attachment preceding the
    real message body in MIME structure was previously indistinguishable
    from the actual body and would be analyzed instead of it."""
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n\r\n'
        b"--BOUNDARY\r\n"
        b'Content-Type: text/plain\r\n'
        b'Content-Disposition: attachment; filename="notes.txt"\r\n\r\n'
        b"unrelated attachment content\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"the real message body\r\n"
        b"--BOUNDARY--\r\n"
    )

    content = extract_email_content(raw_bytes)

    assert "the real message body" in content
    assert "unrelated attachment content" not in content


# --- extract_auth_results_header_from_eml (Story 3.1) --------------------------


def test_extract_auth_results_header_from_eml_returns_trusted_header() -> None:
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Authentication-Results: mx.google.com; spf=pass\r\n\r\n"
        b"body"
    )

    result = extract_auth_results_header_from_eml(raw_bytes)

    assert result == "mx.google.com; spf=pass"


def test_extract_auth_results_header_from_eml_prefers_first_trusted_among_multiple() -> None:
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Authentication-Results: mx.google.com; spf=pass (most recent trusted hop)\r\n"
        b"Authentication-Results: mx.google.com; spf=fail (earlier trusted hop)\r\n\r\n"
        b"body"
    )

    result = extract_auth_results_header_from_eml(raw_bytes)

    assert result == "mx.google.com; spf=pass (most recent trusted hop)"


def test_extract_auth_results_header_from_eml_ignores_untrusted_authserv_id() -> None:
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Authentication-Results: attacker.example.com; spf=pass (crafted, sorts first)\r\n"
        b"Authentication-Results: mx.google.com; spf=fail (the real verdict)\r\n\r\n"
        b"body"
    )

    result = extract_auth_results_header_from_eml(raw_bytes)

    assert result == "mx.google.com; spf=fail (the real verdict)"


def test_extract_auth_results_header_from_eml_returns_none_when_absent() -> None:
    raw_bytes = b"From: alice@example.com\r\n\r\nbody"

    result = extract_auth_results_header_from_eml(raw_bytes)

    assert result is None


def test_extract_auth_results_header_from_eml_returns_none_when_only_untrusted() -> None:
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Authentication-Results: attacker.example.com; spf=pass\r\n\r\n"
        b"body"
    )

    result = extract_auth_results_header_from_eml(raw_bytes)

    assert result is None


def test_extract_auth_results_header_from_eml_never_raises_on_garbage_bytes() -> None:
    raw_bytes = b"\xff\xfe\x00\x01 not a valid email at all"

    result = extract_auth_results_header_from_eml(raw_bytes)

    assert result is None


# --- structural / boundary checks --------------------------------------------


def test_ingest_imports_no_network_listening_library() -> None:
    source_path = Path(__file__).resolve().parents[2] / "src" / "sentinel" / "triage" / "ingest.py"
    tree = ast.parse(source_path.read_text())
    forbidden = {"fastapi", "uvicorn", "http.server", "socketserver", "flask", "aiohttp.web"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden, f"ingest.py imports {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden, f"ingest.py imports from {node.module}"


def test_gmail_credential_default_location_is_gitignored() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        ["git", "check-ignore", "secrets/gmail-service-account.json"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "expected secrets/gmail-service-account.json to be gitignored — "
        f"git check-ignore exited {result.returncode}: {result.stderr}"
    )
