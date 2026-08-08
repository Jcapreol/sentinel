import ast
import base64
import hashlib
import re
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


def _oauth_config(
    client_secret_path: str | None,
    token_path: str | None = "secrets/oauth-token.json",
    mailbox: str | None = "me",
) -> Config:
    return Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        gmail_auth_mode="oauth",
        gmail_oauth_client_secret_path=client_secret_path,
        gmail_oauth_token_path=token_path,
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


def test_build_gmail_service_invalid_auth_mode_raises_config_error() -> None:
    config = _gmail_config()
    object.__setattr__(config, "gmail_auth_mode", "bogus")

    with pytest.raises(ConfigError, match="bogus"):
        build_gmail_service(config)


def test_build_gmail_service_service_account_mode_never_touches_oauth_path(mocker) -> None:  # type: ignore[no-untyped-def]
    mock_creds = mocker.MagicMock()
    mocker.patch(
        "sentinel.triage.ingest.service_account.Credentials.from_service_account_file",
        return_value=mock_creds,
    )
    mocker.patch("sentinel.triage.ingest.build")
    oauth_get_credentials = mocker.patch("sentinel.triage.ingest.get_credentials")
    config = _gmail_config(credentials_path="secrets/key.json", mailbox="soc@example.com")

    build_gmail_service(config)

    oauth_get_credentials.assert_not_called()


# --- build_gmail_service (oauth mode) ----------------------------------------


def test_build_gmail_service_oauth_mode_fails_fast_on_missing_client_secret_path_config() -> None:
    config = _oauth_config(client_secret_path=None)
    with pytest.raises(ConfigError, match="GMAIL_OAUTH_CLIENT_SECRET_PATH"):
        build_gmail_service(config)


def test_build_gmail_service_oauth_mode_fails_fast_on_missing_token_path_config() -> None:
    config = _oauth_config(client_secret_path="secrets/oauth-client.json", token_path=None)
    with pytest.raises(ConfigError, match="GMAIL_OAUTH_TOKEN_PATH"):
        build_gmail_service(config)


def test_build_gmail_service_oauth_mode_fails_fast_when_client_secret_file_missing(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "does-not-exist.json"
    config = _oauth_config(client_secret_path=str(missing))

    with pytest.raises(ConfigError, match=re.escape(str(missing))):
        build_gmail_service(config)


def test_build_gmail_service_oauth_mode_fails_fast_on_missing_mailbox_config(
    tmp_path: Path,
) -> None:
    client_secret = tmp_path / "oauth-client.json"
    client_secret.write_text("{}")
    config = _oauth_config(client_secret_path=str(client_secret), mailbox=None)

    with pytest.raises(ConfigError, match="GMAIL_MONITORED_MAILBOX"):
        build_gmail_service(config)


def test_build_gmail_service_oauth_mode_uses_shared_get_credentials(
    mocker, tmp_path: Path  # type: ignore[no-untyped-def]
) -> None:
    client_secret = tmp_path / "oauth-client.json"
    client_secret.write_text("{}")
    token_path = tmp_path / "oauth-token.json"

    mock_creds = mocker.MagicMock()
    get_credentials_mock = mocker.patch(
        "sentinel.triage.ingest.get_credentials", return_value=mock_creds
    )
    build_mock = mocker.patch("sentinel.triage.ingest.build")
    service = build_mock.return_value
    config = _oauth_config(client_secret_path=str(client_secret), token_path=str(token_path))

    result = build_gmail_service(config)

    get_credentials_mock.assert_called_once_with(client_secret, token_path)
    build_mock.assert_called_once_with("gmail", "v1", credentials=mock_creds, cache_discovery=False)
    assert result is service


def test_build_gmail_service_oauth_mode_wraps_credential_load_failure_as_config_error(
    mocker, tmp_path: Path  # type: ignore[no-untyped-def]
) -> None:
    client_secret = tmp_path / "oauth-client.json"
    client_secret.write_text("{}")
    token_path = tmp_path / "oauth-token.json"
    mocker.patch(
        "sentinel.triage.ingest.get_credentials", side_effect=OSError("disk error")
    )
    config = _oauth_config(client_secret_path=str(client_secret), token_path=str(token_path))

    with pytest.raises(ConfigError, match="disk error"):
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


def test_poll_getprofile_403_mentions_oauth_scope_and_delegation_guidance(
    mocker, capsys  # type: ignore[no-untyped-def]
) -> None:
    """[Review] This is the AC3 fail-loudly check for insufficient
    gmail.readonly scope: rather than a separate probe call in
    build_gmail_service (a redundant real API call every poll cycle, since
    poll_new_messages always immediately makes this same getProfile call
    right after build_gmail_service returns), a 403 here gets a message
    covering both auth modes -- oauth's cached-token-scope case and
    service_account's domain-wide-delegation case -- since this function
    doesn't know which auth mode produced `service`."""
    service = mocker.MagicMock()
    resp = mocker.MagicMock(status=403)
    service.users.return_value.getProfile.return_value.execute.side_effect = HttpError(
        resp, b"insufficient scope"
    )

    with pytest.raises(HttpError):
        poll_new_messages(service, "me", since_history_id=None)

    captured = capsys.readouterr()
    assert "GMAIL_AUTH_MODE=oauth" in captured.err
    assert "gmail.readonly" in captured.err
    assert "domain-wide delegation" in captured.err


def test_poll_getprofile_non_403_error_omits_oauth_guidance(
    mocker, capsys  # type: ignore[no-untyped-def]
) -> None:
    service = mocker.MagicMock()
    resp = mocker.MagicMock(status=500)
    service.users.return_value.getProfile.return_value.execute.side_effect = HttpError(
        resp, b"server error"
    )

    with pytest.raises(HttpError):
        poll_new_messages(service, "soc@example.com", since_history_id=None)

    captured = capsys.readouterr()
    assert "getProfile failed" in captured.err
    assert "GMAIL_AUTH_MODE=oauth" not in captured.err


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


def test_extract_email_content_strips_style_block_content_not_just_tags() -> None:
    """[Cipher domain-extraction fix, Phase 2] _strip_html previously removed
    only the <style>/</style> DELIMITERS via a blanket <[^>]+> tag regex,
    leaving the CSS rule text itself (selectors, property names) in the
    output as if it were real body text -- CipherAgent's _extract_domains
    then matched CSS selector chains like "table.icons" as if they were
    real domains. Real excerpt modeled on benign_corpus_raw/benign/held_out/
    own-inbox-49c0a18092beb365.eml (content_hash 49c0a180...), a real Chick-
    fil-A marketing email where this exact CSS rule appeared inside a real
    <style> block, ahead of the message's real sending domains."""
    raw_bytes = (
        b"From: news@e.chick-fil-a.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><head><style>"
        b".desktop_hide,.desktop_hide table{mso-hide:all;display:none}"
        b"@media (max-width:740px){.desktop_hide table.icons-outer{display:inline-table!important}"
        b".icons-inner{text-align:center}.icons-inner td{margin:0 auto}}"
        b"</style></head>"
        b'<body>See offers at <a href="http://email.chick-fil-a.com/offers">this link</a></body>'
        b"</html>"
    )

    content = extract_email_content(raw_bytes)

    assert "table.icons" not in content
    assert "icons-inner" not in content
    assert "mso-hide" not in content
    assert "http://email.chick-fil-a.com/offers" in content


def test_extract_email_content_strips_script_block_content_not_just_tags() -> None:
    """[Cipher domain-extraction fix, Phase 2] Mirrors the <style> case above
    for <script> blocks. Real excerpt modeled on benign_corpus_raw/malicious/
    held_out/sample-1073.eml, a real malicious file where a real <script>
    block (minified JS overriding history.pushState/replaceState) preceded
    the message's one real indicator -- an unsubscribe link to
    bsq2.firiri.shop -- causing _extract_domains to surface
    "history.pushState" as its first (and previously only-considered) match
    instead of the real malicious domain."""
    raw_bytes = (
        b"From: newsletter@example.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><head>"
        b'<script ecommerce-type="extend-native-history-api">(()=>{const e=history.pushState,'
        b"t=history.replaceState;history.pushState=function(){e.apply(history,arguments)},"
        b"history.replaceState=function(){t.apply(history,arguments)}})()</script>"
        b"</head>"
        b'<body>Um sich abzumelden, klicken Sie bitte auf '
        b'<a href="http://bsq2.firiri.shop/unsubscribe">Hier</a></body></html>'
    )

    content = extract_email_content(raw_bytes)

    assert "history.pushState" not in content
    assert "history.replaceState" not in content
    assert "http://bsq2.firiri.shop/unsubscribe" in content


def test_extract_email_content_preserves_href_written_dynamically_inside_script() -> None:
    """[Code review, 2026-08-05] The new style/script-block removal (added to
    fix the CSS/JS-leak bug above) previously ran BEFORE href extraction,
    so an href written dynamically via document.write() -- a real, if
    uncommon, pattern this project's own corpus contains (13/10,435 real
    files reference document.write) -- was destroyed along with the script
    block before _HREF_PATTERN ever saw it. hrefs must be captured from the
    ORIGINAL html, before any style/script stripping happens."""
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><script>document.write('<a href=\"http://evil.example.tk/steal\">Click</a>')"
        b"</script></html>"
    )

    content = extract_email_content(raw_bytes)

    assert "http://evil.example.tk/steal" in content


def test_extract_email_content_strips_style_script_block_even_with_mismatched_closing_tag() -> None:
    """[Code review, 2026-08-05] Real, malformed HTML in this project's own
    corpus (7/10,435 files) pairs a <style> open with a </script> close (or
    vice versa) -- a backreference-based regex (</\\1>) requires the exact
    same tag name to close, so a mismatched pair previously left the whole
    block, CSS junk included, completely unstripped."""
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><head><style>table.icons{display:none}</script></head>"
        b'<body>real text <a href="http://kay.com/offers">link</a></body></html>'
    )

    content = extract_email_content(raw_bytes)

    assert "table.icons" not in content
    assert "http://kay.com/offers" in content


def test_extract_email_content_bounds_cost_of_pathological_unclosed_script_tags() -> None:
    """[Code review, 2026-08-05] The lazy `.*?` DOTALL block-match regex is
    quadratic in the number of unclosed <script>/<style> opens (each
    unmatched open forces a fresh scan to the end of the document before
    failing) -- confirmed empirically: 800KB of repeated unclosed <script>
    tags took over a second, scaling roughly with the square of input size.
    A phishing-triage tool processes attacker-controlled HTML by design, so
    this must be bounded, not just fast on well-formed input. Not a strict
    timing assertion (flaky under load) -- proves the guard actually
    engages by checking the well-formed style/script logic is skipped
    (junk survives) once the size ceiling is exceeded, which is the
    intended, documented tradeoff."""
    import time

    from sentinel.triage.ingest import _MAX_HTML_LENGTH_FOR_BLOCK_STRIP

    huge_unclosed = "<script>" + ("x" * (_MAX_HTML_LENGTH_FOR_BLOCK_STRIP + 1))
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: text/html\r\n\r\n" + huge_unclosed.encode()
    )

    start = time.perf_counter()
    extract_email_content(raw_bytes)
    elapsed = time.perf_counter() - start

    assert elapsed < 2.0


def test_extract_email_content_self_closed_script_tag_does_not_swallow_unrelated_later_content() -> None:
    """[Code review, 2026-08-05, Edge Case Hunter] A self-closed
    <script src="..."/> (a real, common pattern for external analytics/
    tracking includes in ESP-generated marketing HTML -- has no content and
    no closing tag of its own) was being treated as an unclosed opener,
    causing the lazy block-match to extend all the way to the NEXT,
    UNRELATED <script>...</script> anywhere later in the message --
    silently deleting everything in between, including real body content
    and a real domain. This is strictly worse than the bug being fixed:
    extract_email_content's output feeds BOTH Watchman and Cipher
    (src/sentinel/triage/worker.py), so this could blank real evidence for
    both agents, not just Cipher's IOC pick."""
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b'<html><script src="https://cdn.example.com/analytics.js"/>'
        b"<p>Your invoice ... Pay at http://real-billing-portal.tld/invoice123 ...</p>"
        b'<script>console.log("unrelated tracker")</script></html>'
    )

    content = extract_email_content(raw_bytes)

    assert "http://real-billing-portal.tld/invoice123" in content


def test_extract_email_content_whitespace_only_text_plain_does_not_mask_real_html_body() -> None:
    """[Code review, 2026-08-05] _extract_body's `if text_plain: return
    text_plain` used bare truthiness -- a decorative plaintext fallback of
    pure CRLF/nbsp (non-empty, so truthy) won over a real HTML body with
    actual content. Real reproduction of benign_corpus_raw/malicious/
    tuning/sample-1492.eml (Subject: "VIRUS_DETECED!!!#0XHDD887"): its real
    text/plain part is exactly 14 bytes of '\\r\\n\\r\\n\\r\\n\\r\\n\\xa0\\xa0\\r\\n',
    while its real text/html part is 1305 bytes containing two real
    dereferrer-wrapped redirect links -- a classic image-only phishing
    pattern. Before this fix, extract_email_content returned just the
    Subject line (50 bytes total): Watchman got nothing behavioral to
    analyze and Cipher got no body text to extract an IOC from."""
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: test\r\n"
        b'Content-Type: multipart/alternative; boundary="BOUNDARY"\r\n\r\n'
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"\r\n\r\n\r\n\r\n\xc2\xa0\xc2\xa0\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b'<html><body><a href="https://deref-web.de/mail/client/akYai3oF398/dereferrer/'
        b'?redirectUrl=https%3A%2F%2Ft.ly%2Faiwugiuaew-gakahgbhf97"><img src="x.png"></a>'
        b"</body></html>\r\n"
        b"--BOUNDARY--\r\n"
    )

    content = extract_email_content(raw_bytes)

    assert "deref-web.de" in content


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


def test_extract_email_content_decodes_subject_even_when_parser_returns_header_object() -> None:
    """[Code review, 2026-08-05] The 2026-07-23 patch above tested
    decode_header against a plain str Subject, but email.message.Message's
    get("Subject") can ALSO return an email.header.Header object instead
    of str for certain real, oddly-folded encoded headers -- decode_header
    does not raise on that input, it silently mis-decodes as charset=
    "unknown-8bit" instead, leaving the literal "=?UTF-8?B?...?=" marker
    undecoded.

    This is a verbatim reproduction of the exact bytes from
    benign_corpus_raw/malicious/tuning/sample-5380.eml's real Subject
    header (a real "🌞 Starte jetzt in den Sommer 2025..." phishing
    subject) -- confirmed by bisection that this specific real padding
    content (not just its length; a same-length synthetic line of spaces
    or commas does NOT reproduce it) is what makes Python's email parser
    return a Header object here rather than str, so the real bytes are
    used verbatim rather than a hand-built approximation that might not
    actually trigger the bug."""
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: =?UTF-8?B?8J+MniBTdGFydGUgamV0enQgaW4gZGVuIFNvbW1lciAyMDI1OiDigqwyMDAwIEJvbnVzICsgMTQ1IEZyZWlzcGllbGUgYmVpIGlXaW4gRm9ydHVuZSBDYXNpbm8g4oCTIGtlaW5lIEVpbnphaGx1bmcgbsO2dGlnIQ==?=\r\n"
        b"                                                                                                                                                                                                                                                      "
        b",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
        b"                                                                                                               "
        + b"\xc2\xb2" * 89 + b"wnznasdelw" + b"\xc2\xb2" * 39 + b"oatbbwaf" + b"\xc2\xb2" * 9
        + b"\r\n\r\nbody text"
    )

    content = extract_email_content(raw_bytes)

    assert "Starte jetzt in den Sommer 2025" in content
    assert "=?UTF-8?B?" not in content.split("\n\n", 1)[0]


def test_extract_email_content_preserves_raw_utf8_homoglyph_subject_not_corrupted_by_decode() -> None:
    """[Code review, 2026-08-05, Edge Case Hunter] CRITICAL regression test.
    An earlier version of this fix (str(raw_subject) unconditionally before
    decode_header) was a NET REGRESSION, confirmed against the real corpus:
    it "fixed" 11 files but CORRUPTED 1,903 others (18% of the corpus) --
    real Subject text replaced with U+FFFD garbage, including homoglyph
    phishing text specifically, directly undermining this function's own
    stated purpose.

    This is a verbatim reproduction of the real raw bytes from
    benign_corpus_raw/malicious/held_out/sample-1053.eml: a homoglyph-
    evasion phishing subject with a raw (non-RFC-2047-encoded) UTF-8
    Cyrillic 'о' (0xD0 0xBE) sitting directly in the header bytes --
    "Imp[Cyrillic-о]rtant Inf[Cyrillic-о]rmation Fr[Cyrillic-о]m AT&T!".
    Python's email parser stores this as a Header object with an
    "unknown-8bit" chunk holding the ORIGINAL bytes (recoverable losslessly
    via surrogateescape). Passing that Header object directly into
    decode_header() correctly recovers and decodes the real bytes; calling
    str() on it FIRST invokes Header.__str__(), which decodes those same
    bytes with errors="replace" internally -- permanently destroying them
    with U+FFFD before decode_header ever gets a chance to see the real
    bytes. The fix must never do that."""
    raw_bytes = (
        b"From: alice@example.com\r\n"
        b"Subject: Imp\xd0\xbertant Inf\xd0\xbermation Fr\xd0\xbem AT&T!\r\n"
        b"\r\nbody text"
    )

    content = extract_email_content(raw_bytes)

    assert "Impоrtant Infоrmation Frоm AT&T!" in content
    assert "�" not in content.split("\n\n", 1)[0]


def test_decode_subject_handles_a_realistic_header_object_with_leading_plain_text() -> None:
    """[Code review, 2026-08-05] Real corpus example (sample-4911.eml) of a
    PARTIAL decode failure -- a Subject with real plain-text content
    followed by a trailing encoded-word ("phishing@pot, Get an ESaver -
    <encoded 'Enter to Win with Elon Musk!'>"). Constructs an actual
    email.header.Header directly (the real, minimal trigger for this bug
    class -- decode_header() behaves differently for a Header instance
    than for a str, regardless of how that Header was produced) rather
    than relying on the fragile exact-byte-padding trigger reproduced in
    the test above, while still using the real corpus text verbatim."""
    from email.header import Header

    from sentinel.triage.ingest import _decode_subject

    real_subject_text = (
        "phishing@pot, Get an ESaver – "
        "=?UTF-8?B?RW50ZXIgdG8gV2luIHdpdGggRWxvbiBNdXNrIQ==?="
    )
    header_obj = Header(real_subject_text)
    assert not isinstance(header_obj, str)  # sanity: reproduces the real type mismatch

    decoded = _decode_subject(header_obj)  # type: ignore[arg-type]

    assert "Enter to Win with Elon Musk!" in decoded
    assert "=?UTF-8?B?" not in decoded


def test_decode_subject_exception_fallback_still_returns_str_not_header_object() -> None:
    """[Code review, 2026-08-05] decode_header() itself CAN raise (confirmed:
    HeaderParseError on malformed base64 in an encoded-word, a realistic
    real-world case -- corrupted/truncated headers, whether accidental or
    a deliberate evasion attempt). The exception fallback `return
    raw_subject` previously returned the ORIGINAL object unmodified -- if
    raw_subject was a Header (this function's whole reason for existing),
    it could still hand back a non-str Header on this path, undermining
    the fix's own guarantee that this function always returns str."""
    from email.header import Header

    from sentinel.triage.ingest import _decode_subject

    header_obj = Header("=?UTF-8?B?not-valid-base64!!!?=")
    assert not isinstance(header_obj, str)

    decoded = _decode_subject(header_obj)  # type: ignore[arg-type]

    assert isinstance(decoded, str)


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
