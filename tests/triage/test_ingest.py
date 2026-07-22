import ast
import subprocess
from pathlib import Path

import pytest
from googleapiclient.errors import HttpError

from sentinel.config import Config, ConfigError
from sentinel.triage.ingest import (
    FetchFailed,
    build_gmail_service,
    fetch_headers_for_messages,
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
