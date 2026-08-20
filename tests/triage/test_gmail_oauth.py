import re
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from sentinel.triage import gmail_oauth
from sentinel.triage.gmail_oauth import GMAIL_READONLY_SCOPE, get_credentials


def test_requested_scope_is_exactly_gmail_readonly() -> None:
    """[Story 5.3, AC4] Every other test in this file (and in
    test_ingest.py's service-account equivalent) asserts against the
    GMAIL_READONLY_SCOPE constant, not a hardcoded literal -- which means
    a future change that silently broadens the constant's own value (e.g.
    to gmail.modify) would pass every one of those tests unchanged, since
    they'd just be comparing the broadened value to itself. This pins the
    exact literal string and the list shape (exactly one scope) with no
    reference to the constant, so a broadened scope fails here regardless
    of what the constant is renamed or refactored to."""
    assert gmail_oauth._SCOPES == ["https://www.googleapis.com/auth/gmail.readonly"]
    assert GMAIL_READONLY_SCOPE == "https://www.googleapis.com/auth/gmail.readonly"


def test_get_credentials_uses_cached_valid_token_without_flow(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    token_path = tmp_path / "token.json"
    token_path.write_text("{}")
    client_secret_path = tmp_path / "client.json"

    cached_creds = mocker.MagicMock(valid=True)
    from_file = mocker.patch(
        "sentinel.triage.gmail_oauth.Credentials.from_authorized_user_file",
        return_value=cached_creds,
    )
    flow_cls = mocker.patch("sentinel.triage.gmail_oauth.InstalledAppFlow")

    result = get_credentials(client_secret_path, token_path)

    from_file.assert_called_once_with(str(token_path), [GMAIL_READONLY_SCOPE])
    flow_cls.from_client_secrets_file.assert_not_called()
    assert result is cached_creds


def test_get_credentials_refreshes_expired_token_with_refresh_token(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    token_path = tmp_path / "token.json"
    token_path.write_text("{}")
    client_secret_path = tmp_path / "client.json"

    cached_creds = mocker.MagicMock(valid=False, expired=True, refresh_token="rt")
    cached_creds.to_json.return_value = '{"refreshed": true}'
    mocker.patch(
        "sentinel.triage.gmail_oauth.Credentials.from_authorized_user_file",
        return_value=cached_creds,
    )
    request_cls = mocker.patch("sentinel.triage.gmail_oauth.Request")
    flow_cls = mocker.patch("sentinel.triage.gmail_oauth.InstalledAppFlow")

    result = get_credentials(client_secret_path, token_path)

    cached_creds.refresh.assert_called_once_with(request_cls.return_value)
    flow_cls.from_client_secrets_file.assert_not_called()
    assert result is cached_creds
    assert token_path.read_text() == '{"refreshed": true}'


def test_get_credentials_runs_installed_app_flow_when_no_cached_token(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    # [Story 8.2] Interactive flow only ever attempted when a TTY is present
    # -- pytest's own stdin is not one, so this simulates an attended
    # session explicitly, same as a human would provide one for real.
    mocker.patch("sentinel.triage.gmail_oauth.sys.stdin.isatty", return_value=True)
    token_path = tmp_path / "nested" / "token.json"
    client_secret_path = tmp_path / "client.json"
    client_secret_path.write_text("{}")

    fresh_creds = mocker.MagicMock()
    fresh_creds.to_json.return_value = '{"fresh": true}'
    flow_cls = mocker.patch("sentinel.triage.gmail_oauth.InstalledAppFlow")
    flow_cls.from_client_secrets_file.return_value.run_local_server.return_value = fresh_creds

    result = get_credentials(client_secret_path, token_path)

    flow_cls.from_client_secrets_file.assert_called_once_with(
        str(client_secret_path), [GMAIL_READONLY_SCOPE]
    )
    # [Story 8.2] timeout_seconds is now always passed -- a safety bound,
    # not something callers opt out of.
    flow_cls.from_client_secrets_file.return_value.run_local_server.assert_called_once_with(
        port=0, timeout_seconds=gmail_oauth._OAUTH_CONSENT_TIMEOUT_SECONDS
    )
    assert result is fresh_creds
    assert token_path.exists()
    assert token_path.read_text() == '{"fresh": true}'


def test_get_credentials_raises_when_client_secret_missing(tmp_path: Path) -> None:
    token_path = tmp_path / "token.json"
    client_secret_path = tmp_path / "does-not-exist.json"

    with pytest.raises(FileNotFoundError, match=re.escape(str(client_secret_path))):
        get_credentials(client_secret_path, token_path)


# --- Story 8.2: fail fast on non-interactive OAuth consent ----------------------


def test_get_credentials_raises_when_no_tty_and_no_cached_token(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """[Story 8.2, AC1] The primary fix: under a non-interactive invocation
    (e.g. cron), this must fail in milliseconds -- no browser opened, no
    local server bound, no network call attempted -- rather than entering
    the interactive consent flow and blocking forever."""
    mocker.patch("sentinel.triage.gmail_oauth.sys.stdin.isatty", return_value=False)
    token_path = tmp_path / "token.json"
    client_secret_path = tmp_path / "client.json"
    client_secret_path.write_text("{}")
    flow_cls = mocker.patch("sentinel.triage.gmail_oauth.InstalledAppFlow")

    with pytest.raises(RuntimeError, match="No interactive terminal available"):
        get_credentials(client_secret_path, token_path)

    flow_cls.from_client_secrets_file.assert_not_called()


def test_get_credentials_no_tty_error_names_the_remedy(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """[Story 8.2, AC2] The error must name the actual remedy an operator
    can act on: complete consent on a machine with a browser, then copy
    the token file over."""
    mocker.patch("sentinel.triage.gmail_oauth.sys.stdin.isatty", return_value=False)
    token_path = tmp_path / "token.json"
    client_secret_path = tmp_path / "client.json"
    client_secret_path.write_text("{}")

    with pytest.raises(RuntimeError) as exc_info:
        get_credentials(client_secret_path, token_path)

    message = str(exc_info.value)
    assert "unattended" in message
    assert "browser" in message
    assert "copy the resulting token file" in message
    assert "GMAIL_OAUTH_TOKEN_PATH" in message
    assert repr(token_path) in message


def test_get_credentials_raises_on_consent_timeout(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """[Story 8.2, AC3] An attended session that starts the flow and never
    completes it must still eventually fail with a clear error, not hang
    forever -- simulated by making run_local_server raise the real
    WSGITimeoutError the library itself raises on expiry, never a real
    300-second wait."""
    mocker.patch("sentinel.triage.gmail_oauth.sys.stdin.isatty", return_value=True)
    token_path = tmp_path / "token.json"
    client_secret_path = tmp_path / "client.json"
    client_secret_path.write_text("{}")
    flow_cls = mocker.patch("sentinel.triage.gmail_oauth.InstalledAppFlow")
    flow_cls.from_client_secrets_file.return_value.run_local_server.side_effect = (
        gmail_oauth.WSGITimeoutError("Timed out waiting for response from authorization server")
    )

    with pytest.raises(RuntimeError, match="timed out after 300s"):
        get_credentials(client_secret_path, token_path)

    flow_cls.from_client_secrets_file.return_value.run_local_server.assert_called_once_with(
        port=0, timeout_seconds=gmail_oauth._OAUTH_CONSENT_TIMEOUT_SECONDS
    )


def test_get_credentials_timeout_error_names_the_remedy_and_no_unreachable_advice(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """[Story 8.2, AC2] Deliberately does NOT mention copying a token file
    for unattended use -- this branch is only ever reached when a TTY was
    already present (Case 1's check gates entry to the whole flow), so
    that advice would be unreachable noise at the moment a human needs one
    clear instruction. Regression guard for the reviewed-and-revised
    wording (see the Story 8.2 story file's Q3)."""
    mocker.patch("sentinel.triage.gmail_oauth.sys.stdin.isatty", return_value=True)
    token_path = tmp_path / "token.json"
    client_secret_path = tmp_path / "client.json"
    client_secret_path.write_text("{}")
    flow_cls = mocker.patch("sentinel.triage.gmail_oauth.InstalledAppFlow")
    flow_cls.from_client_secrets_file.return_value.run_local_server.side_effect = (
        gmail_oauth.WSGITimeoutError("Timed out waiting for response from authorization server")
    )

    with pytest.raises(RuntimeError) as exc_info:
        get_credentials(client_secret_path, token_path)

    message = str(exc_info.value)
    assert "re-run interactively and complete sign-in and consent" in message
    assert "unattended" not in message
    assert "copy" not in message


def test_get_credentials_no_tty_and_timeout_messages_are_distinguishable(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """[Story 8.2, AC7] The two new failure messages, and the pre-existing
    invalid_grant-shaped refresh failure, must be tellable apart at a
    glance in raw log output -- not just structurally different types
    (all three end up wrapped as ConfigError by ingest.py's
    build_gmail_service either way)."""
    token_path = tmp_path / "token.json"
    client_secret_path = tmp_path / "client.json"
    client_secret_path.write_text("{}")

    mocker.patch("sentinel.triage.gmail_oauth.sys.stdin.isatty", return_value=False)
    with pytest.raises(RuntimeError) as no_tty_exc:
        get_credentials(client_secret_path, token_path)

    mocker.patch("sentinel.triage.gmail_oauth.sys.stdin.isatty", return_value=True)
    flow_cls = mocker.patch("sentinel.triage.gmail_oauth.InstalledAppFlow")
    flow_cls.from_client_secrets_file.return_value.run_local_server.side_effect = (
        gmail_oauth.WSGITimeoutError("Timed out waiting for response from authorization server")
    )
    with pytest.raises(RuntimeError) as timeout_exc:
        get_credentials(client_secret_path, token_path)

    no_tty_message = str(no_tty_exc.value)
    timeout_message = str(timeout_exc.value)
    assert no_tty_message != timeout_message
    # Each error's own distinguishing phrase appears in only one of the two.
    assert "No interactive terminal available" in no_tty_message
    assert "No interactive terminal available" not in timeout_message
    assert "timed out after" in timeout_message
    assert "timed out after" not in no_tty_message


def test_get_credentials_expired_token_with_refresh_token_never_checks_tty(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """[Story 8.2, AC4] The refresh-token branch (a cached, expired-but-
    refreshable token) must be completely unaffected by this story -- the
    TTY check lives only inside the "no usable token at all" branch, never
    on the refresh path, which was already correctly unattended-safe."""
    token_path = tmp_path / "token.json"
    token_path.write_text("{}")
    client_secret_path = tmp_path / "client.json"

    cached_creds = mocker.MagicMock(valid=False, expired=True, refresh_token="rt")
    cached_creds.to_json.return_value = '{"refreshed": true}'
    mocker.patch(
        "sentinel.triage.gmail_oauth.Credentials.from_authorized_user_file",
        return_value=cached_creds,
    )
    mocker.patch("sentinel.triage.gmail_oauth.Request")
    isatty_spy = mocker.patch("sentinel.triage.gmail_oauth.sys.stdin.isatty")

    result = get_credentials(client_secret_path, token_path)

    isatty_spy.assert_not_called()
    assert result is cached_creds
