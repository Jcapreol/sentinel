import re
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from sentinel.triage.gmail_oauth import GMAIL_READONLY_SCOPE, get_credentials


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
    flow_cls.from_client_secrets_file.return_value.run_local_server.assert_called_once_with(
        port=0
    )
    assert result is fresh_creds
    assert token_path.exists()
    assert token_path.read_text() == '{"fresh": true}'


def test_get_credentials_raises_when_client_secret_missing(tmp_path: Path) -> None:
    token_path = tmp_path / "token.json"
    client_secret_path = tmp_path / "does-not-exist.json"

    with pytest.raises(FileNotFoundError, match=re.escape(str(client_secret_path))):
        get_credentials(client_secret_path, token_path)
