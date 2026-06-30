from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from sentinel.config import ConfigError
from sentinel.web.main import app

if TYPE_CHECKING:
    from sentinel.config import Config


def test_root_returns_200(fake_config: "Config") -> None:
    with patch("sentinel.web.main.load_config", return_value=fake_config):
        with TestClient(app) as client:
            response = client.get("/")
    assert response.status_code == 200


def test_root_returns_html(fake_config: "Config") -> None:
    with patch("sentinel.web.main.load_config", return_value=fake_config):
        with TestClient(app) as client:
            response = client.get("/")
    assert "text/html" in response.headers["content-type"]


def test_missing_api_key_logs_to_stderr_not_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch(
        "sentinel.web.main.load_config",
        side_effect=ConfigError(
            "Missing required environment variable: ANTHROPIC_API_KEY"
        ),
    ):
        with TestClient(app) as client:
            client.get("/")
    captured = capsys.readouterr()
    assert "[sentinel-web]" in captured.err
    assert "Traceback" not in captured.err


def test_fixtures_not_accessible_via_static_mount(fake_config: "Config") -> None:
    with patch("sentinel.web.main.load_config", return_value=fake_config):
        with TestClient(app) as client:
            response = client.get("/static/../fixtures/lsass-credential-dumping.json")
    assert response.status_code in (400, 404)
