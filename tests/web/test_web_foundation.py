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


# ── Static file content-type tests ───────────────────────────────────────────

def test_static_style_css_serves_correct_content_type(web_client: TestClient) -> None:
    response = web_client.get("/static/style.css")
    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]


def test_static_app_js_serves_correct_content_type(web_client: TestClient) -> None:
    response = web_client.get("/static/app.js")
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]


def test_static_index_html_serves_correct_content_type(web_client: TestClient) -> None:
    response = web_client.get("/static/index.html")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


# ── NFR8: no .env / config / source files reachable via the web server ───────

def test_direct_fixtures_path_returns_404(web_client: TestClient) -> None:
    """NFR8: fixtures/ is not mounted — direct path must return 404."""
    response = web_client.get("/fixtures/tor-exit-node.json")
    assert response.status_code == 404


def test_dotenv_not_accessible_via_server(web_client: TestClient) -> None:
    """NFR8: /.env is not a registered route — must return 404."""
    response = web_client.get("/.env")
    assert response.status_code == 404


def test_src_path_traversal_via_static_blocked(web_client: TestClient) -> None:
    """NFR8: path traversal from /static into src/ must be blocked."""
    response = web_client.get("/static/../src/sentinel/config.py")
    assert response.status_code in (400, 404)


# ── FR28: Evaluation methodology footnote ────────────────────────────────────

def test_eval_footnote_present_in_rendered_page(web_client: TestClient) -> None:
    """FR28: rendered page states 10-sample evaluation set size and references reproducibility files."""
    html = web_client.get("/").text
    assert "10" in html, "Footnote must state the 10-sample evaluation set size"
    assert "labeled_set.json" in html, "Footnote must reference the labeled set file"
    assert "run_eval.py" in html, "Footnote must reference the reproducibility script"
    assert "5" in html, "Footnote must state per-class sample count (5 benign, 5 malicious)"
