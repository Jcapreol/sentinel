from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Generator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import sentinel.web.state as state_mod
from sentinel.web.main import app

if TYPE_CHECKING:
    from sentinel.config import Config


@pytest.fixture(autouse=True)
def reset_web_state() -> Generator[None, None, None]:
    """Reset all mutable web state before and after every test in tests/web/."""
    state_mod._vt_calls_used = 0
    state_mod._config = None
    state_mod._quota_lock = asyncio.Lock()
    yield
    state_mod._vt_calls_used = 0
    state_mod._config = None


@pytest.fixture
def web_client(fake_config: "Config") -> Generator[TestClient, None, None]:
    """TestClient with fake config loaded through the lifespan."""
    with patch("sentinel.web.main.load_config", return_value=fake_config):
        with TestClient(app) as client:
            yield client
