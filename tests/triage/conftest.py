from collections.abc import Callable
from pathlib import Path
from typing import Literal

import pytest
from cryptography.fernet import Fernet

from sentinel.config import Config
from sentinel.triage.evidence import EvidenceItem


@pytest.fixture
def make_evidence_item() -> Callable[..., EvidenceItem]:
    def _make(
        name: str = "test_signal",
        finding: str = "test finding",
        weight: float = 0.5,
        direction: Literal["malicious", "benign", "neutral"] = "neutral",
    ) -> EvidenceItem:
        return EvidenceItem(name=name, finding=finding, weight=weight, direction=direction)

    return _make


@pytest.fixture
def store_db_path(tmp_path: Path) -> str:
    return str(tmp_path / "evidence.db")


@pytest.fixture
def store_config() -> Config:
    return Config(
        anthropic_api_key="ak-test",
        virustotal_api_key="vt-test",
        abuseipdb_api_key="ab-test",
        urlhaus_api_key="uh-test",
        evidence_encryption_key=Fernet.generate_key().decode(),
    )
