from collections.abc import Callable
from typing import Literal

import pytest

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
