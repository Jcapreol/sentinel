from collections.abc import Callable

from sentinel.triage.evidence import EvidenceItem


def test_evidence_item_construction_with_all_fields() -> None:
    item = EvidenceItem(
        name="spf_check",
        finding="SPF record passed",
        weight=0.7,
        direction="benign",
    )
    assert item["name"] == "spf_check"
    assert item["finding"] == "SPF record passed"
    assert item["weight"] == 0.7
    assert item["direction"] == "benign"


def test_make_evidence_item_factory_defaults(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    item = make_evidence_item()
    assert item["name"] == "test_signal"
    assert item["finding"] == "test finding"
    assert item["weight"] == 0.5
    assert item["direction"] == "neutral"


def test_make_evidence_item_factory_overrides(
    make_evidence_item: Callable[..., EvidenceItem],
) -> None:
    item = make_evidence_item(name="dkim_check", weight=0.9, direction="malicious")
    assert item["name"] == "dkim_check"
    assert item["weight"] == 0.9
    assert item["direction"] == "malicious"
