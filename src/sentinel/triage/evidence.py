from typing import Literal, TypedDict


class EvidenceItem(TypedDict):
    name: str
    finding: str
    weight: float
    direction: Literal["malicious", "benign", "neutral"]
