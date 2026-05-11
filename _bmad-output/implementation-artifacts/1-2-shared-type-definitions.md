# Story 1.2: Shared Type Definitions

Status: review

## Story

As a developer,
I want all cross-module data contracts defined in a single source-of-truth module,
so that every other module can import typed structures, mypy enforces the contracts at dev time, and no module redefines types independently.

## Acceptance Criteria

1. **Given** `verdict.py` is implemented, **When** `mypy src/` runs, **Then** no type errors are reported for any TypedDict or Protocol definition.

2. **Given** `AgentResult` is imported from `sentinel.verdict`, **When** its fields are inspected, **Then** it has exactly: `source_name: str`, `findings: list[str]`, `blind_spots: list[BlindSpot]`, `raw_confidence: str | None`, `error: str | None`.

3. **Given** `BlindSpot` is imported from `sentinel.verdict`, **When** its fields are inspected, **Then** it has exactly: `source: str`, `reason: str`, `next_step: str | None`.

4. **Given** `VerdictSchema` is imported from `sentinel.verdict`, **When** its fields are inspected, **Then** it has exactly: `verdict: str`, `confidence_tier: int`, `methodology: list[dict]`, `citations: list[dict]`, `blind_spots: list[BlindSpot]`, `source_independence_confirmed: bool`, `execution_time_seconds: float`, `timestamp: str`.

5. **Given** `SentinelAgent` Protocol is imported from `sentinel.verdict`, **When** a class with `analyze(self, input_data: str) -> AgentResult` is checked by mypy, **Then** mypy accepts it as satisfying the Protocol without the class inheriting from anything.

6. **Given** `verdict.py` is inspected for imports, **When** its import statements are reviewed, **Then** it imports nothing from `sentinel.*` — it is the foundation layer with no intra-package dependencies.

7. **And** `tests/test_verdict.py` verifies schema field presence, correct types for all TypedDict fields, and that the Protocol signature matches the defined contract.

## Tasks / Subtasks

- [x] **Task 1: Implement `verdict.py`** (AC: 1, 2, 3, 4, 5, 6)
  - [x] Create `src/sentinel/verdict.py` with stdlib-only imports (`from typing import Any, Protocol, TypedDict`)
  - [x] Define `BlindSpot` TypedDict with exactly 3 fields: `source: str`, `reason: str`, `next_step: str | None`
  - [x] Define `AgentResult` TypedDict with exactly 5 fields — **CRITICAL: `blind_spots: list[BlindSpot]` not `list[str]`** (see Dev Notes)
  - [x] Define `VerdictSchema` TypedDict with exactly 8 fields — use `list[dict[str, Any]]` for `methodology` and `citations` (see Dev Notes)
  - [x] Define `SentinelAgent` Protocol with `analyze(self, input_data: str) -> AgentResult: ...`
  - [x] Confirm ordering: `BlindSpot` → `AgentResult` → `VerdictSchema` → `SentinelAgent` (dependency order)

- [x] **Task 2: Write `tests/test_verdict.py`** (AC: 7)
  - [x] Test `BlindSpot` field presence and types (including `next_step: str | None`)
  - [x] Test `AgentResult` field presence — specifically verify `blind_spots` is `list[BlindSpot]` not `list[str]`
  - [x] Test `VerdictSchema` has exactly 8 fields (use `typing.get_type_hints()`)
  - [x] Test `SentinelAgent` Protocol is satisfied structurally by a class with the correct `analyze()` signature

- [x] **Task 3: Verify CI green** (AC: 1)
  - [x] `py -m ruff check src/ tests/` — 0 issues
  - [x] `py -m mypy src/` — 0 errors across all source files (now 3: `__init__.py`, `main.py`, `verdict.py`)
  - [x] `py -m pytest tests/ -v` — all tests pass (existing `test_version.py` + new `test_verdict.py`)

## Dev Notes

### verdict.py — Exact Implementation

`verdict.py` is the **foundation layer** of the entire codebase. Every other module imports from it. It must have **zero intra-package imports** — only stdlib.

```python
from typing import Any, Protocol, TypedDict


class BlindSpot(TypedDict):
    source: str
    reason: str
    next_step: str | None


class AgentResult(TypedDict):
    source_name: str
    findings: list[str]
    blind_spots: list[BlindSpot]
    raw_confidence: str | None
    error: str | None


class VerdictSchema(TypedDict):
    verdict: str
    confidence_tier: int
    methodology: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    blind_spots: list[BlindSpot]
    source_independence_confirmed: bool
    execution_time_seconds: float
    timestamp: str


class SentinelAgent(Protocol):
    def analyze(self, input_data: str) -> AgentResult: ...
```

**That is the complete file.** No additional code, no functions, no `__all__`, no logging.

### CRITICAL: `AgentResult.blind_spots` is `list[BlindSpot]`, NOT `list[str]`

This was a deliberate architecture validation fix (Issue 1 from `architecture.md#Architecture Validation Results`). An early draft had `list[str]`. The final architecture explicitly corrected it to `list[BlindSpot]`.

**Why it matters:** Every agent (Watchman, Cipher) returns `AgentResult`. If `blind_spots` were `list[str]`, agents would store blind spot data as unstructured strings, losing the `source`, `reason`, and `next_step` fields. The structured `BlindSpot` TypedDict is what allows verdict assembly to build the final `named_blind_spots` section with actionable implications (FR13–FR15).

**mypy will enforce this:** Once `verdict.py` exists, any code that assigns `list[str]` to `blind_spots` is a type error caught at dev time.

### mypy strict: `list[dict[str, Any]]` not `list[dict]`

With `strict = true` in `pyproject.toml`, mypy enables `--disallow-any-generics`. This makes it an error to use generic types without explicit type parameters.

| ❌ Fails strict | ✅ Passes strict |
|---|---|
| `methodology: list[dict]` | `methodology: list[dict[str, Any]]` |
| `citations: list[dict]` | `citations: list[dict[str, Any]]` |

The AC says `list[dict]` semantically — meaning "a list of dicts". The actual annotation must be `list[dict[str, Any]]` to satisfy mypy strict. This is compliant with the AC: the runtime structure is still a list of dicts.

**Why `dict[str, Any]`:** Citation entries have mixed-value types (e.g. `{"source": "VirusTotal", "reports": 12}` — string key, mixed str/int values). `dict[str, str]` would be too narrow. `dict[str, Any]` is the correct explicit annotation.

### `str | None` Syntax — Python 3.10+ Only

The union syntax `str | None` (PEP 604) is valid in Python 3.10+. The project requires `python_version = "3.10"` in mypy config and `requires-python = ">=3.10"` in `pyproject.toml`. Do **not** use `Optional[str]` from typing — it is equivalent but more verbose and unnecessary in 3.10+.

### Import Discipline — `verdict.py` Imports Nothing from `sentinel.*`

```
verdict.py   ← ONLY: from typing import Any, Protocol, TypedDict
config.py    ← imports nothing from sentinel.* (Story 1.3)
source_registry.py ← imports nothing from sentinel.* (Story 2.1)
confidence.py ← imports source_registry (Story 2.2)
watchman.py  ← imports verdict, config (Story 3.1)
cipher.py    ← imports verdict, config (Story 3.2)
main.py      ← imports all siblings (Story 4.2 completion)
```

`verdict.py` sits at the bottom of the dependency graph. Any `from sentinel.X import Y` inside it is a **bug**. It should be flagged immediately in code review.

### Existing Files — Do NOT Modify

These files were created in Story 1.1 and must remain unchanged:

| File | Current state | Action |
|------|--------------|--------|
| `src/sentinel/__init__.py` | `__version__ = "0.1.0"` | **Leave as-is** |
| `src/sentinel/main.py` | argparse scaffold, stdlib-only | **Leave as-is** |
| `tests/test_version.py` | version string test | **Leave as-is** |
| `pyproject.toml` | full config with pinned deps | **Leave as-is** |

`main.py` currently does `import argparse, sys` — no `sentinel.*` imports. That's correct. Story 4.2 is when `main.py` gets the full implementation.

### No `conftest.py` Yet

`tests/conftest.py` with `fake_config()`, `sample_alert`, and `make_agent_result()` fixtures is **Story 1.3**. Do not create it here.

`test_verdict.py` does not need shared fixtures — it instantiates TypedDicts directly inline.

### test_verdict.py — Implementation Guide

```python
import typing

from sentinel.verdict import AgentResult, BlindSpot, SentinelAgent, VerdictSchema


def test_blindspot_fields() -> None:
    bs = BlindSpot(source="watchman", reason="timed out", next_step=None)
    assert bs["source"] == "watchman"
    assert bs["reason"] == "timed out"
    assert bs["next_step"] is None


def test_blindspot_next_step_can_be_string() -> None:
    bs = BlindSpot(
        source="cipher",
        reason="VirusTotal rate limited",
        next_step="Retry after 60 seconds or check VT web UI",
    )
    assert bs["next_step"] == "Retry after 60 seconds or check VT web UI"


def test_agent_result_fields() -> None:
    bs = BlindSpot(source="watchman", reason="timed out", next_step=None)
    result = AgentResult(
        source_name="watchman",
        findings=["suspicious behavior"],
        blind_spots=[bs],
        raw_confidence=None,
        error="timeout",
    )
    assert result["source_name"] == "watchman"
    assert result["findings"] == ["suspicious behavior"]
    assert result["raw_confidence"] is None
    assert result["error"] == "timeout"


def test_agent_result_blind_spots_is_list_of_blindspot() -> None:
    # Verify blind_spots holds BlindSpot dicts, not plain strings (architecture fix)
    bs = BlindSpot(source="cipher", reason="rate limited", next_step=None)
    result = AgentResult(
        source_name="cipher",
        findings=[],
        blind_spots=[bs],
        raw_confidence=None,
        error="rate_limited",
    )
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["source"] == "cipher"
    assert result["blind_spots"][0]["reason"] == "rate limited"


def test_verdict_schema_has_exactly_eight_fields() -> None:
    hints = typing.get_type_hints(VerdictSchema)
    assert set(hints.keys()) == {
        "verdict",
        "confidence_tier",
        "methodology",
        "citations",
        "blind_spots",
        "source_independence_confirmed",
        "execution_time_seconds",
        "timestamp",
    }


def test_verdict_schema_fields() -> None:
    verdict = VerdictSchema(
        verdict="Probable",
        confidence_tier=2,
        methodology=[{"agent": "watchman", "action": "behavioral_analysis"}],
        citations=[{"source": "VirusTotal", "indicator": "1.2.3.4"}],
        blind_spots=[],
        source_independence_confirmed=True,
        execution_time_seconds=18.4,
        timestamp="2026-05-11T00:00:00Z",
    )
    assert verdict["verdict"] == "Probable"
    assert verdict["confidence_tier"] == 2
    assert verdict["source_independence_confirmed"] is True
    assert verdict["blind_spots"] == []
    assert isinstance(verdict["execution_time_seconds"], float)


def test_sentinel_agent_protocol_satisfied_structurally() -> None:
    # Annotating as SentinelAgent lets mypy verify structural conformance
    class MockAgent:
        def analyze(self, input_data: str) -> AgentResult:
            return AgentResult(
                source_name="mock",
                findings=[],
                blind_spots=[],
                raw_confidence=None,
                error=None,
            )

    agent: SentinelAgent = MockAgent()
    result = agent.analyze("test alert")
    assert result["source_name"] == "mock"
    assert result["blind_spots"] == []
    assert result["error"] is None
```

**Note on the Protocol test:** At runtime this verifies the structural interface works correctly. mypy verifies structural compatibility when it type-checks the file — the CI `mypy src/` step will confirm Protocol satisfaction. `@runtime_checkable` is **not** used (not in the architecture spec).

### Architecture Compliance Checklist

- [x] `verdict.py` has zero `sentinel.*` imports (AR1 — foundation layer, no intra-package deps)
- [x] `AgentResult.blind_spots` type is `list[BlindSpot]`, not `list[str]` (architecture validation fix Issue 1)
- [x] `methodology` and `citations` use `list[dict[str, Any]]` — passes mypy `--disallow-any-generics`
- [x] `str | None` syntax used throughout — no `Optional[str]` (Python 3.10+ style)
- [x] Definition order: `BlindSpot` → `AgentResult` → `VerdictSchema` → `SentinelAgent` (forward reference safety)
- [x] No `@runtime_checkable` on `SentinelAgent` — pure structural typing, mypy-only enforcement
- [x] `mypy src/` passes with 0 errors on all 3 source files after this story

### Project Structure After This Story

```
sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py          ← unchanged from Story 1.1
│       ├── main.py              ← unchanged from Story 1.1
│       └── verdict.py           ← NEW: foundation TypedDicts + Protocol
├── tests/
│   ├── test_version.py          ← unchanged from Story 1.1
│   └── test_verdict.py          ← NEW: schema and Protocol tests
```

### Previous Story Learnings (Story 1.1)

- Use `py -m ruff` / `py -m mypy` / `py -m pytest` — the `ruff`, `mypy`, `pytest` commands are not on PowerShell PATH on Windows; invoke via `py -m` prefix
- mypy 2.0.0 is installed and strict mode is active — `--disallow-any-generics` and `--disallow-untyped-defs` are both enabled; all functions and TypedDicts must be fully annotated
- `build-backend = "setuptools.build_meta"` (not `"setuptools.backends.legacy:build"`) — confirmed working
- `tests/conftest.py` is intentionally absent until Story 1.3

### References

- [Source: architecture.md#Data Architecture] — TypedDict definitions, `AgentResult`, `BlindSpot`, `VerdictSchema`, `SentinelAgent` Protocol
- [Source: architecture.md#API & Communication Patterns] — agent interface contract, Protocol shape
- [Source: architecture.md#Architecture Validation Results, Issue 1] — `AgentResult.blind_spots: list[BlindSpot]` correction
- [Source: architecture.md#Blind Spot Format Pattern] — `BlindSpot` three-field structure, reason field rules
- [Source: architecture.md#Import Discipline] — `verdict.py` at foundation layer; imports nothing from `sentinel.*`
- [Source: architecture.md#Implementation Handoff] — implementation sequence; `verdict.py` first
- [Source: epics.md#Story 1.2] — acceptance criteria, field specifications

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

- ruff F401: `SentinelAgent` imported but unused — fixed by annotating `agent: SentinelAgent = MockAgent()` in the Protocol test. This is the correct fix: it uses the import at runtime AND gives mypy an explicit structural conformance check to verify.

### Completion Notes List

- `verdict.py` is 22 lines including blank lines. Foundation layer confirmed: only `from typing import Any, Protocol, TypedDict`.
- `AgentResult.blind_spots: list[BlindSpot]` — architecture validation fix applied correctly.
- `methodology` and `citations` annotated as `list[dict[str, Any]]` — passes `--disallow-any-generics` under mypy strict.
- `str | None` union syntax used throughout (Python 3.10+ style, no `Optional`).
- Definition order: `BlindSpot` → `AgentResult` → `VerdictSchema` → `SentinelAgent` — no forward references needed.
- `agent: SentinelAgent = MockAgent()` annotation pattern gives mypy a structural conformance check and satisfies ruff's unused-import check simultaneously.
- mypy now checks 3 source files (`__init__.py`, `main.py`, `verdict.py`) — 0 errors.
- All 8 tests pass; `test_version.py` (1.1) is a clean regression.

### File List

- `src/sentinel/verdict.py` (new)
- `tests/test_verdict.py` (new)
