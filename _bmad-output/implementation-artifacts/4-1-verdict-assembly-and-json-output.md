# Story 4.1: Verdict Assembly & JSON Output

Status: review

## Story

As a pipeline builder,
I want SENTINEL to output a stable, complete JSON verdict to stdout on every run,
So that I can parse `confidence_tier` with `jq` reliably and my downstream tooling never breaks across v1.x releases.

## Acceptance Criteria

1. **Given** both agent results, a confidence tier tuple, and the source independence flag, **When** `assemble_verdict(watchman_result, cipher_result, tier, source_independence_confirmed, start_time)` is called, **Then** it returns a `VerdictSchema` TypedDict with all 8 fields populated: `verdict` (string), `confidence_tier` (int), `methodology` (list of agent steps), `citations` (list of source findings), `blind_spots` (merged list from both agents — never null, always a list), `source_independence_confirmed` (bool), `execution_time_seconds` (float), `timestamp` (ISO 8601 UTC string).

2. **Given** a fully assembled `VerdictSchema`, **When** `print_verdict(verdict)` is called, **Then** JSON goes to stdout only — nothing to stderr, output is parseable by `json.loads()`.

3. **Given** the JSON is printed to stdout, **When** parsed by `json.loads()` or `jq`, **Then** it is valid JSON with no trailing text, no ANSI codes, and no extra whitespace breaking parsers.

4. **Given** both agents errored and produced only blind spots, **When** `assemble_verdict` is called with `tier=(1, "Investigating")`, **Then** `blind_spots` is a non-empty list (never `[]` or `null`), `confidence_tier` is 1, and `source_independence_confirmed` is `False`.

5. **Given** `blind_spots` from both agents are combined, **When** the final verdict is assembled, **Then** all blind spots from both agents appear in the output array — none are dropped.

6. **And** `tests/test_verdict.py` adds tests for: correct field values per confidence tier, blind_spots always a list, JSON round-trip stability, stdout purity (capsys verifies nothing hits stderr), all 8 fields present regardless of agent outcome.

## Tasks / Subtasks

- [x] **Task 1: Add `assemble_verdict` and `print_verdict` to `verdict.py`** (AC: 1–5)
  - [x] Add stdlib imports to `verdict.py`: `import json`, `import sys`, `import time`, `from datetime import datetime, timezone`
  - [x] Implement `assemble_verdict(watchman_result, cipher_result, tier, source_independence_confirmed, start_time)` — see Dev Notes for exact signature and implementation
  - [x] Implement `print_verdict(verdict: VerdictSchema) -> None` — prints `json.dumps(verdict, indent=2)` to `sys.stdout`

- [x] **Task 2: Add new tests to `tests/test_verdict.py`** (AC: 6)
  - [x] Test: Investigating tier — correct `confidence_tier=1`, `verdict="Investigating"`, `source_independence_confirmed=False`
  - [x] Test: Probable tier — correct `confidence_tier=2`, `verdict="Probable"`, `source_independence_confirmed=True`
  - [x] Test: `blind_spots` is always a `list` (even when empty)
  - [x] Test: blind spots merged from both agents when both fail — 2 blind spots total
  - [x] Test: JSON round-trip — `json.loads(json.dumps(verdict))` restores all field values
  - [x] Test: `print_verdict` stdout purity — `capsys.readouterr()` shows output on stdout, nothing on stderr, output is valid JSON
  - [x] Test: all 8 fields present when both agents fail

- [x] **Task 3: Verify CI green** (AC: all)
  - [x] `py -m ruff check src/ tests/` — 0 issues
  - [x] `py -m mypy src/` — 0 errors across all 8 source files
  - [x] `py -m pytest tests/ -v` — all 41 existing tests pass + new test_verdict.py tests

## Dev Notes

### Critical Import Constraint — No Circular Imports

`verdict.py` is the **foundation layer**. It already has ZERO imports from `sentinel.*`. This MUST remain true after Story 4.1.

**The circular import trap:** `confidence.py` imports `AgentResult` from `verdict.py`. If `verdict.py` imported `ConfidenceTier` from `confidence.py`, Python would fail at import time with a circular import error.

**Solution:** `assemble_verdict` accepts `tier: tuple[int, str]` — already resolved from `TIER_MAP` by the caller (`main.py` in Story 4.2). It also accepts `source_independence_confirmed: bool` — computed by the caller via `are_independent("watchman", "cipher")` from `source_registry.py`. `verdict.py` never imports from `confidence.py` or `source_registry.py`.

```
verdict.py        ← foundation: ZERO sentinel.* imports ← THIS FILE
config.py         ← foundation
source_registry.py ← foundation
confidence.py     ← imports source_registry + verdict
watchman.py       ← imports verdict + config
cipher.py         ← imports verdict + config
main.py           ← imports all siblings (Story 4.2)
```

### assemble_verdict — Exact Implementation

```python
def assemble_verdict(
    watchman_result: AgentResult,
    cipher_result: AgentResult,
    tier: tuple[int, str],
    source_independence_confirmed: bool,
    start_time: float,
) -> VerdictSchema:
    tier_int, tier_str = tier
    results = [watchman_result, cipher_result]
    methodology: list[dict[str, Any]] = [
        {
            "agent": r["source_name"],
            "status": "error" if r["error"] else "success",
            "error": r["error"],
        }
        for r in results
    ]
    citations: list[dict[str, Any]] = [
        {"source": r["source_name"], "finding": finding}
        for r in results
        for finding in r["findings"]
    ]
    blind_spots: list[BlindSpot] = [bs for r in results for bs in r["blind_spots"]]
    return VerdictSchema(
        verdict=tier_str,
        confidence_tier=tier_int,
        methodology=methodology,
        citations=citations,
        blind_spots=blind_spots,
        source_independence_confirmed=source_independence_confirmed,
        execution_time_seconds=round(time.time() - start_time, 3),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
```

### print_verdict — Exact Implementation

```python
def print_verdict(verdict: VerdictSchema) -> None:
    print(json.dumps(verdict, indent=2), file=sys.stdout)
```

`json.dumps(verdict, indent=2)` — TypedDicts are regular Python dicts at runtime, so `json.dumps` serializes them without a custom encoder. `None` values become `null` in JSON (correct for `next_step: str | None` in `BlindSpot`).

### verdict.py — Complete File After This Story

```python
import json
import sys
import time
from datetime import datetime, timezone
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


def assemble_verdict(
    watchman_result: AgentResult,
    cipher_result: AgentResult,
    tier: tuple[int, str],
    source_independence_confirmed: bool,
    start_time: float,
) -> VerdictSchema:
    tier_int, tier_str = tier
    results = [watchman_result, cipher_result]
    methodology: list[dict[str, Any]] = [
        {
            "agent": r["source_name"],
            "status": "error" if r["error"] else "success",
            "error": r["error"],
        }
        for r in results
    ]
    citations: list[dict[str, Any]] = [
        {"source": r["source_name"], "finding": finding}
        for r in results
        for finding in r["findings"]
    ]
    blind_spots: list[BlindSpot] = [bs for r in results for bs in r["blind_spots"]]
    return VerdictSchema(
        verdict=tier_str,
        confidence_tier=tier_int,
        methodology=methodology,
        citations=citations,
        blind_spots=blind_spots,
        source_independence_confirmed=source_independence_confirmed,
        execution_time_seconds=round(time.time() - start_time, 3),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def print_verdict(verdict: VerdictSchema) -> None:
    print(json.dumps(verdict, indent=2), file=sys.stdout)
```

### `tier` Parameter — How Callers Resolve It

In tests, use hard-coded tuples matching `TIER_MAP`:
```python
# Do NOT import from confidence.py in test_verdict.py — unnecessary coupling
tier_investigating = (1, "Investigating")
tier_probable = (2, "Probable")
tier_confirmed = (3, "Confirmed")
```

In `main.py` (Story 4.2), the caller does:
```python
from sentinel.confidence import calculate_tier, TIER_MAP
tier_enum = calculate_tier([watchman_result, cipher_result])
tier_tuple = TIER_MAP[tier_enum]  # (int, str)

from sentinel.source_registry import are_independent
independence = are_independent("watchman", "cipher")

verdict = assemble_verdict(watchman_result, cipher_result, tier_tuple, independence, start_time)
```

### `methodology` and `citations` Shapes

**methodology** — one entry per agent, always 2 entries in v1:
```python
[
    {"agent": "watchman", "status": "success", "error": None},
    {"agent": "cipher",   "status": "error",   "error": "timeout"},
]
```

**citations** — one entry per finding, across all agents:
```python
[
    {"source": "watchman", "finding": "Suspicious outbound connection to known Tor exit node"},
    {"source": "cipher",   "finding": "VirusTotal: 185.220.101.45 flagged by 5 engines as malicious"},
]
```

When agents have no findings (error case), `citations` is `[]`. This is valid and expected.

### mypy Annotations Required

**New function signatures** — both need full annotations (strict mode):
```python
def assemble_verdict(
    watchman_result: AgentResult,
    cipher_result: AgentResult,
    tier: tuple[int, str],
    source_independence_confirmed: bool,
    start_time: float,
) -> VerdictSchema: ...

def print_verdict(verdict: VerdictSchema) -> None: ...
```

**Local variables** — annotate to help mypy:
```python
methodology: list[dict[str, Any]] = [...]
citations: list[dict[str, Any]] = [...]
blind_spots: list[BlindSpot] = [...]
```

Without annotations, mypy may infer `list[dict[str, str | None]]` for `methodology` (because the dict values are `str` and `str | None`). The explicit `list[dict[str, Any]]` annotation is required.

**`tier_int, tier_str = tier`** — mypy infers `int` and `str` from `tuple[int, str]` unpacking. No annotation needed.

**`json.dumps(verdict, indent=2)`** — `verdict` is `VerdictSchema` (TypedDict = dict at runtime). `json.dumps` accepts `Any`. mypy is fine with this.

### test_verdict.py — New Imports Required

The existing `test_verdict.py` imports:
```python
import typing
from sentinel.verdict import AgentResult, BlindSpot, SentinelAgent, VerdictSchema
```

Add these imports (update the import block — do NOT duplicate):
```python
import json
import time
import typing

import pytest

from conftest import make_agent_result
from sentinel.verdict import (
    AgentResult,
    BlindSpot,
    SentinelAgent,
    VerdictSchema,
    assemble_verdict,
    print_verdict,
)
```

All 5 new names (`json`, `time`, `pytest`, `make_agent_result`, `assemble_verdict`, `print_verdict`) must appear in new test code — ruff F401 will fail otherwise.

### test_verdict.py — New Tests (Exact Implementation)

```python
def test_assemble_verdict_investigating_tier() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher", error="timeout")
    verdict = assemble_verdict(watchman, cipher, (1, "Investigating"), False, time.time())
    assert verdict["confidence_tier"] == 1
    assert verdict["verdict"] == "Investigating"
    assert verdict["source_independence_confirmed"] is False


def test_assemble_verdict_probable_tier() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    verdict = assemble_verdict(watchman, cipher, (2, "Probable"), True, time.time())
    assert verdict["confidence_tier"] == 2
    assert verdict["verdict"] == "Probable"
    assert verdict["source_independence_confirmed"] is True


def test_assemble_verdict_blind_spots_always_list() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    verdict = assemble_verdict(watchman, cipher, (2, "Probable"), True, time.time())
    assert isinstance(verdict["blind_spots"], list)


def test_assemble_verdict_blind_spots_merged_from_both_agents() -> None:
    bs1 = BlindSpot(source="watchman", reason="timed out", next_step=None)
    bs2 = BlindSpot(source="cipher", reason="rate limited", next_step=None)
    watchman = make_agent_result(source="watchman", blind_spots=[bs1], error="timeout")
    cipher = make_agent_result(source="cipher", blind_spots=[bs2], error="rate_limited")
    verdict = assemble_verdict(watchman, cipher, (1, "Investigating"), False, time.time())
    assert len(verdict["blind_spots"]) == 2
    sources = {bs["source"] for bs in verdict["blind_spots"]}
    assert sources == {"watchman", "cipher"}


def test_assemble_verdict_json_round_trip() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    verdict = assemble_verdict(watchman, cipher, (2, "Probable"), True, time.time())
    parsed = json.loads(json.dumps(verdict))
    assert parsed["confidence_tier"] == 2
    assert parsed["verdict"] == "Probable"
    assert isinstance(parsed["blind_spots"], list)


def test_print_verdict_goes_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    verdict = assemble_verdict(watchman, cipher, (2, "Probable"), True, time.time())
    print_verdict(verdict)
    captured = capsys.readouterr()
    assert captured.out.strip() != ""
    assert captured.err == ""
    parsed = json.loads(captured.out)
    assert parsed["confidence_tier"] == 2


def test_assemble_verdict_all_fields_present_when_both_agents_fail() -> None:
    bs_w = BlindSpot(source="watchman", reason="timed out", next_step=None)
    bs_c = BlindSpot(source="cipher", reason="timed out", next_step=None)
    watchman = make_agent_result(source="watchman", blind_spots=[bs_w], error="timeout")
    cipher = make_agent_result(source="cipher", blind_spots=[bs_c], error="timeout")
    verdict = assemble_verdict(watchman, cipher, (1, "Investigating"), False, time.time())
    assert verdict["verdict"] == "Investigating"
    assert verdict["confidence_tier"] == 1
    assert isinstance(verdict["blind_spots"], list)
    assert len(verdict["blind_spots"]) == 2
    assert verdict["execution_time_seconds"] >= 0
    assert isinstance(verdict["timestamp"], str)
    assert len(verdict["timestamp"]) > 0
```

### stdout/stderr Discipline — Architecture Rule

From the architecture doc:
> **Rule:** `sys.stdout` is touched only in `verdict.py`. All other modules write to `sys.stderr` or nowhere.

`print_verdict` is the **only** function in the entire codebase that writes to `sys.stdout`. All progress messages, warnings, and debug output everywhere else use `print(..., file=sys.stderr)`. The `capsys` test enforces this at the unit level.

### `execution_time_seconds` and `timestamp` — Test Expectations

**`execution_time_seconds`:** Tests pass `time.time()` as `start_time` and assert `>= 0`. Actual value will be a tiny positive float (near 0 in unit tests). Do NOT assert exact values.

**`timestamp`:** Tests assert `isinstance(verdict["timestamp"], str)` and `len(verdict["timestamp"]) > 0`. Do NOT assert exact ISO string — timezone handling varies by environment.

### Existing `test_verdict.py` — Do NOT Break

Current 7 tests MUST remain passing. They test `BlindSpot`, `AgentResult`, `VerdictSchema` TypedDicts and `SentinelAgent` Protocol — none touch `assemble_verdict`. Adding new tests and new imports must not disturb existing test logic.

**Key risk:** The existing import line `from sentinel.verdict import AgentResult, BlindSpot, SentinelAgent, VerdictSchema` must be expanded (not replaced) to include `assemble_verdict` and `print_verdict`.

### Existing Files — Do NOT Modify

| File | Reason |
|------|--------|
| `src/sentinel/config.py` | Foundation, complete |
| `src/sentinel/source_registry.py` | Complete as of 2.2 |
| `src/sentinel/confidence.py` | Complete as of 2.2 |
| `src/sentinel/watchman.py` | Complete as of 3.1 |
| `src/sentinel/cipher.py` | Complete as of 3.2 |
| `src/sentinel/main.py` | Unchanged until 4.2 |
| `tests/conftest.py` | Complete — fixtures available |
| All prior test files except test_verdict.py | Must remain passing |

### Architecture Compliance Checklist

- [ ] `verdict.py` has ZERO imports from `sentinel.*` — no `from sentinel.confidence import ...`, no `from sentinel.source_registry import ...`
- [ ] New stdlib imports added: `json`, `sys`, `time`, `datetime`, `timezone` — all stdlib, no new dependencies
- [ ] `assemble_verdict` signature: `(watchman_result: AgentResult, cipher_result: AgentResult, tier: tuple[int, str], source_independence_confirmed: bool, start_time: float) -> VerdictSchema`
- [ ] `print_verdict` writes to `sys.stdout` — not `sys.stderr`, not `print()` with no file arg
- [ ] `blind_spots` in returned `VerdictSchema` is always a `list` — flat merge of both agents' blind_spots
- [ ] `execution_time_seconds` is a `float` (from `round(..., 3)`)
- [ ] `timestamp` is a `str` (from `datetime.now(timezone.utc).isoformat()`)
- [ ] `mypy src/` passes 0 errors on all 8 source files

### Previous Story Learnings (from Stories 1.3–3.2)

- **`py -m` prefix** on Windows for all tooling.
- **mypy strict:** all function params and local variables in new functions need explicit type annotations.
- **ruff F401:** all imports in `test_verdict.py` must be used in test code. Count carefully: `json`, `time`, `pytest`, `make_agent_result`, `assemble_verdict`, `print_verdict` — all 6 must appear.
- **TypedDict dict comprehensions:** when using list comprehensions to build `list[dict[str, Any]]`, annotate the variable explicitly — mypy won't infer `Any` correctly without it.
- **41 tests currently passing** — must remain green.

### Project Structure After This Story

```
sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py          ← unchanged
│       ├── main.py              ← unchanged until 4.2
│       ├── verdict.py           ← UPDATED: + assemble_verdict, + print_verdict
│       ├── config.py            ← unchanged
│       ├── source_registry.py   ← unchanged
│       ├── confidence.py        ← unchanged
│       ├── watchman.py          ← unchanged
│       └── cipher.py            ← unchanged
├── tests/
│   ├── conftest.py              ← unchanged
│   ├── test_version.py          ← unchanged
│   ├── test_verdict.py          ← UPDATED: + 7 new tests, + new imports
│   ├── test_config.py           ← unchanged
│   ├── test_source_registry.py  ← unchanged
│   ├── test_confidence.py       ← unchanged
│   ├── test_watchman.py         ← unchanged
│   └── test_cipher.py           ← unchanged
```

### References

- [Source: epics.md#Story 4.1] — acceptance criteria, VerdictSchema field requirements
- [Source: architecture.md#Data Architecture] — VerdictSchema as stable TypedDict, all 8 fields
- [Source: architecture.md#stderr Output Pattern] — sys.stdout only in verdict.py
- [Source: architecture.md#Confidence Tier Pattern] — TIER_MAP maps ConfidenceTier → (int, str)
- [Source: architecture.md#Import Discipline] — verdict.py imports nothing from sentinel.*
- [Source: epics.md#FR21–26] — JSON to stdout, stable schema, parseable output
- [Source: epics.md#AR7] — TIER_MAP in confidence.py; verdict.py reads the resolved (int, str) tuple

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

None — implementation matched Dev Notes exactly, no iteration needed.

### Completion Notes List

- Added 4 stdlib imports to `verdict.py`: `json`, `sys`, `time`, `datetime`/`timezone`
- Implemented `assemble_verdict` — builds `methodology` (2 entries), `citations` (per finding), and `blind_spots` (flat merge from both agents); uses caller-resolved `tier: tuple[int, str]` to avoid circular imports
- Implemented `print_verdict` — sole function in codebase touching `sys.stdout`; uses `json.dumps(verdict, indent=2)`
- Expanded `test_verdict.py` imports; added 7 new tests covering: tier fields, blind_spots always list, merged blind spots, JSON round-trip, stdout purity (capsys), all-8-fields when both agents fail
- 48/48 tests pass; ruff 0 issues; mypy 0 errors on all 8 source files
- `verdict.py` maintains ZERO `sentinel.*` imports — no circular import risk

### File List

- `src/sentinel/verdict.py` (modified)
- `tests/test_verdict.py` (modified)
