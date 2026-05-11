# Story 1.3: Config Module & Test Infrastructure

Status: review

## Story

As a developer,
I want environment variable reading and validation isolated in one module and shared test fixtures available to all test files,
so that agents receive a typed `Config` object without touching `os.environ` directly, missing credentials are caught at startup before any API call, and all test files share a consistent set of fixtures.

## Acceptance Criteria

1. **Given** all three env vars (`ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) are set, **When** `config.load()` is called, **Then** a frozen `Config` dataclass is returned with all three keys populated and `timeout_seconds` defaulting to 10.

2. **Given** `SENTINEL_TIMEOUT` is set to `"15"`, **When** `config.load()` is called, **Then** the returned `Config` has `timeout_seconds == 15`.

3. **Given** any one of the three required env vars is absent, **When** `config.load()` is called, **Then** `ConfigError` is raised with a message that names the specific missing variable.

4. **Given** `config.py` is implemented, **When** `mypy src/` runs, **Then** no type errors are reported, and `os.environ` appears in `config.py` only — not in any other module.

5. **Given** `tests/conftest.py` is present, **When** any test file uses its fixtures or imports its factory, **Then** the following are available: `fake_config()` fixture returning `Config` with dummy keys and `timeout_seconds=5`, `sample_alert` fixture returning a realistic security alert string, `make_agent_result(source, findings, blind_spots, error)` factory returning a valid `AgentResult`.

6. **And** `tests/test_config.py` passes for: all 3 vars present → Config with correct values, `SENTINEL_TIMEOUT="15"` → `timeout_seconds=15`, each of the 3 missing-var scenarios raises `ConfigError` naming the specific variable, `SENTINEL_TIMEOUT` not set → defaults to 10.

## Tasks / Subtasks

- [x] **Task 1: Implement `config.py`** (AC: 1, 2, 3, 4)
  - [x] Create `src/sentinel/config.py` with stdlib-only imports (`dataclasses`, `os`)
  - [x] Define `ConfigError(Exception)` — custom exception, no extra fields
  - [x] Define `Config` as a `@dataclass(frozen=True)` with 4 fields (see Dev Notes)
  - [x] Implement `load() -> Config` — reads the 3 required env vars, parses `SENTINEL_TIMEOUT`, raises `ConfigError` naming the specific missing var

- [x] **Task 2: Create `tests/conftest.py`** (AC: 5)
  - [x] Add `fake_config()` fixture — returns `Config` with dummy keys and `timeout_seconds=5`
  - [x] Add `sample_alert` fixture — returns the canonical realistic alert string
  - [x] Add `make_agent_result()` plain factory function (not a fixture) with all 4 optional params typed

- [x] **Task 3: Write `tests/test_config.py`** (AC: 6)
  - [x] Test: all 3 vars present + no `SENTINEL_TIMEOUT` → `Config` with correct values and `timeout_seconds=10`
  - [x] Test: `SENTINEL_TIMEOUT="15"` → `timeout_seconds == 15`
  - [x] Test: missing `ANTHROPIC_API_KEY` → `ConfigError` message contains `"ANTHROPIC_API_KEY"`
  - [x] Test: missing `VIRUSTOTAL_API_KEY` → `ConfigError` message contains `"VIRUSTOTAL_API_KEY"`
  - [x] Test: missing `ABUSEIPDB_API_KEY` → `ConfigError` message contains `"ABUSEIPDB_API_KEY"`
  - [x] Test: `Config` is frozen — assigning a field raises `FrozenInstanceError`

- [x] **Task 4: Verify CI green** (AC: 4)
  - [x] `py -m ruff check src/ tests/` — 0 issues
  - [x] `py -m mypy src/` — 0 errors across all 4 source files
  - [x] `py -m pytest tests/ -v` — all tests pass (8 existing + new test_config.py tests)

## Dev Notes

### config.py — Exact Implementation

```python
import os
from dataclasses import dataclass


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    anthropic_api_key: str
    virustotal_api_key: str
    abuseipdb_api_key: str
    timeout_seconds: int = 10


def load() -> Config:
    missing = [
        var
        for var in ("ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")
        if not os.environ.get(var)
    ]
    if missing:
        raise ConfigError(f"Missing required environment variable: {missing[0]}")

    timeout_raw = os.environ.get("SENTINEL_TIMEOUT")
    timeout = int(timeout_raw) if timeout_raw else 10

    return Config(
        anthropic_api_key=os.environ["ANTHROPIC_API_KEY"],
        virustotal_api_key=os.environ["VIRUSTOTAL_API_KEY"],
        abuseipdb_api_key=os.environ["ABUSEIPDB_API_KEY"],
        timeout_seconds=timeout,
    )
```

**Why `frozen=True`:** Agents receive `Config` in `__init__` and must not mutate it. Frozen dataclass makes mutation a runtime `FrozenInstanceError`. Mypy also enforces immutability at type-check time.

**Why raise on the first missing var only:** The AC says "raises `ConfigError` with a message that names the specific missing variable" — singular. Listing multiple missing vars in one message would pass the test but is a different UX. The loop finds the first absent var and raises immediately.

**Why `not os.environ.get(var)`:** `os.environ.get(var)` returns `None` if absent or `""` if set to empty string. `not ""` is `True`, so an empty-string env var is treated as unset (same as absent). This prevents a confusing half-configured state.

**`os.environ` rule (AR3):** This is the ONLY file in the codebase that reads `os.environ`. Any occurrence of `os.environ` outside `config.py` is a bug. This rule applies to all future stories.

### conftest.py — Exact Implementation

```python
import pytest

from sentinel.config import Config
from sentinel.verdict import AgentResult, BlindSpot


@pytest.fixture
def fake_config() -> Config:
    return Config(
        anthropic_api_key="test-anthropic-key",
        virustotal_api_key="test-virustotal-key",
        abuseipdb_api_key="test-abuseipdb-key",
        timeout_seconds=5,
    )


@pytest.fixture
def sample_alert() -> str:
    return "Unusual outbound traffic to 185.220.101.45 on port 443 from prod-db-01"


def make_agent_result(
    source: str = "watchman",
    findings: list[str] | None = None,
    blind_spots: list[BlindSpot] | None = None,
    error: str | None = None,
) -> AgentResult:
    return AgentResult(
        source_name=source,
        findings=findings or [],
        blind_spots=blind_spots or [],
        raw_confidence=None if error else "Probable",
        error=error,
    )
```

**`make_agent_result` is a plain function, not a fixture.** Fixtures inject values via pytest's mechanism; a factory function is called explicitly in tests to create `AgentResult` instances with controlled state. Test files that need it do: `from conftest import make_agent_result`.

**`sample_alert` IP:** `185.220.101.45` is a known Tor exit node — realistic for security testing without using a real incident IP. This is the same alert used in the architecture's data flow example.

**`timeout_seconds=5` in `fake_config`:** Faster than the production default of 10s. Tests that mock agents don't actually wait, but 5s provides a tighter budget for any tests that do real timing.

**`blind_spots or []` type:** The `or []` pattern returns `list[BlindSpot]` when `blind_spots` is `None`. mypy infers this correctly from the parameter annotation `list[BlindSpot] | None`.

### test_config.py — Implementation Guide

```python
import pytest

from sentinel.config import Config, ConfigError, load


def test_all_vars_present_default_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.delenv("SENTINEL_TIMEOUT", raising=False)

    config = load()

    assert config.anthropic_api_key == "ak-test"
    assert config.virustotal_api_key == "vt-test"
    assert config.abuseipdb_api_key == "ab-test"
    assert config.timeout_seconds == 10


def test_sentinel_timeout_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.setenv("SENTINEL_TIMEOUT", "15")

    config = load()

    assert config.timeout_seconds == 15


def test_missing_anthropic_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")

    with pytest.raises(ConfigError, match="ANTHROPIC_API_KEY"):
        load()


def test_missing_virustotal_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")

    with pytest.raises(ConfigError, match="VIRUSTOTAL_API_KEY"):
        load()


def test_missing_abuseipdb_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    with pytest.raises(ConfigError, match="ABUSEIPDB_API_KEY"):
        load()


def test_config_is_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    monkeypatch.delenv("SENTINEL_TIMEOUT", raising=False)

    from dataclasses import FrozenInstanceError

    config = load()
    with pytest.raises(FrozenInstanceError):
        config.anthropic_api_key = "mutated"  # type: ignore[misc]
```

**`monkeypatch.delenv("VAR", raising=False)`:** The `raising=False` argument prevents an error if the var isn't in the environment at all. Always use it for cleanup — test environments may or may not have these vars set.

**`# type: ignore[misc]`** on the frozen mutation attempt: mypy correctly flags `config.anthropic_api_key = "mutated"` as an error on a frozen dataclass. The ignore suppresses the mypy error so the test can run and verify the runtime behavior.

**`FrozenInstanceError` import:** Available in `dataclasses` module since Python 3.11. For Python 3.10, the equivalent is `dataclasses.FrozenInstanceError` — same name, same module. This is fine for our `>=3.10` target.

### Import Discipline — `config.py` Position in Hierarchy

```
verdict.py        ← from typing import Any, Protocol, TypedDict  (foundation)
config.py         ← import os; from dataclasses import dataclass  (foundation)
source_registry.py ← (Story 2.1, imports nothing from sentinel.*)
confidence.py     ← imports source_registry (Story 2.2)
watchman.py       ← from sentinel.verdict import ...; from sentinel.config import Config
cipher.py         ← from sentinel.verdict import ...; from sentinel.config import Config
main.py           ← imports all siblings (Story 4.2)
```

`config.py` and `verdict.py` are both foundation-layer modules — neither imports from the other. They form independent roots that agents import from.

**Do NOT import `verdict.py` types into `config.py`.** `Config` is not a TypedDict and doesn't need types from `verdict.py`. Any such import would create a circular dependency later.

### Existing Files — Do NOT Modify

| File | Reason |
|------|--------|
| `src/sentinel/__init__.py` | Unchanged since 1.1 |
| `src/sentinel/main.py` | Imports `config.py` in Story 4.2 — untouched now |
| `src/sentinel/verdict.py` | Foundation layer, complete as of 1.2 |
| `tests/test_version.py` | Passes clean, no changes needed |
| `tests/test_verdict.py` | Passes clean, no changes needed |

**`main.py` note:** Story 4.2 will add `from sentinel.config import Config, ConfigError, load` to `main.py`. Do not add it now. `main.py` is a pure argparse scaffold at this point.

### Architecture Compliance Checklist

- [ ] `config.py` imports only stdlib: `os`, `dataclasses` — no `sentinel.*` imports (AR3)
- [ ] `os.environ` appears in `config.py` ONLY — enforced across all source files (AR3)
- [ ] `Config` is `@dataclass(frozen=True)` — not a TypedDict, not a plain class (AR3)
- [ ] `Config` has exactly 4 fields: `anthropic_api_key`, `virustotal_api_key`, `abuseipdb_api_key`, `timeout_seconds` (AR4)
- [ ] `ConfigError` subclasses `Exception` with no extra fields
- [ ] `load()` raises `ConfigError` naming the specific missing variable (AC: 3)
- [ ] `mypy src/` passes with 0 errors on all 4 source files

### Previous Story Learnings

- **ruff F401 trap:** Import something and not use it at runtime triggers F401. Pattern: if a Protocol or type is only used in a type annotation, annotate a variable with it to make it runtime-visible (e.g. `agent: SentinelAgent = MockAgent()`).
- **`py -m` prefix required on Windows** for ruff, mypy, pytest — bare commands not on PATH.
- **mypy strict + `# type: ignore[misc]`** is the right pattern for intentionally testing type-system-enforced behaviors at runtime (e.g. mutating a frozen dataclass).
- **`monkeypatch.delenv(..., raising=False)`** — always use `raising=False` when cleaning up env vars in tests; the var may or may not exist in CI.

### Project Structure After This Story

```
sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py        ← unchanged (1.1)
│       ├── main.py            ← unchanged (1.1)
│       ├── verdict.py         ← unchanged (1.2)
│       └── config.py          ← NEW: Config dataclass, load(), ConfigError
├── tests/
│   ├── conftest.py            ← NEW: fake_config, sample_alert, make_agent_result
│   ├── test_version.py        ← unchanged (1.1)
│   ├── test_verdict.py        ← unchanged (1.2)
│   └── test_config.py         ← NEW: 6 config tests
```

### References

- [Source: architecture.md#Authentication & Security] — Config frozen dataclass, `load()`, `ConfigError`, startup validation sequence
- [Source: architecture.md#Config Injection Pattern] — `Config` shape, `os.environ` in `config.py` only
- [Source: architecture.md#Project Structure] — `conftest.py` location, shared fixture definitions
- [Source: architecture.md#Shared Test Fixtures] — exact `fake_config`, `sample_alert`, `make_agent_result` implementations
- [Source: architecture.md#Test Mock Pattern] — `pytest-mock` for agent mocking (Stories 3.x); `monkeypatch` for env vars (this story)
- [Source: epics.md#Story 1.3] — acceptance criteria, missing-var error message requirement
- [Source: architecture.md#Enforcement Summary] — `os.environ` rule applies to all modules

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

- ruff F401: `Config` imported but unused in `test_config.py` — fixed by removing `Config` from the import. Tests use `load()` to get back a `Config` instance; no test directly references the `Config` name, so the import was unnecessary.

### Completion Notes List

- `config.py` is 33 lines including blank lines. Foundation layer confirmed: only `import os` and `from dataclasses import dataclass`.
- `frozen=True` enforced at runtime — `test_config_is_frozen` verifies `FrozenInstanceError` on mutation attempt; `# type: ignore[misc]` suppresses the correct mypy error on the frozen assignment line.
- `os.environ` rule (AR3) satisfied — `os.environ` appears only in `config.py` across all 4 source files.
- `conftest.py` uses plain function `make_agent_result()` (not a fixture) per spec. Imports `BlindSpot` from `sentinel.verdict` for the type annotation.
- `monkeypatch.delenv(..., raising=False)` used on all env var cleanup — safe whether or not the var exists in CI.
- mypy now checks 4 source files (`__init__.py`, `main.py`, `verdict.py`, `config.py`) — 0 errors.
- All 14 tests pass: 6 new `test_config.py` tests + 7 `test_verdict.py` (1.2) + 1 `test_version.py` (1.1).

### File List

- `src/sentinel/config.py` (new)
- `tests/conftest.py` (new)
- `tests/test_config.py` (new)
