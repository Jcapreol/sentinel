# Story 2.1: Source Registry

Status: review

## Story

As a contributor,
I want a clearly defined, extensible registry of independent source categories,
So that I can add a new corroboration source by adding one entry to one dict, and the independence check automatically applies without touching any other logic.

## Acceptance Criteria

1. **Given** `source_registry.py` is implemented, **When** `are_independent("anthropic_claude", "virustotal")` is called, **Then** it returns `True` — they are in different source categories (`llm_behavioral` vs `community_reputation`).

2. **Given** two sources in the same category, **When** `are_independent("virustotal", "virustotal")` is called, **Then** it returns `False` — same category means one independent source, not two.

3. **Given** both VirusTotal and AbuseIPDB are classified, **When** `are_independent("virustotal", "abuseipdb")` is called, **Then** it returns `False` — both are in `community_reputation`, confirming Cipher counts as one independent source regardless of which sub-APIs returned data.

4. **Given** a contributor adds `"shodan": "network_scanning"` to `SOURCE_CATEGORIES`, **When** `are_independent("shodan", "virustotal")` is called, **Then** it returns `True` with no code changes outside `source_registry.py`.

5. **Given** an unknown source name is passed, **When** `are_independent("unknown_source", "virustotal")` is called, **Then** it returns `False` — unknown sources default to dependent (conservative classification).

6. **And** `source_registry.py` imports nothing from `sentinel.*`, and `tests/test_source_registry.py` covers: two independent sources → True, same source → False, same-category different names → False, unknown source → False, new entry extensibility.

## Tasks / Subtasks

- [x] **Task 1: Implement `source_registry.py`** (AC: 1, 2, 3, 4, 5, 6)
  - [x] Create `src/sentinel/source_registry.py` with stdlib-only imports (none required)
  - [x] Define `SOURCE_CATEGORIES: dict[str, str]` with all three initial sources (see Dev Notes — CRITICAL: virustotal and abuseipdb must share a category)
  - [x] Implement `are_independent(source_a: str, source_b: str) -> bool` — returns False when either source is unknown (see Dev Notes for why simple `get()` comparison is insufficient)

- [x] **Task 2: Write `tests/test_source_registry.py`** (AC: 6)
  - [x] Test: `are_independent("anthropic_claude", "virustotal")` → `True`
  - [x] Test: `are_independent("virustotal", "virustotal")` → `False`
  - [x] Test: `are_independent("virustotal", "abuseipdb")` → `False` (same category)
  - [x] Test: unknown source → `False` (conservative)
  - [x] Test: extensibility — add `"shodan": "network_scanning"` → `are_independent("shodan", "virustotal")` is `True`; clean up after

- [x] **Task 3: Verify CI green** (AC: 1–6)
  - [x] `py -m ruff check src/ tests/` — 0 issues
  - [x] `py -m mypy src/` — 0 errors across all 5 source files
  - [x] `py -m pytest tests/ -v` — all tests pass (14 existing + new test_source_registry.py tests)

## Dev Notes

### CRITICAL: Architecture Document Discrepancy

The `architecture.md` data architecture section shows this example:

```python
# architecture.md example — INCORRECT for virustotal category
SOURCE_CATEGORIES: dict[str, str] = {
    "anthropic_claude": "llm_behavioral",
    "virustotal": "threat_intel_aggregator",   # ← wrong
    "abuseipdb": "community_reputation",        # ← wrong
}
```

**This example is inconsistent with AC 3.** The AC explicitly states:
> "returns `False` — both are in `community_reputation`"

The architecture.md example would make `are_independent("virustotal", "abuseipdb")` return `True` (different categories), which contradicts AC 3.

**Correct implementation** — both must share `community_reputation`:

```python
SOURCE_CATEGORIES: dict[str, str] = {
    "anthropic_claude": "llm_behavioral",
    "virustotal": "community_reputation",   # ← same category as abuseipdb
    "abuseipdb": "community_reputation",    # ← same category as virustotal
}
```

**Why this is architecturally correct:** VirusTotal and AbuseIPDB are both community-sourced IP reputation systems. They draw from overlapping reporting communities — a malicious IP is often reported to both by the same security researchers. From a source independence perspective, they are the same data pipeline observed through two lenses. Cipher uses both but they count as ONE independent source (FR6, FR7).

The `architecture.md` example was a typo/draft error. The acceptance criteria in `epics.md` are the authoritative specification.

### CRITICAL: Unknown Source Handling — Simple `get()` Comparison Is Wrong

The naive implementation:

```python
def are_independent(source_a: str, source_b: str) -> bool:
    return SOURCE_CATEGORIES.get(source_a) != SOURCE_CATEGORIES.get(source_b)
```

**Fails AC 5.** When `source_a = "unknown_source"`:
- `SOURCE_CATEGORIES.get("unknown_source")` returns `None`
- `None != "community_reputation"` evaluates to `True`
- Returns `True` (independent) — **WRONG** — unknown sources must return `False` (dependent)

The AC requires conservative classification: if either source is unknown, treat them as dependent. This prevents a new uncategorized source from inflating the confidence tier.

**Correct implementation:**

```python
def are_independent(source_a: str, source_b: str) -> bool:
    cat_a = SOURCE_CATEGORIES.get(source_a)
    cat_b = SOURCE_CATEGORIES.get(source_b)
    if cat_a is None or cat_b is None:
        return False
    return cat_a != cat_b
```

### source_registry.py — Exact Implementation

```python
SOURCE_CATEGORIES: dict[str, str] = {
    "anthropic_claude": "llm_behavioral",
    "virustotal": "community_reputation",
    "abuseipdb": "community_reputation",
}


def are_independent(source_a: str, source_b: str) -> bool:
    cat_a = SOURCE_CATEGORIES.get(source_a)
    cat_b = SOURCE_CATEGORIES.get(source_b)
    if cat_a is None or cat_b is None:
        return False
    return cat_a != cat_b
```

**That is the complete file.** No imports, no classes, no `__all__`, no additional functions.

**Why no imports:** `source_registry.py` is a foundation layer module (same tier as `verdict.py` and `config.py`). It imports nothing from `sentinel.*`. Circular imports are impossible.

**Why a module-level dict, not a class:** Contributors extend by adding one line to `SOURCE_CATEGORIES`. No inheritance, no subclassing, no factory registration pattern. The simplest mechanism that satisfies FR16.

**Why `dict[str, str]`:** mypy strict requires explicit type parameters. `dict` alone is rejected by `--disallow-any-generics`. Both keys and values are always strings — no `Any` needed.

### test_source_registry.py — Exact Implementation

```python
from sentinel.source_registry import SOURCE_CATEGORIES, are_independent


def test_llm_and_threat_intel_are_independent() -> None:
    assert are_independent("anthropic_claude", "virustotal") is True


def test_same_source_is_not_independent() -> None:
    assert are_independent("virustotal", "virustotal") is False


def test_virustotal_and_abuseipdb_same_category() -> None:
    assert are_independent("virustotal", "abuseipdb") is False


def test_unknown_source_returns_false() -> None:
    assert are_independent("unknown_source", "virustotal") is False


def test_anthropic_and_abuseipdb_are_independent() -> None:
    assert are_independent("anthropic_claude", "abuseipdb") is True


def test_new_entry_extensibility() -> None:
    SOURCE_CATEGORIES["shodan"] = "network_scanning"
    try:
        assert are_independent("shodan", "virustotal") is True
        assert are_independent("shodan", "anthropic_claude") is True
        assert are_independent("shodan", "abuseipdb") is True
    finally:
        del SOURCE_CATEGORIES["shodan"]
```

**`test_new_entry_extensibility` design:** Mutates `SOURCE_CATEGORIES` directly — this tests the contributor workflow exactly as described in AC 4. The `try/finally` block ensures cleanup even if an assertion fails, so the dict is never left in a polluted state for other tests. No `monkeypatch` needed because `SOURCE_CATEGORIES` is a plain module-level dict.

**`test_anthropic_and_abuseipdb_are_independent`:** Extra test not in AC but validates the full cross-product. `anthropic_claude` is `llm_behavioral`, `abuseipdb` is `community_reputation` — they are independent. Verifies the category model is symmetric.

**`is True` / `is False` (not `== True`):** Uses identity comparison. `bool` in Python is a singleton; `assert x is True` is stricter than `assert x` because it rejects truthy non-bool returns (e.g., a non-empty string would pass `assert x` but fail `assert x is True`). `are_independent` always returns `bool` — this is just best practice.

### Import Discipline — source_registry.py Position in Hierarchy

```
verdict.py          ← from typing import Any, Protocol, TypedDict  (foundation)
config.py           ← import os; from dataclasses import dataclass  (foundation)
source_registry.py  ← NO IMPORTS AT ALL                            (foundation)
confidence.py       ← imports source_registry (Story 2.2)
watchman.py         ← from sentinel.verdict import ...; from sentinel.config import Config
cipher.py           ← from sentinel.verdict import ...; from sentinel.config import Config
main.py             ← imports all siblings (Story 4.2)
```

`source_registry.py` is the only source module with **zero imports of any kind** — not even stdlib. It defines a dict literal and a two-line function. Any import added to this file is almost certainly a bug.

### Existing Files — Do NOT Modify

| File | Reason |
|------|--------|
| `src/sentinel/__init__.py` | Unchanged since 1.1 |
| `src/sentinel/main.py` | Unchanged until 4.2 |
| `src/sentinel/verdict.py` | Foundation layer, complete as of 1.2 |
| `src/sentinel/config.py` | Foundation layer, complete as of 1.3 |
| `tests/conftest.py` | Shared fixtures, complete as of 1.3 — do NOT modify |
| `tests/test_version.py` | Passes clean |
| `tests/test_verdict.py` | Passes clean |
| `tests/test_config.py` | Passes clean |

### Architecture Compliance Checklist

- [ ] `source_registry.py` has zero imports of any kind (foundation layer — no sentinel.*, no stdlib needed)
- [ ] `SOURCE_CATEGORIES` uses `dict[str, str]` type annotation (mypy strict: no bare `dict`)
- [ ] `virustotal` and `abuseipdb` both map to `"community_reputation"` (AC 3 — critical)
- [ ] `are_independent()` explicitly handles `None` case — does NOT rely on `None != str` being `True` (AC 5 — critical)
- [ ] `are_independent()` return type annotated as `-> bool` (mypy strict: no untyped defs)
- [ ] `mypy src/` passes with 0 errors on all 5 source files
- [ ] `tests/test_source_registry.py` imports `SOURCE_CATEGORIES` directly for the extensibility test

### Previous Story Learnings

- **`py -m` prefix required on Windows** for ruff, mypy, pytest — bare commands not on PATH.
- **mypy strict + bare generics:** `dict` → `dict[str, str]`, `list` → `list[str]`, etc. Any unparametrized generic fails `--disallow-any-generics`.
- **ruff F401 trap:** Import something unused at runtime → F401. For `source_registry.py` this is moot (no imports), but watch for it in `test_source_registry.py` — both `SOURCE_CATEGORIES` and `are_independent` must be used.
- **`conftest.py` is complete** — `fake_config`, `sample_alert`, `make_agent_result` are already available. The source registry tests don't need any of these fixtures (no agents involved), but future stories will use them.
- **14 tests currently passing** — must remain passing after this story.

### Project Structure After This Story

```
sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py        ← unchanged (1.1)
│       ├── main.py            ← unchanged (1.1)
│       ├── verdict.py         ← unchanged (1.2)
│       ├── config.py          ← unchanged (1.3)
│       └── source_registry.py ← NEW: SOURCE_CATEGORIES dict + are_independent()
├── tests/
│   ├── conftest.py            ← unchanged (1.3)
│   ├── test_version.py        ← unchanged (1.1)
│   ├── test_verdict.py        ← unchanged (1.2)
│   ├── test_config.py         ← unchanged (1.3)
│   └── test_source_registry.py ← NEW: 6 independence tests
```

### References

- [Source: epics.md#Story 2.1] — acceptance criteria (authoritative for `virustotal`/`abuseipdb` category)
- [Source: architecture.md#Data Architecture] — SOURCE_CATEGORIES dict pattern, `are_independent()` signature
- [Source: architecture.md#Import Discipline] — foundation layer, no sentinel.* imports
- [Source: architecture.md#Enforcement Summary] — source_registry.py imported by confidence.py only
- [Source: prd.md#FR6, FR7, FR16] — source independence enforcement, registry extensibility

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

### Completion Notes List

- `source_registry.py` is 13 lines including blank lines. Foundation layer confirmed: zero imports of any kind.
- `virustotal` and `abuseipdb` both mapped to `"community_reputation"` — architecture.md example was a draft error; epics.md AC is authoritative.
- Unknown source guard implemented explicitly: `if cat_a is None or cat_b is None: return False` — naive `get()` comparison would return `True` for unknown sources (since `None != "category"`), violating AC 5.
- `dict[str, str]` type annotation satisfies mypy `--disallow-any-generics`.
- Extensibility test mutates `SOURCE_CATEGORIES` directly and cleans up via `try/finally` — tests the contributor workflow exactly as AC 4 describes.
- mypy now checks 5 source files (`__init__.py`, `main.py`, `verdict.py`, `config.py`, `source_registry.py`) — 0 errors.
- All 20 tests pass: 6 new `test_source_registry.py` + 14 prior.

### File List

- `src/sentinel/source_registry.py` (new)
- `tests/test_source_registry.py` (new)
