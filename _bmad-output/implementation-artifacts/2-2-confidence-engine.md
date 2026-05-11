# Story 2.2: Confidence Engine

Status: review

## Story

As an analyst,
I want SENTINEL to map the count of independent corroborating sources to a human-readable confidence tier,
So that I know immediately whether to investigate further, escalate, or act — without interpreting opaque ML percentages.

## Acceptance Criteria

1. **Given** results from one independent source only, **When** `calculate_tier([watchman_result])` is called, **Then** it returns `ConfidenceTier.INVESTIGATING`.

2. **Given** results from two independent sources (Watchman + Cipher), **When** `calculate_tier([watchman_result, cipher_result])` is called with `are_independent` confirming independence, **Then** it returns `ConfidenceTier.PROBABLE`.

3. **Given** results from three or more independent sources, **When** `calculate_tier([...])` is called, **Then** it returns `ConfidenceTier.CONFIRMED`.

4. **Given** `ConfidenceTier` is defined as an `Enum`, **When** its members are inspected, **Then** `ConfidenceTier.INVESTIGATING.value == "Investigating"`, `ConfidenceTier.PROBABLE.value == "Probable"`, `ConfidenceTier.CONFIRMED.value == "Confirmed"`.

5. **Given** `TIER_MAP` is defined in `confidence.py`, **When** `TIER_MAP[ConfidenceTier.PROBABLE]` is accessed, **Then** it returns `(2, "Probable")` — the `(int, str)` tuple used to populate `confidence_tier` and `verdict` in `VerdictSchema`.

6. **Given** an agent result with `error` set, **When** `count_independent_sources([watchman_result, failed_cipher_result])` is called, **Then** the failed agent is excluded from the independence count — only successful results contribute to corroboration.

7. **And** `confidence.py` imports only from `source_registry` and `verdict`, and `tests/test_confidence.py` covers: 0 sources, 1 source, 2 independent sources, 2 dependent sources (counts as 1), 3+ sources, failed agent excluded from count.

## Tasks / Subtasks

- [x] **Task 1: Extend `source_registry.py` with agent-level source names** (AC: 1, 2, 6)
  - [x] Add `"watchman": "llm_behavioral"` to `SOURCE_CATEGORIES` (see Dev Notes — CRITICAL: agents use source_name "watchman"/"cipher", not "anthropic_claude"/"virustotal")
  - [x] Add `"cipher": "community_reputation"` to `SOURCE_CATEGORIES`

- [x] **Task 2: Implement `confidence.py`** (AC: 1–6)
  - [x] Create `src/sentinel/confidence.py` importing only `from enum import Enum`, `from sentinel.source_registry import SOURCE_CATEGORIES`, `from sentinel.verdict import AgentResult`
  - [x] Define `ConfidenceTier(Enum)` with 3 members: `INVESTIGATING = "Investigating"`, `PROBABLE = "Probable"`, `CONFIRMED = "Confirmed"`
  - [x] Define `TIER_MAP: dict[ConfidenceTier, tuple[int, str]]` mapping each tier to `(int, str)` tuple
  - [x] Implement `count_independent_sources(results: list[AgentResult]) -> int` — category-set approach (see Dev Notes)
  - [x] Implement `calculate_tier(results: list[AgentResult]) -> ConfidenceTier` — maps count to tier

- [x] **Task 3: Write `tests/test_confidence.py`** (AC: 7)
  - [x] Test: `ConfidenceTier` enum values match strings exactly
  - [x] Test: `TIER_MAP` values are correct `(int, str)` tuples for all 3 tiers
  - [x] Test: `calculate_tier([])` → `INVESTIGATING` (zero sources)
  - [x] Test: `calculate_tier([watchman_result])` → `INVESTIGATING` (one source)
  - [x] Test: `calculate_tier([watchman_result, cipher_result])` → `PROBABLE` (two independent)
  - [x] Test: `calculate_tier([virustotal_result, abuseipdb_result])` → `INVESTIGATING` (two dependent, same category)
  - [x] Test: `calculate_tier([watchman, cipher, shodan])` → `CONFIRMED` (three independent — uses temporary SOURCE_CATEGORIES entry)
  - [x] Test: failed agent excluded from `count_independent_sources`

- [x] **Task 4: Verify CI green** (AC: all)
  - [x] `py -m ruff check src/ tests/` — 0 issues
  - [x] `py -m mypy src/` — 0 errors across all 6 source files
  - [x] `py -m pytest tests/ -v` — all tests pass (20 existing + new test_confidence.py tests)

## Dev Notes

### CRITICAL: Agent source_name Mismatch — source_registry.py MUST Be Extended

`count_independent_sources` looks up each `AgentResult.source_name` in `SOURCE_CATEGORIES` to get its category. Currently `SOURCE_CATEGORIES` contains:

```python
{
    "anthropic_claude": "llm_behavioral",
    "virustotal": "community_reputation",
    "abuseipdb": "community_reputation",
}
```

But Story 3.1 (Watchman) and 3.2 (Cipher) agents return:
- `source_name = "watchman"`
- `source_name = "cipher"`

These keys do NOT exist in `SOURCE_CATEGORIES`. `SOURCE_CATEGORIES.get("watchman")` returns `None` → not counted as an independent source → `count_independent_sources([watchman_result, cipher_result])` returns `0` → `calculate_tier` returns `INVESTIGATING` for two successful agents.

**Fix:** Task 1 adds the agent-level names to the registry. This is the correct use of the extensible registry pattern — agents register themselves by their `source_name`:

```python
SOURCE_CATEGORIES: dict[str, str] = {
    "anthropic_claude": "llm_behavioral",
    "watchman": "llm_behavioral",          # ← add in Task 1
    "virustotal": "community_reputation",
    "abuseipdb": "community_reputation",
    "cipher": "community_reputation",      # ← add in Task 1
}
```

The pre-existing `"anthropic_claude"`, `"virustotal"`, `"abuseipdb"` entries remain — they are tested by Story 2.1 tests and are valid registry entries for direct API-level source lookups in future stories.

### confidence.py — Exact Implementation

```python
from enum import Enum

from sentinel.source_registry import SOURCE_CATEGORIES
from sentinel.verdict import AgentResult


class ConfidenceTier(Enum):
    INVESTIGATING = "Investigating"
    PROBABLE = "Probable"
    CONFIRMED = "Confirmed"


TIER_MAP: dict[ConfidenceTier, tuple[int, str]] = {
    ConfidenceTier.INVESTIGATING: (1, "Investigating"),
    ConfidenceTier.PROBABLE: (2, "Probable"),
    ConfidenceTier.CONFIRMED: (3, "Confirmed"),
}


def count_independent_sources(results: list[AgentResult]) -> int:
    categories: set[str] = set()
    for result in results:
        if result["error"] is None:
            cat = SOURCE_CATEGORIES.get(result["source_name"])
            if cat is not None:
                categories.add(cat)
    return len(categories)


def calculate_tier(results: list[AgentResult]) -> ConfidenceTier:
    count = count_independent_sources(results)
    if count >= 3:
        return ConfidenceTier.CONFIRMED
    if count >= 2:
        return ConfidenceTier.PROBABLE
    return ConfidenceTier.INVESTIGATING
```

**Why category-set counting (not pairwise `are_independent`):** Counting unique categories in a `set[str]` is O(n) and handles degenerate cases correctly. Pairwise comparison requires O(n²) checks and becomes a graph-coloring problem with 3+ sources. The category-set approach is equivalent and simpler — two sources are independent iff they belong to different categories, which is exactly what unique category counting measures.

**Why `categories: set[str]` annotation:** mypy strict (`--disallow-any-generics`) rejects bare `set`. The explicit `set[str]` annotation is required.

**Why `tuple[int, str]` not `Tuple[int, str]`:** Python 3.10+ supports built-in generic aliases. `tuple[int, str]` is correct; `typing.Tuple` is not needed.

**Why `calculate_tier` with two `if` (not `if/elif/else`):** The second `if count >= 2` is only reached when `count < 3`, so it's equivalent to `elif`. The flat `if/return` style avoids nesting and satisfies ruff's style checks.

**Why `AgentResult` is imported from `sentinel.verdict`:** Required for the `list[AgentResult]` parameter annotation. mypy strict enforces all function parameters are typed.

**Import hierarchy compliance:**
```
verdict.py          ← foundation (no sentinel.* imports)
config.py           ← foundation (no sentinel.* imports)
source_registry.py  ← foundation (no imports at all)
confidence.py       ← logic layer: imports source_registry + verdict ONLY  ← THIS FILE
watchman.py         ← logic layer: imports verdict + config
cipher.py           ← logic layer: imports verdict + config
main.py             ← orchestration: imports all siblings
```

`confidence.py` must NEVER import from `config.py`, `watchman.py`, `cipher.py`, or `main.py`. It knows nothing about agents — it only processes `AgentResult` values that are passed to it.

### source_registry.py — Updated Full File

After Task 1, the complete file reads:

```python
SOURCE_CATEGORIES: dict[str, str] = {
    "anthropic_claude": "llm_behavioral",
    "watchman": "llm_behavioral",
    "virustotal": "community_reputation",
    "abuseipdb": "community_reputation",
    "cipher": "community_reputation",
}


def are_independent(source_a: str, source_b: str) -> bool:
    cat_a = SOURCE_CATEGORIES.get(source_a)
    cat_b = SOURCE_CATEGORIES.get(source_b)
    if cat_a is None or cat_b is None:
        return False
    return cat_a != cat_b
```

All 6 Story 2.1 tests continue to pass after this addition — the new entries don't affect the existing keys or the `are_independent` logic.

### test_confidence.py — Exact Implementation

```python
from conftest import make_agent_result
from sentinel.confidence import (
    ConfidenceTier,
    TIER_MAP,
    calculate_tier,
    count_independent_sources,
)
from sentinel.source_registry import SOURCE_CATEGORIES


def test_confidence_tier_enum_values() -> None:
    assert ConfidenceTier.INVESTIGATING.value == "Investigating"
    assert ConfidenceTier.PROBABLE.value == "Probable"
    assert ConfidenceTier.CONFIRMED.value == "Confirmed"


def test_tier_map_values() -> None:
    assert TIER_MAP[ConfidenceTier.INVESTIGATING] == (1, "Investigating")
    assert TIER_MAP[ConfidenceTier.PROBABLE] == (2, "Probable")
    assert TIER_MAP[ConfidenceTier.CONFIRMED] == (3, "Confirmed")


def test_zero_sources_investigating() -> None:
    assert calculate_tier([]) == ConfidenceTier.INVESTIGATING


def test_one_source_investigating() -> None:
    result = make_agent_result(source="watchman")
    assert calculate_tier([result]) == ConfidenceTier.INVESTIGATING


def test_two_independent_sources_probable() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    assert calculate_tier([watchman, cipher]) == ConfidenceTier.PROBABLE


def test_two_dependent_sources_counts_as_one() -> None:
    vt = make_agent_result(source="virustotal")
    ab = make_agent_result(source="abuseipdb")
    assert calculate_tier([vt, ab]) == ConfidenceTier.INVESTIGATING


def test_three_or_more_sources_confirmed() -> None:
    SOURCE_CATEGORIES["shodan"] = "network_scanning"
    try:
        watchman = make_agent_result(source="watchman")
        cipher = make_agent_result(source="cipher")
        shodan = make_agent_result(source="shodan")
        assert calculate_tier([watchman, cipher, shodan]) == ConfidenceTier.CONFIRMED
    finally:
        del SOURCE_CATEGORIES["shodan"]


def test_failed_agent_excluded_from_count() -> None:
    watchman = make_agent_result(source="watchman")
    failed_cipher = make_agent_result(source="cipher", error="timeout")
    assert count_independent_sources([watchman, failed_cipher]) == 1
    assert calculate_tier([watchman, failed_cipher]) == ConfidenceTier.INVESTIGATING


def test_count_independent_sources_two_independent() -> None:
    watchman = make_agent_result(source="watchman")
    cipher = make_agent_result(source="cipher")
    assert count_independent_sources([watchman, cipher]) == 2


def test_count_independent_sources_same_category() -> None:
    vt = make_agent_result(source="virustotal")
    ab = make_agent_result(source="abuseipdb")
    assert count_independent_sources([vt, ab]) == 1
```

**`from conftest import make_agent_result` (not a fixture):** `make_agent_result` is a plain factory function defined in `conftest.py`. It is NOT a pytest fixture — test functions import and call it directly. This pattern was established in Story 1.3 and is the correct usage.

**`try/finally` in `test_three_or_more_sources_confirmed`:** Mutates `SOURCE_CATEGORIES` directly to add a third independent source — exactly the contributor extensibility pattern from Story 2.1. `try/finally` ensures cleanup even if an assertion fails.

**No `import pytest`:** None of these tests use `pytest.raises`, `pytest.mark`, or `MonkeyPatch`. The `import pytest` line would be flagged by ruff F401 (unused import). Only add it if a fixture parameter annotation is needed.

### mypy Considerations

`dict[ConfidenceTier, tuple[int, str]]` — both `dict` and `tuple` must have explicit type parameters (mypy strict `--disallow-any-generics`). ✓

`set[str]` in `count_independent_sources` — must be annotated explicitly. The inline declaration `categories: set[str] = set()` satisfies this. ✓

`list[AgentResult]` in both function signatures — `AgentResult` is imported from `sentinel.verdict`. ✓

`ConfidenceTier` is an `Enum` subclass — mypy handles this correctly; no special annotation needed beyond `from enum import Enum`.

### Existing Files — Do NOT Modify (except source_registry.py — Task 1 only)

| File | Action |
|------|--------|
| `src/sentinel/__init__.py` | Leave unchanged |
| `src/sentinel/main.py` | Leave unchanged |
| `src/sentinel/verdict.py` | Leave unchanged |
| `src/sentinel/config.py` | Leave unchanged |
| `src/sentinel/source_registry.py` | **Add 2 entries only** (Task 1) — do NOT change existing entries or `are_independent()` |
| `tests/conftest.py` | Leave unchanged |
| `tests/test_source_registry.py` | Leave unchanged — all 6 tests must still pass after Task 1 |

### Architecture Compliance Checklist

- [ ] `source_registry.py` updated: `"watchman": "llm_behavioral"` and `"cipher": "community_reputation"` added
- [ ] All 6 `test_source_registry.py` tests still pass after the source_registry update
- [ ] `confidence.py` imports only `enum` (stdlib), `sentinel.source_registry`, and `sentinel.verdict`
- [ ] `ConfidenceTier` uses string values (`"Investigating"`, `"Probable"`, `"Confirmed"`) — not raw ints
- [ ] `TIER_MAP` is `dict[ConfidenceTier, tuple[int, str]]` — explicit type parameters (mypy strict)
- [ ] `count_independent_sources` uses `set[str]` annotation — explicit (mypy strict)
- [ ] `calculate_tier` handles 0 results → `INVESTIGATING` (empty list edge case)
- [ ] No raw tier string literals (`"Investigating"` etc.) appear outside `confidence.py`
- [ ] `mypy src/` passes with 0 errors on all 6 source files

### Previous Story Learnings

- **`py -m` prefix** required on Windows for all tooling.
- **mypy strict generics:** all collections need explicit type parameters — `dict[K, V]`, `set[T]`, `list[T]`, `tuple[A, B]`.
- **ruff F401:** every imported name must be used at runtime. In `test_confidence.py`, both `SOURCE_CATEGORIES` and `make_agent_result` must be used; all four imports from `sentinel.confidence` must be used.
- **`try/finally` for SOURCE_CATEGORIES mutations** — established pattern from `test_source_registry.py::test_new_entry_extensibility`. Always clean up temporary registry entries.
- **`from conftest import make_agent_result`** — plain function, imported directly. NOT a fixture. This pattern is established and working.
- **20 tests currently passing** — all must remain green.

### Project Structure After This Story

```
sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py          ← unchanged (1.1)
│       ├── main.py              ← unchanged (1.1)
│       ├── verdict.py           ← unchanged (1.2)
│       ├── config.py            ← unchanged (1.3)
│       ├── source_registry.py   ← MODIFIED: +2 agent-level entries (2.1 base)
│       └── confidence.py        ← NEW: ConfidenceTier enum, TIER_MAP, count/calculate functions
├── tests/
│   ├── conftest.py              ← unchanged (1.3)
│   ├── test_version.py          ← unchanged (1.1)
│   ├── test_verdict.py          ← unchanged (1.2)
│   ├── test_config.py           ← unchanged (1.3)
│   ├── test_source_registry.py  ← unchanged (2.1) — all 6 tests still pass
│   └── test_confidence.py       ← NEW: 9 confidence engine tests
```

### References

- [Source: epics.md#Story 2.2] — acceptance criteria, ConfidenceTier enum values, TIER_MAP spec
- [Source: architecture.md#Confidence Tier Pattern] — Enum definition, no raw string literals rule
- [Source: architecture.md#Decision Impact Analysis — Issue 3] — `TIER_MAP` definition, `(int, str)` tuple mapping
- [Source: architecture.md#Import Discipline] — logic layer: confidence imports source_registry + verdict only
- [Source: prd.md#FR8, FR9] — confidence tier tied to independent source count; human-readable labels

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

### Completion Notes List

- `source_registry.py` extended with `"watchman": "llm_behavioral"` and `"cipher": "community_reputation"` — all 6 Story 2.1 tests continue to pass unchanged.
- `confidence.py` is 31 lines including blank lines. Imports: `enum` (stdlib), `sentinel.source_registry`, `sentinel.verdict` — logic layer confirmed.
- Category-set approach (`set[str]`) for `count_independent_sources` — O(n), handles 0/1/2/3+ sources and same-category deduplication correctly.
- `TIER_MAP: dict[ConfidenceTier, tuple[int, str]]` — explicit type parameters satisfy mypy `--disallow-any-generics`.
- `calculate_tier([])` → `INVESTIGATING` — empty list edge case handled by `count` = 0 falling through to the final `return`.
- `try/finally` in `test_three_or_more_sources_confirmed` — cleans up temporary `"shodan"` entry even on assertion failure.
- mypy now checks 6 source files (`__init__.py`, `main.py`, `verdict.py`, `config.py`, `source_registry.py`, `confidence.py`) — 0 errors.
- All 30 tests pass: 10 new `test_confidence.py` + 20 prior.

### File List

- `src/sentinel/source_registry.py` (modified — 2 entries added)
- `src/sentinel/confidence.py` (new)
- `tests/test_confidence.py` (new)
