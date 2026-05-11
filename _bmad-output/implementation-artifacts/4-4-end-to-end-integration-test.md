# Story 4.4: End-to-End Integration Test

Status: ready-for-dev

## Story

As a developer,
I want a full pipeline integration test that exercises every module together with mocked external APIs,
So that I can verify the complete analysis flow — from raw input to final JSON — and catch any wiring errors that unit tests miss.

## Acceptance Criteria

1. **Given** mocked Watchman (successful) and mocked Cipher (successful), **When** `main()` is called with a sample alert as a positional argument, **Then** stdout is valid JSON with all 8 `VerdictSchema` fields, `confidence_tier` is 2 (Probable), `source_independence_confirmed` is `True`, exit code is 0, and `execution_time_seconds` is a positive float.

2. **Given** mocked Watchman times out and mocked Cipher succeeds, **When** `main()` is called, **Then** stdout JSON has `confidence_tier` of 1 (Investigating), `blind_spots` contains one entry for Watchman, exit code is 0, and `execution_time_seconds` is a positive float.

3. **Given** both agents are mocked to fail, **When** `main()` is called, **Then** stdout JSON has `confidence_tier` of 1 (Investigating), `blind_spots` contains entries for both agents, exit code is 0, and `execution_time_seconds` is a positive float.

4. **Given** no input is provided, **When** `main()` is called, **Then** nothing is written to stdout, a usage message is written to stderr, and exit code is 2.

5. **Given** `ANTHROPIC_API_KEY` is not set, **When** `main()` is called, **Then** nothing is written to stdout, an error naming the missing variable is written to stderr, and exit code is 2.

**And** stdout and stderr are captured separately in all test cases — stdout purity (clean JSON only) is verified explicitly in every integration test.

## Tasks / Subtasks

- [ ] **Task 1: Create `tests/test_integration.py`** (AC: 1–5)
  - [ ] Test 1: both agents succeed → all 8 VerdictSchema fields present, tier=2/Probable/independence=True, exit 0
  - [ ] Test 2: Watchman times out, Cipher succeeds → tier=1/Investigating, one blind_spot for watchman, exit 0
  - [ ] Test 3: both agents fail → tier=1/Investigating, two blind_spots with both sources, exit 0
  - [ ] Test 4: no input → exit 2, stdout empty, stderr non-empty
  - [ ] Test 5: ANTHROPIC_API_KEY missing → exit 2, stdout empty, "ANTHROPIC_API_KEY" in stderr
  - [ ] Every test: assert `captured.out == ""` OR `json.loads(captured.out)` — never mixed content on stdout

- [ ] **Task 2: Verify CI green** (AC: all)
  - [ ] `py -m pytest tests/ -v` — all 55 existing tests pass + 5 new integration tests (60 total)
  - [ ] `py -m ruff check src/ tests/` — 0 issues (test_integration.py uses all its imports)
  - [ ] `py -m mypy src/` — 0 errors (no new src/ files; test files are not mypy-checked by default)

## Dev Notes

### Dependency: Story 4.2 Must Be Complete First

**These integration tests call `main()` from the fully-implemented `sentinel.main` module.** If Story 4.2 is not yet done (i.e., `main.py` still contains only the scaffold "Not yet implemented." exit), every integration test will fail with exit code 1 and an empty stdout — no fixture or mock can fix this.

**Before running these tests:** verify `py -m pytest tests/test_main.py -v` shows 7 passing tests. If not, implement Story 4.2 first.

### What Makes These Integration Tests Different from Story 4.2 Unit Tests

Story 4.2 unit tests (`tests/test_main.py`) verify **orchestration wiring**: correct exit codes, correct call targets, correct call arguments. They mock aggressively at the `sentinel.main.*` namespace.

Story 4.4 integration tests (`tests/test_integration.py`) verify **pipeline output**: every module runs together, the full JSON schema is correct, all 8 fields are present, field values reflect the actual confidence engine and verdict assembly logic. The mocking strategy is identical — we still mock `WatchmanAgent` and `CipherAgent` at `sentinel.main.*` to avoid real API calls — but the assertions focus on the complete output rather than call patterns.

**Key difference in assertions:**
- 4.2: `assert exc.value.code == 0` + `assert result["confidence_tier"] == 2`
- 4.4: `assert set(result.keys()) == EXPECTED_VERDICT_FIELDS` + all field values + `execution_time_seconds > 0` + explicit stdout purity check

### Complete `test_integration.py` Implementation

```python
import io
import json

import pytest

from conftest import make_agent_result
from sentinel.config import ConfigError
from sentinel.main import main
from sentinel.verdict import BlindSpot


EXPECTED_VERDICT_FIELDS = {
    "verdict",
    "confidence_tier",
    "methodology",
    "citations",
    "blind_spots",
    "source_independence_confirmed",
    "execution_time_seconds",
    "timestamp",
}


def test_both_agents_succeed_probable_verdict(
    mocker: pytest.MockerFixture,
    fake_config: "Config",
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel", "Unusual outbound traffic to 185.220.101.45 on port 443"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result(
        "watchman", findings=["Suspicious outbound connection to known Tor exit node"]
    )
    cipher_mock.return_value.analyze.return_value = make_agent_result(
        "cipher", findings=["VirusTotal: 185.220.101.45 flagged by 12 engines as malicious"]
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.out != ""
    result = json.loads(captured.out)
    assert set(result.keys()) == EXPECTED_VERDICT_FIELDS
    assert result["confidence_tier"] == 2
    assert result["verdict"] == "Probable"
    assert result["source_independence_confirmed"] is True
    assert result["blind_spots"] == []
    assert result["execution_time_seconds"] > 0


def test_watchman_timeout_investigating_verdict(
    mocker: pytest.MockerFixture,
    fake_config: "Config",
    capsys: pytest.CaptureFixture[str],
) -> None:
    bs = BlindSpot(
        source="watchman",
        reason="Watchman analysis timed out — behavioral analysis unavailable",
        next_step="Retry or check Anthropic API connectivity",
    )
    mocker.patch("sys.argv", ["sentinel", "Brute force SSH attempt from 10.0.0.1"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result(
        "watchman", blind_spots=[bs], error="timeout"
    )
    cipher_mock.return_value.analyze.return_value = make_agent_result(
        "cipher", findings=["AbuseIPDB: 10.0.0.1 abuse confidence 85% from 42 reports"]
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.out != ""
    result = json.loads(captured.out)
    assert result["confidence_tier"] == 1
    assert result["verdict"] == "Investigating"
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["source"] == "watchman"
    assert result["execution_time_seconds"] > 0


def test_both_agents_fail_investigating_verdict(
    mocker: pytest.MockerFixture,
    fake_config: "Config",
    capsys: pytest.CaptureFixture[str],
) -> None:
    bs_w = BlindSpot(
        source="watchman",
        reason="Watchman analysis timed out — behavioral analysis unavailable",
        next_step="Retry or check Anthropic API connectivity",
    )
    bs_c = BlindSpot(
        source="cipher",
        reason="VirusTotal API unavailable — reputation data unavailable",
        next_step="Check VirusTotal API status and retry",
    )
    mocker.patch("sys.argv", ["sentinel", "Suspicious DNS query to malware-domain.com"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result(
        "watchman", blind_spots=[bs_w], error="timeout"
    )
    cipher_mock.return_value.analyze.return_value = make_agent_result(
        "cipher", blind_spots=[bs_c], error="api_error"
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.out != ""
    result = json.loads(captured.out)
    assert result["confidence_tier"] == 1
    assert result["verdict"] == "Investigating"
    assert len(result["blind_spots"]) == 2
    sources = {bs["source"] for bs in result["blind_spots"]}
    assert sources == {"watchman", "cipher"}
    assert result["execution_time_seconds"] > 0


def test_no_input_nothing_to_stdout(
    mocker: pytest.MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel"])
    mock_stdin = mocker.MagicMock()
    mock_stdin.isatty.return_value = True
    mocker.patch("sys.stdin", mock_stdin)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err != ""


def test_missing_api_key_nothing_to_stdout(
    mocker: pytest.MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel", "test alert for integration"])
    mocker.patch(
        "sentinel.main.load_config",
        side_effect=ConfigError("Missing required environment variable: ANTHROPIC_API_KEY"),
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ANTHROPIC_API_KEY" in captured.err
```

### Import Discipline in `test_integration.py`

All 6 imports must be used in test bodies (ruff F401):

| Import | Used in |
|--------|---------|
| `io` | NOT needed here — `io.StringIO` is only needed in test_main.py; no stdin mocking in test_integration.py except via MagicMock |
| `json` | Tests 1–3: `json.loads(captured.out)` |
| `pytest` | All tests: `pytest.MockerFixture`, `pytest.CaptureFixture`, `pytest.raises` |
| `make_agent_result` | All tests: constructing agent return values |
| `ConfigError` | Test 5: `side_effect=ConfigError(...)` |
| `main` | All tests: called under `pytest.raises(SystemExit)` |
| `BlindSpot` | Tests 2–3: constructing blind_spot objects |

**Note:** `io` is NOT imported in `test_integration.py`. The "no input" test uses `mocker.MagicMock()` with `.isatty.return_value = True` instead of `io.StringIO`. This avoids an unused import.

### EXPECTED_VERDICT_FIELDS — Exactly 8

The module-level constant `EXPECTED_VERDICT_FIELDS` acts as the integration test's schema assertion. It mirrors the `VerdictSchema` TypedDict from `verdict.py`:

```python
EXPECTED_VERDICT_FIELDS = {
    "verdict",
    "confidence_tier",
    "methodology",
    "citations",
    "blind_spots",
    "source_independence_confirmed",
    "execution_time_seconds",
    "timestamp",
}
```

Test 1 asserts `assert set(result.keys()) == EXPECTED_VERDICT_FIELDS` — this is the full schema check that verifies no field is missing or extra-added in the JSON output.

### Confidence Tier Logic — What to Expect for Each Scenario

**Scenario 1 (both succeed):**
- `count_independent_sources`: `watchman` (error=None) → `"llm_behavioral"`, `cipher` (error=None) → `"community_reputation"` → 2 distinct categories → `ConfidenceTier.PROBABLE`
- `tier = TIER_MAP[PROBABLE]` = `(2, "Probable")`
- `are_independent("watchman", "cipher")` → `True` (different categories)
- `confidence_tier=2`, `verdict="Probable"`, `source_independence_confirmed=True` ✓

**Scenario 2 (Watchman timeout):**
- `count_independent_sources`: `watchman` (error="timeout") excluded, `cipher` (error=None) → `"community_reputation"` → 1 distinct category → `ConfidenceTier.INVESTIGATING`
- `tier = TIER_MAP[INVESTIGATING]` = `(1, "Investigating")`
- `confidence_tier=1`, `verdict="Investigating"` ✓
- `blind_spots` contains the BlindSpot passed into `make_agent_result("watchman", blind_spots=[bs], error="timeout")`

**Scenario 3 (both fail):**
- `count_independent_sources`: both have errors → 0 categories → `ConfidenceTier.INVESTIGATING`
- `tier = TIER_MAP[INVESTIGATING]` = `(1, "Investigating")`
- `confidence_tier=1`, `verdict="Investigating"` ✓
- `blind_spots` contains both blind_spots merged from both agent results

### Mocking Pattern — Same as Story 4.2

```python
watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
cipher_mock = mocker.patch("sentinel.main.CipherAgent")
watchman_mock.return_value.analyze.return_value = make_agent_result("watchman", ...)
cipher_mock.return_value.analyze.return_value = make_agent_result("cipher", ...)
```

Patching at `sentinel.main.WatchmanAgent` replaces the name in `main.py`'s namespace. When `main.py` calls `WatchmanAgent(config)`, it gets `watchman_mock.return_value`. When `.analyze(input_data)` is called, it returns the `AgentResult` from `make_agent_result(...)`.

### Stdout Purity — The Integration Guarantee

Every test explicitly checks `captured.out`:
- Success tests (1–3): `assert captured.out != ""` then `json.loads(captured.out)` — if any non-JSON sneaks into stdout, `json.loads` raises and fails the test
- Failure tests (4–5): `assert captured.out == ""` — nothing reaches stdout before exit 2

This is the most important integration-level assertion: it verifies that the progress message `print("[sentinel] Analyzing alert...", file=sys.stderr)` in `main.py` correctly targets stderr, not stdout.

### `fake_config` Type Annotation

Use string annotation `"Config"` to avoid importing `Config` only for the type hint:

```python
def test_both_agents_succeed_probable_verdict(
    mocker: pytest.MockerFixture,
    fake_config: "Config",
    capsys: pytest.CaptureFixture[str],
) -> None:
```

This matches the pattern established in `test_main.py` (Story 4.2) and avoids ruff F401 for unused imports.

### Existing Files — Do NOT Modify

| File | Reason |
|------|--------|
| `src/sentinel/main.py` | Must be fully implemented (Story 4.2) before these tests run |
| `src/sentinel/verdict.py` | Complete as of 4.1 |
| `src/sentinel/config.py` | Foundation, complete |
| `src/sentinel/source_registry.py` | Complete as of 2.1 |
| `src/sentinel/confidence.py` | Complete as of 2.2 |
| `src/sentinel/watchman.py` | Complete as of 3.1 |
| `src/sentinel/cipher.py` | Complete as of 3.2 |
| `tests/conftest.py` | Complete — fixtures available |
| All prior test files | Must remain passing |

### Test Count After This Story

| File | Tests |
|------|-------|
| Stories 1.1–4.1 (7 test files) | 48 |
| test_main.py (Story 4.2) | 7 |
| test_integration.py (this story) | 5 |
| **Total** | **60** |

### Project Structure After This Story

```
sentinel/
├── src/sentinel/            ← unchanged (main.py complete from Story 4.2)
├── tests/
│   ├── conftest.py          ← unchanged
│   ├── test_version.py      ← unchanged
│   ├── test_verdict.py      ← unchanged
│   ├── test_config.py       ← unchanged
│   ├── test_source_registry.py ← unchanged
│   ├── test_confidence.py   ← unchanged
│   ├── test_watchman.py     ← unchanged
│   ├── test_cipher.py       ← unchanged
│   ├── test_main.py         ← unchanged (from Story 4.2)
│   └── test_integration.py  ← NEW: 5 integration tests
├── README.md                ← unchanged (complete from Story 4.3)
├── CONTRIBUTING.md          ← unchanged (complete from Story 4.3)
└── .env.example             ← unchanged
```

### Previous Story Learnings

- **`py -m` prefix** on Windows for all tooling
- **ruff F401:** Every import in test_integration.py must be used — `io` is NOT imported because no `io.StringIO` is needed; MagicMock handles the "no stdin" case instead
- **`fake_config` type annotation:** Use string `"Config"` to avoid importing `Config` for annotation only
- **Story 4.2 is a hard dependency:** integration tests call `main()` end-to-end; the scaffold `main.py` produces exit 1 + empty stdout on every call
- **48 + 7 = 55 tests before this story** — must remain green; new tests bring total to 60

### References

- [Source: epics.md#Story 4.4] — acceptance criteria and 6 integration scenarios
- [Source: epics.md#FR21, FR22] — stdout clean JSON, stderr for all other output
- [Source: epics.md#FR27–29] — exit codes 0/2
- [Source: architecture.md#stdout/stderr pattern] — stdout is always clean JSON

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

### Completion Notes List

### File List
