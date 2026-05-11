# Story 4.2: CLI Orchestrator

Status: ready-for-dev

## Story

As an analyst,
I want to submit a security alert by argument or stdin pipe and have both agents run in parallel,
So that I get a verdict in under 30 seconds with correct exit codes for any outcome — success, analysis error, or missing input.

## Acceptance Criteria

1. **Given** a positional argument is provided (`sentinel "alert text"`), **When** the command runs, **Then** SENTINEL uses the argument as input and does not attempt to read stdin.

2. **Given** input is piped via stdin (`echo "alert" | sentinel`), **When** the command runs, **Then** SENTINEL reads from stdin automatically with no flag required.

3. **Given** neither argument nor stdin is provided, **When** `sentinel` is run with no input, **Then** it prints a usage message to stderr and exits with code 2.

4. **Given** a valid input and all env vars set, **When** SENTINEL runs, **Then** Watchman and Cipher are invoked concurrently via `ThreadPoolExecutor` and both results are collected before `assemble_verdict` is called.

5. **Given** one agent times out (exceeds `config.timeout_seconds`), **When** `ThreadPoolExecutor` collects results, **Then** the timed-out agent's result is treated as a blind spot and the other agent's result is used — analysis always produces a verdict, never hangs.

6. **Given** a verdict is produced at any confidence tier, **When** the command completes, **Then** it exits with code 0.

7. **Given** an unrecoverable error occurs (both agents fail and no verdict can be assembled), **When** the command completes, **Then** it exits with code 1.

8. **Given** required env vars are missing, **When** `sentinel` is run, **Then** `ConfigError` is caught at the top level, a clear message is printed to stderr naming the missing variable, and it exits with code 2.

9. **And** `main.py` imports all 6 sibling modules and is the only module that does so. The top-level handler catches all unhandled exceptions and always produces either a structured exit or a JSON verdict — SENTINEL never crashes with an unhandled traceback.

## Tasks / Subtasks

- [ ] **Task 1: Implement `main.py` — complete CLI orchestrator** (AC: 1–9)
  - [ ] Add all imports: `argparse`, `sys`, `time`, `concurrent.futures.ThreadPoolExecutor`, and all 6 sentinel sibling modules
  - [ ] Implement `_run()` helper: argparse → input detection (arg > stdin > exit 2) → `load_config()` → agents → `ThreadPoolExecutor` → tier → `assemble_verdict` → `print_verdict` → `sys.exit(0)`
  - [ ] Implement `main()` entry point: calls `_run()`, catches `SystemExit` (re-raises), catches `Exception` (prints to stderr, exits 1)

- [ ] **Task 2: Create `tests/test_main.py`** (AC: 1–9)
  - [ ] Test: positional arg is used as input — `analyze()` called with arg value
  - [ ] Test: stdin is read when no positional arg provided — `analyze()` called with stdin content
  - [ ] Test: no input (isatty=True, no arg) → exit 2, usage message to stderr, nothing to stdout
  - [ ] Test: empty input (stdin returns empty string) → exit 2
  - [ ] Test: ConfigError from `load_config` → exit 2, error message in stderr, nothing to stdout
  - [ ] Test: both agents succeed → exit 0, stdout is valid JSON with `confidence_tier`
  - [ ] Test: unhandled exception from inside `_run` → exit 1, nothing to stdout, "unexpected error" in stderr

- [ ] **Task 3: Verify CI green** (AC: all)
  - [ ] `py -m ruff check src/ tests/` — 0 issues
  - [ ] `py -m mypy src/` — 0 errors across all 8 source files
  - [ ] `py -m pytest tests/ -v` — all 48 existing tests pass + 7 new test_main.py tests (55 total)

## Dev Notes

### Current State of `main.py`

`main.py` currently contains a minimal scaffold (only argparse setup + "Not yet implemented."):

```python
import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL — multi-agent security alert corroboration engine"
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Security alert, log line, or IOC to analyze",
    )
    parser.parse_args()
    print("Not yet implemented.", file=sys.stderr)
    sys.exit(1)
```

**This file must be completely replaced.** Everything except the argparse argument shape carries over; the full orchestration logic is new.

### Complete `main.py` After This Story

```python
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from sentinel.cipher import CipherAgent
from sentinel.confidence import TIER_MAP, calculate_tier
from sentinel.config import ConfigError
from sentinel.config import load as load_config
from sentinel.source_registry import are_independent
from sentinel.verdict import assemble_verdict, print_verdict
from sentinel.watchman import WatchmanAgent


def main() -> None:
    try:
        _run()
    except SystemExit:
        raise
    except Exception as exc:
        print(f"sentinel: unexpected error — {exc}", file=sys.stderr)
        sys.exit(1)


def _run() -> None:
    start_time = time.time()

    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL — multi-agent security alert corroboration engine",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Security alert, log line, or IOC to analyze",
    )
    args = parser.parse_args()

    if args.input is not None:
        input_data: str = args.input
    elif not sys.stdin.isatty():
        input_data = sys.stdin.read().strip()
    else:
        print(
            'sentinel: no input provided.\n'
            'Usage: sentinel "<alert text>"  OR  echo "<alert>" | sentinel',
            file=sys.stderr,
        )
        sys.exit(2)

    if not input_data:
        print("sentinel: input is empty.", file=sys.stderr)
        sys.exit(2)

    try:
        config = load_config()
    except ConfigError as exc:
        print(f"sentinel: {exc}", file=sys.stderr)
        sys.exit(2)

    watchman = WatchmanAgent(config)
    cipher = CipherAgent(config)

    print("[sentinel] Analyzing alert...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=2) as executor:
        w_future = executor.submit(watchman.analyze, input_data)
        c_future = executor.submit(cipher.analyze, input_data)
        watchman_result = w_future.result()
        cipher_result = c_future.result()

    tier_enum = calculate_tier([watchman_result, cipher_result])
    tier = TIER_MAP[tier_enum]
    independence = are_independent("watchman", "cipher")

    verdict = assemble_verdict(watchman_result, cipher_result, tier, independence, start_time)
    print_verdict(verdict)
    sys.exit(0)
```

### Why `_run()` + `main()` Split

The top-level handler in `main()` must re-raise `SystemExit` (not catch it as a generic `Exception`) because `sys.exit()` raises `SystemExit`, which is a subclass of `BaseException` — NOT `Exception`. Without the `except SystemExit: raise` guard, `sys.exit(2)` calls inside `_run()` would be swallowed by `except Exception` and turned into exit code 1. Verification:

```
BaseException
├── SystemExit        ← sys.exit() raises this
├── KeyboardInterrupt
└── Exception         ← everything else
```

So the pattern is:
1. `except SystemExit: raise` — lets `sys.exit(2)` and `sys.exit(0)` propagate correctly
2. `except Exception as exc:` — catches everything unexpected → exit 1

### stdin Detection Pattern

`sys.stdin.isatty()` returns `False` when stdin is a pipe and `True` when it's an interactive terminal. This is the correct, cross-platform way to detect piped input:

```python
elif not sys.stdin.isatty():
    input_data = sys.stdin.read().strip()
```

**In tests:** `io.StringIO` has `.isatty()` → returns `False` by default. So monkeypatching `sys.stdin` with `io.StringIO("alert text")` automatically satisfies the `not sys.stdin.isatty()` condition without extra mocking.

**For the "no input" test:** Patch `sys.stdin` with a `MagicMock` whose `.isatty()` returns `True`.

### ThreadPoolExecutor — Agent Timeout Handling

Both `WatchmanAgent` and `CipherAgent` already handle their own timeouts internally:
- Watchman catches `anthropic.APITimeoutError` → returns `AgentResult(error="timeout", blind_spots=[...])`
- Cipher catches `httpx.TimeoutException` → returns `AgentResult(error="timeout", blind_spots=[...])`

So `w_future.result()` and `c_future.result()` **always return** `AgentResult` — they never raise. This means:
- The `with ThreadPoolExecutor(...)` block never blocks indefinitely
- No `TimeoutError` import needed — the safety is in the agents, not the future
- `assemble_verdict` always has two valid `AgentResult` objects to work with

This satisfies AC5 because a timed-out agent's result already contains the blind spot — the orchestrator never needs to construct one itself.

### Import Discipline — `main.py` imports all 6 siblings

`main.py` is the only module that imports all 6 siblings. The import block:

```python
from sentinel.cipher import CipherAgent           # sibling 1
from sentinel.confidence import TIER_MAP, calculate_tier   # sibling 2
from sentinel.config import ConfigError           # sibling 3 (part 1)
from sentinel.config import load as load_config   # sibling 3 (part 2)
from sentinel.source_registry import are_independent  # sibling 4
from sentinel.verdict import assemble_verdict, print_verdict  # sibling 5
from sentinel.watchman import WatchmanAgent       # sibling 6
```

Using `load as load_config` avoids shadowing the local variable `config` when it's used later as the variable name for the loaded Config object.

### Exit Code Reference

| Code | Trigger | Where |
|------|---------|--------|
| 0 | Verdict produced (any tier) | `_run()` after `print_verdict()` |
| 1 | Unexpected exception | `main()` top-level `except Exception` handler |
| 2 | No/empty input | `_run()` input detection block |
| 2 | Missing env var | `_run()` ConfigError catch block |

### mypy Compliance

**`_run()` → `None` return type is valid:** All code paths in `_run()` end in `sys.exit()` which is typed `NoReturn` in typeshed. Python/mypy accept `-> None` for functions that always raise or call `NoReturn` functions.

**`input_data: str = args.input`** — explicit annotation needed because `args.input` is typed as `str | None` from argparse. After the `if args.input is not None:` guard, mypy knows it's `str`, but annotating explicitly in the `if` branch prevents any ambiguity.

**`watchman_result` and `cipher_result`** — mypy infers `AgentResult` from `w_future.result()` since `executor.submit(watchman.analyze, input_data)` returns `Future[AgentResult]`.

### `test_main.py` — Complete Implementation

```python
import io
import json

import pytest

from conftest import make_agent_result
from sentinel.config import ConfigError
from sentinel.main import main


def test_positional_arg_is_used_as_input(
    mocker: pytest.MockerFixture, fake_config: "Config"
) -> None:
    mocker.patch("sys.argv", ["sentinel", "test alert content"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result("watchman")
    cipher_mock.return_value.analyze.return_value = make_agent_result("cipher")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    watchman_mock.return_value.analyze.assert_called_once_with("test alert content")


def test_stdin_read_when_no_positional_arg(
    mocker: pytest.MockerFixture, fake_config: "Config"
) -> None:
    mocker.patch("sys.argv", ["sentinel"])
    mocker.patch("sys.stdin", io.StringIO("alert from stdin"))
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result("watchman")
    cipher_mock.return_value.analyze.return_value = make_agent_result("cipher")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    watchman_mock.return_value.analyze.assert_called_once_with("alert from stdin")


def test_no_input_exits_2_with_usage_to_stderr(
    mocker: pytest.MockerFixture, capsys: pytest.CaptureFixture[str]
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


def test_empty_input_exits_2(
    mocker: pytest.MockerFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    mocker.patch("sys.argv", ["sentinel"])
    mocker.patch("sys.stdin", io.StringIO("   "))  # only whitespace → strip → ""

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""


def test_config_error_exits_2(
    mocker: pytest.MockerFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    mocker.patch("sys.argv", ["sentinel", "some alert"])
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


def test_success_exits_0_with_json_to_stdout(
    mocker: pytest.MockerFixture, fake_config: "Config", capsys: pytest.CaptureFixture[str]
) -> None:
    mocker.patch("sys.argv", ["sentinel", "suspicious outbound traffic to 1.2.3.4"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result(
        "watchman", findings=["Suspicious outbound connection pattern"]
    )
    cipher_mock.return_value.analyze.return_value = make_agent_result(
        "cipher", findings=["VirusTotal: 1.2.3.4 flagged by 5 engines"]
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.out != ""
    result = json.loads(captured.out)
    assert result["confidence_tier"] == 2
    assert result["source_independence_confirmed"] is True
    assert result["verdict"] == "Probable"


def test_unhandled_exception_exits_1(
    mocker: pytest.MockerFixture, fake_config: "Config", capsys: pytest.CaptureFixture[str]
) -> None:
    mocker.patch("sys.argv", ["sentinel", "some alert"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result("watchman")
    cipher_mock.return_value.analyze.return_value = make_agent_result("cipher")
    mocker.patch("sentinel.main.assemble_verdict", side_effect=RuntimeError("unexpected failure"))

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unexpected error" in captured.err
```

### Import Annotation for `fake_config`

In `test_main.py`, the `fake_config` parameter type is `Config`. Since `Config` is a dataclass, importing it only for the annotation would trigger ruff F401 if `Config` isn't used in the test body. Use a string annotation `"Config"` instead to avoid the import-for-annotation-only pattern:

```python
def test_positional_arg_is_used_as_input(
    mocker: pytest.MockerFixture, fake_config: "Config"
) -> None:
```

This is a forward reference string annotation — mypy accepts it.

### Confidence Tier Expectation in `test_success_exits_0`

The test passes `make_agent_result("watchman")` and `make_agent_result("cipher")` — both with `error=None`.

`count_independent_sources` logic:
- `watchman` source_name → `SOURCE_CATEGORIES["watchman"]` = `"llm_behavioral"` → added
- `cipher` source_name → `SOURCE_CATEGORIES["cipher"]` = `"community_reputation"` → added
- 2 distinct categories → count = 2 → `ConfidenceTier.PROBABLE` → `tier = (2, "Probable")`

`are_independent("watchman", "cipher")`:
- `"llm_behavioral"` ≠ `"community_reputation"` → `True`

So `confidence_tier=2`, `verdict="Probable"`, `source_independence_confirmed=True`. ✓

### Mocking Pattern for `WatchmanAgent` / `CipherAgent`

```python
watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
cipher_mock = mocker.patch("sentinel.main.CipherAgent")
watchman_mock.return_value.analyze.return_value = make_agent_result("watchman")
cipher_mock.return_value.analyze.return_value = make_agent_result("cipher")
```

`mocker.patch("sentinel.main.WatchmanAgent")` replaces the `WatchmanAgent` name in `sentinel.main`'s namespace with a `MagicMock`. When `main.py` calls `WatchmanAgent(config)`, it gets `watchman_mock.return_value`. When `.analyze(input_data)` is called on that, it returns `watchman_mock.return_value.analyze.return_value`. ✓

### Existing Files — Do NOT Modify

| File | Reason |
|------|--------|
| `src/sentinel/verdict.py` | Complete as of 4.1 |
| `src/sentinel/config.py` | Foundation, complete |
| `src/sentinel/source_registry.py` | Complete as of 2.1 |
| `src/sentinel/confidence.py` | Complete as of 2.2 |
| `src/sentinel/watchman.py` | Complete as of 3.1 |
| `src/sentinel/cipher.py` | Complete as of 3.2 |
| `tests/conftest.py` | Complete — fixtures available |
| All prior test files | Must remain passing |

### Architecture Compliance Checklist

- [ ] `main.py` is the ONLY module that imports from all 6 siblings
- [ ] `os.environ` NOT accessed in `main.py` — all env var access is in `config.py`
- [ ] All progress/warning messages use `print(..., file=sys.stderr)` — never bare `print()`
- [ ] `print_verdict()` is the only `sys.stdout` write (in `verdict.py`) — `main.py` never writes to stdout directly
- [ ] `SystemExit` is re-raised in `main()` top-level handler, not swallowed
- [ ] ThreadPoolExecutor used for parallel agent execution
- [ ] Both agents always return `AgentResult` (never raise) — no `concurrent.futures.TimeoutError` handling needed

### Previous Story Learnings (from Stories 1.1–4.1)

- **`py -m` prefix** on Windows for all tooling
- **mypy strict:** annotate `input_data: str = args.input` explicitly in the `if args.input is not None:` branch to avoid `str | None` type issue
- **ruff F401:** All 6 imports in `test_main.py` (`io`, `json`, `pytest`, `make_agent_result`, `ConfigError`, `main`) must be used in test bodies
- **`fake_config` type annotation:** Use string `"Config"` to avoid importing `Config` for annotation only
- **`sys.exit()` is `NoReturn`:** Calling `sys.exit()` inside `_run()` is safe with `-> None` return type annotation — mypy understands
- **`_run()` never returns normally** — all paths call `sys.exit()`, so the `main()` caller never reaches code after `_run()` unless an exception propagates
- **48 tests currently passing** — must remain green; new tests in `test_main.py` bring total to 55

### Project Structure After This Story

```
sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py          ← unchanged
│       ├── main.py              ← REWRITTEN: full CLI orchestrator
│       ├── verdict.py           ← unchanged (complete as of 4.1)
│       ├── config.py            ← unchanged
│       ├── source_registry.py   ← unchanged
│       ├── confidence.py        ← unchanged
│       ├── watchman.py          ← unchanged
│       └── cipher.py            ← unchanged
├── tests/
│   ├── conftest.py              ← unchanged
│   ├── test_version.py          ← unchanged
│   ├── test_verdict.py          ← unchanged
│   ├── test_config.py           ← unchanged
│   ├── test_source_registry.py  ← unchanged
│   ├── test_confidence.py       ← unchanged
│   ├── test_watchman.py         ← unchanged
│   ├── test_cipher.py           ← unchanged
│   └── test_main.py             ← NEW: 7 tests for CLI orchestration
```

### References

- [Source: epics.md#Story 4.2] — acceptance criteria, exit codes, parallel execution requirement
- [Source: architecture.md#Data Flow] — ThreadPoolExecutor pattern, main.py wiring diagram
- [Source: architecture.md#stderr Output Pattern] — sys.stdout only in verdict.py; sys.stderr for all other output
- [Source: architecture.md#Config Injection Pattern] — os.environ only in config.py
- [Source: architecture.md#Import Discipline] — main.py at top of import hierarchy
- [Source: epics.md#FR1–4, FR27–29] — input detection, exit codes
- [Source: epics.md#AR3, AR10] — config injection; no raw exceptions from agents to main.py

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

### Completion Notes List

### File List
