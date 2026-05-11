# Story 3.1: Watchman Agent

Status: review

## Story

As an analyst,
I want SENTINEL to run behavioral analysis on my alert using Claude,
So that I get structured findings about whether the alert pattern matches known threat TTPs — and a named blind spot if the analysis cannot complete, rather than a crash.

## Acceptance Criteria

1. **Given** a valid `Config` and alert text, **When** `WatchmanAgent(config).analyze(input_data)` is called with a mocked Anthropic client returning a well-formed response, **Then** it returns an `AgentResult` with `source_name="watchman"`, non-empty `findings`, `blind_spots=[]`, and `error=None`.

2. **Given** the Anthropic client raises `APITimeoutError`, **When** `analyze(input_data)` is called, **Then** it returns an `AgentResult` with `error="timeout"`, a `BlindSpot` in `blind_spots` with a human-readable `reason` (not "APITimeoutError"), and `findings=[]` — no exception propagates.

3. **Given** the Anthropic client returns a response that cannot be parsed into the expected schema, **When** `analyze(input_data)` is called, **Then** it returns an `AgentResult` with `error="malformed_output"` and `blind_spots` containing a `BlindSpot` with `reason="Watchman output malformed — behavioral analysis unavailable"` — satisfying FR10.

4. **Given** any other exception is raised during analysis, **When** `analyze(input_data)` is called, **Then** it returns an `AgentResult` with `error` set and a descriptive `BlindSpot` — no raw exception reaches the caller.

5. **Given** `WatchmanAgent` is inspected by mypy against `SentinelAgent` Protocol, **When** type checking runs, **Then** no type errors are reported — it satisfies the Protocol structurally without inheriting from anything.

6. **And** `WatchmanAgent.__init__` accepts only `config: Config` with no `os.environ` access inside the class, and `tests/test_watchman.py` uses `pytest-mock` to patch the Anthropic SDK at the call boundary, covering: success, timeout → blind spot, malformed output → blind spot, generic exception → blind spot.

## Tasks / Subtasks

- [x] **Task 1: Implement `watchman.py`** (AC: 1–5)
  - [x] Create `src/sentinel/watchman.py` importing `json`, `anthropic`, `sentinel.config.Config`, `sentinel.verdict.AgentResult`, `sentinel.verdict.BlindSpot`
  - [x] Define module-level `_MODEL` and `_PROMPT_TEMPLATE` constants (see Dev Notes)
  - [x] Implement `WatchmanAgent.__init__(self, config: Config)` — stores config, instantiates `anthropic.Anthropic`
  - [x] Implement `analyze(self, input_data: str) -> AgentResult` with all 3 exception branches (see Dev Notes)

- [x] **Task 2: Write `tests/test_watchman.py`** (AC: 6)
  - [x] Test: success path — mocked Claude response → non-empty findings, `error=None`
  - [x] Test: `APITimeoutError` → `error="timeout"`, 1 blind spot with human-readable reason
  - [x] Test: malformed JSON response → `error="malformed_output"`, blind spot reason contains "malformed"
  - [x] Test: generic exception (`APIConnectionError`) → `error` set, 1 blind spot
  - [x] Test: Protocol compliance — `agent: SentinelAgent = WatchmanAgent(config=fake_config)` annotation

- [x] **Task 3: Verify CI green** (AC: all)
  - [x] `py -m ruff check src/ tests/` — 0 issues
  - [x] `py -m mypy src/` — 0 errors across all 7 source files
  - [x] `py -m pytest tests/ -v` — all 30 existing tests pass + new test_watchman.py tests

## Dev Notes

### watchman.py — Exact Implementation

```python
import json

import anthropic

from sentinel.config import Config
from sentinel.verdict import AgentResult, BlindSpot

_MODEL = "claude-haiku-4-5-20251001"

_PROMPT_TEMPLATE = """\
You are a security analyst. Analyze the following security alert for behavioral indicators of compromise.

Respond ONLY with valid JSON in this exact format:
{{
    "findings": ["<specific behavioral finding>", "<another finding>"],
    "confidence": "<Investigating|Probable|Confirmed>"
}}

Alert: {alert}"""


class WatchmanAgent:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._client = anthropic.Anthropic(
            api_key=config.anthropic_api_key,
            timeout=config.timeout_seconds,
        )

    def analyze(self, input_data: str) -> AgentResult:
        try:
            response = self._client.messages.create(
                model=_MODEL,
                max_tokens=1024,
                messages=[
                    {
                        "role": "user",
                        "content": _PROMPT_TEMPLATE.format(alert=input_data),
                    }
                ],
            )
            raw_text: str = response.content[0].text  # type: ignore[union-attr]
            parsed = json.loads(raw_text)
            findings: list[str] = parsed.get("findings") or []
            confidence: str | None = parsed.get("confidence")
            if not isinstance(findings, list):
                raise ValueError("findings must be a list")
            return AgentResult(
                source_name="watchman",
                findings=findings,
                blind_spots=[],
                raw_confidence=confidence,
                error=None,
            )
        except anthropic.APITimeoutError:
            return AgentResult(
                source_name="watchman",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="watchman",
                        reason="Watchman timed out — behavioral analysis unavailable",
                        next_step="Retry when Anthropic API is available or increase SENTINEL_TIMEOUT",
                    )
                ],
                raw_confidence=None,
                error="timeout",
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return AgentResult(
                source_name="watchman",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="watchman",
                        reason="Watchman output malformed — behavioral analysis unavailable",
                        next_step=None,
                    )
                ],
                raw_confidence=None,
                error="malformed_output",
            )
        except Exception:
            return AgentResult(
                source_name="watchman",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="watchman",
                        reason="Watchman analysis failed — behavioral analysis unavailable",
                        next_step=None,
                    )
                ],
                raw_confidence=None,
                error="analysis_failed",
            )
```

### Double Braces in `_PROMPT_TEMPLATE`

The template uses `str.format(alert=input_data)`. Any `{` or `}` in the template that should appear literally in the prompt (the JSON example) must be doubled to `{{` and `}}`. Forgetting this causes a `KeyError` at runtime when `.format()` tries to interpret the JSON example as a format placeholder.

```python
# ❌ WRONG — raises KeyError: 'findings'
_PROMPT_TEMPLATE = """
Respond with: {"findings": [...]}
Alert: {alert}"""

# ✅ CORRECT — {{ and }} are escaped
_PROMPT_TEMPLATE = """
Respond with: {{"findings": [...]}}
Alert: {alert}"""
```

### `response.content[0].text` — `# type: ignore[union-attr]`

`response.content` is typed as `list[TextBlock | ToolUseBlock]` in the anthropic SDK. `ToolUseBlock` has no `.text` attribute. mypy strict flags `.text` access on the union as a potential `union-attr` error.

Since we always send a plain text message and request no tools, the response will always be a `TextBlock`. The `# type: ignore[union-attr]` suppresses the mypy error for this intentional access. This is the correct pattern — the ignore comment is narrow and documented.

**Alternative (if stricter checking is desired):**
```python
block = response.content[0]
if not hasattr(block, "text") or not isinstance(block.text, str):
    raise ValueError("unexpected content block type")
raw_text = block.text
```
But for v1, `# type: ignore[union-attr]` with an explicit type annotation `raw_text: str = ...` is cleaner.

### Exception Handling — Order Matters

The three `except` branches must be ordered:
1. `except anthropic.APITimeoutError:` — **must come first**, before `Exception`
2. `except (json.JSONDecodeError, KeyError, ValueError):` — parsing failures
3. `except Exception:` — catches everything else (network errors, auth errors, etc.)

If `except Exception:` came first, it would swallow `APITimeoutError` and the wrong error code would be returned.

### `anthropic.APITimeoutError` — Constructor for Tests

From the installed SDK (`anthropic==0.100.0`):
```python
anthropic.APITimeoutError.__init__(self, request: httpx.Request) -> None
```

In tests, construct it with:
```python
anthropic.APITimeoutError(request=mocker.MagicMock())
```

`APIConnectionError` takes keyword-only `request`:
```python
anthropic.APIConnectionError(request=mocker.MagicMock())
```

### Test Mocking Pattern

Mock `anthropic.Anthropic` at the point of import in `watchman.py`:

```python
mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
```

This replaces the `Anthropic` class as seen from within `sentinel.watchman`. When `WatchmanAgent.__init__` runs `anthropic.Anthropic(api_key=..., timeout=...)`, it gets the mock. Then:

- `mock_anthropic.return_value` → the mock client instance
- `mock_anthropic.return_value.messages.create.return_value` → mock response
- `mock_anthropic.return_value.messages.create.side_effect = SomeException(...)` → raise on call

### test_watchman.py — Exact Implementation

```python
import anthropic
import pytest

from sentinel.config import Config
from sentinel.verdict import SentinelAgent
from sentinel.watchman import WatchmanAgent


def test_watchman_success(
    mocker: pytest.MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_response = mocker.MagicMock()
    mock_response.content[0].text = (
        '{"findings": ["Suspicious outbound connection to known Tor exit node",'
        ' "High-volume data transfer on port 443"], "confidence": "Probable"}'
    )
    mock_anthropic.return_value.messages.create.return_value = mock_response

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["source_name"] == "watchman"
    assert result["error"] is None
    assert result["blind_spots"] == []
    assert len(result["findings"]) > 0
    assert result["raw_confidence"] == "Probable"


def test_watchman_timeout_returns_blind_spot(
    mocker: pytest.MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_anthropic.return_value.messages.create.side_effect = (
        anthropic.APITimeoutError(request=mocker.MagicMock())
    )

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "timeout"
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["source"] == "watchman"
    assert "timed out" in result["blind_spots"][0]["reason"]


def test_watchman_malformed_output_returns_blind_spot(
    mocker: pytest.MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_response = mocker.MagicMock()
    mock_response.content[0].text = "Sorry, I cannot analyze this alert."
    mock_anthropic.return_value.messages.create.return_value = mock_response

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "malformed_output"
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["reason"] == (
        "Watchman output malformed — behavioral analysis unavailable"
    )


def test_watchman_generic_exception_returns_blind_spot(
    mocker: pytest.MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_anthropic = mocker.patch("sentinel.watchman.anthropic.Anthropic")
    mock_anthropic.return_value.messages.create.side_effect = (
        anthropic.APIConnectionError(request=mocker.MagicMock())
    )

    agent = WatchmanAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] is not None
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["source"] == "watchman"


def test_watchman_satisfies_sentinel_agent_protocol(
    mocker: pytest.MockerFixture, fake_config: Config
) -> None:
    mocker.patch("sentinel.watchman.anthropic.Anthropic")
    agent: SentinelAgent = WatchmanAgent(config=fake_config)
    assert callable(getattr(agent, "analyze", None))
```

**`mocker: pytest.MockerFixture` annotation:** Required under mypy strict — unannotated parameters fail `--disallow-untyped-defs`. `pytest.MockerFixture` is the correct type for the `mocker` fixture from `pytest-mock`. Import `pytest` for this annotation.

**`fake_config: Config` and `sample_alert: str` fixture annotations:** mypy strict requires these too. Import `Config` from `sentinel.config` and annotate — the `fake_config` fixture is already typed `-> Config` in `conftest.py`, so mypy resolves the injection type correctly.

**Why mock in `test_watchman_satisfies_sentinel_agent_protocol`:** `WatchmanAgent.__init__` calls `anthropic.Anthropic(api_key="test-anthropic-key", ...)`. This doesn't make network calls (client construction is local), but mocking is cleaner and prevents any SDK-level validation from affecting the test. The test's purpose is purely structural — verify the `SentinelAgent` Protocol annotation compiles.

### Import Discipline

```
verdict.py          ← foundation
config.py           ← foundation
source_registry.py  ← foundation
confidence.py       ← logic layer
watchman.py         ← logic layer: imports verdict + config ONLY  ← THIS FILE
cipher.py           ← logic layer: imports verdict + config (Story 3.2)
main.py             ← orchestration
```

`watchman.py` must NEVER import from `confidence.py`, `source_registry.py`, `cipher.py`, or `main.py`. It knows nothing about tiers or other agents — it only produces `AgentResult`.

### mypy Considerations

**`_PROMPT_TEMPLATE`** — string constant, no annotation needed. mypy infers `str`.

**`_MODEL`** — string constant. mypy infers `str`. No annotation needed.

**`self._client`** — type is `anthropic.Anthropic`. No explicit annotation needed; mypy infers it from the assignment.

**`raw_text: str = response.content[0].text  # type: ignore[union-attr]`** — the explicit `str` annotation is essential. Without it, mypy would infer `Any` (since it can't resolve `.text` on the union). With the annotation plus `type: ignore`, mypy treats `raw_text` as `str` throughout the rest of the function.

**`findings: list[str] = parsed.get("findings") or []`** — `parsed` is `Any` (from `json.loads`), so `parsed.get("findings")` is `Any`. The `or []` returns `list[Any]` at runtime, but the explicit `list[str]` annotation tells mypy to trust our declared type. This is fine — we validate with `isinstance(findings, list)` immediately after.

**`mocker: pytest.MockerFixture`** — required for `--disallow-untyped-defs`. Add `import pytest` to `test_watchman.py`.

### Existing Files — Do NOT Modify

| File | Reason |
|------|--------|
| `src/sentinel/__init__.py` | Unchanged since 1.1 |
| `src/sentinel/main.py` | Unchanged until 4.2 |
| `src/sentinel/verdict.py` | Foundation, complete |
| `src/sentinel/config.py` | Foundation, complete |
| `src/sentinel/source_registry.py` | Complete as of 2.2 |
| `src/sentinel/confidence.py` | Complete as of 2.2 |
| `tests/conftest.py` | Complete — fixtures available |
| All prior test files | Must remain passing |

### Architecture Compliance Checklist

- [ ] `watchman.py` imports: `json` (stdlib), `anthropic` (runtime dep), `sentinel.config`, `sentinel.verdict` only
- [ ] No `os.environ` anywhere in `watchman.py` — config is injected (AR3)
- [ ] `WatchmanAgent.__init__` signature: `(self, config: Config) -> None` — no other parameters
- [ ] `analyze` signature: `(self, input_data: str) -> AgentResult` — matches `SentinelAgent` Protocol
- [ ] `source_name="watchman"` in all returned `AgentResult` instances
- [ ] All `BlindSpot.reason` fields are human-readable strings — no exception class names
- [ ] `except anthropic.APITimeoutError` is the FIRST except branch (before `except Exception`)
- [ ] `response.content[0].text` has `# type: ignore[union-attr]` comment
- [ ] `mypy src/` passes with 0 errors on all 7 source files

### Previous Story Learnings

- **`py -m` prefix** on Windows for all tooling.
- **mypy strict parameter annotations:** ALL test function parameters must be typed — `mocker: pytest.MockerFixture`, `fake_config: Config`, `sample_alert: str`. Import `pytest` for `pytest.MockerFixture`.
- **ruff F401 trap:** every import must be used at runtime. In `test_watchman.py`: `anthropic` (for exception types), `pytest` (for `pytest.MockerFixture`), `Config` (for fixture annotation), `SentinelAgent` (for Protocol test annotation), `WatchmanAgent` (obviously). All 5 must appear in test code.
- **`try/finally` not needed here** — exception handling uses `return`, not resource cleanup. Each `except` branch returns immediately.
- **30 tests currently passing** — must remain green.

### Project Structure After This Story

```
sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py          ← unchanged
│       ├── main.py              ← unchanged
│       ├── verdict.py           ← unchanged
│       ├── config.py            ← unchanged
│       ├── source_registry.py   ← unchanged
│       ├── confidence.py        ← unchanged
│       └── watchman.py          ← NEW: WatchmanAgent class
├── tests/
│   ├── conftest.py              ← unchanged
│   ├── test_version.py          ← unchanged
│   ├── test_verdict.py          ← unchanged
│   ├── test_config.py           ← unchanged
│   ├── test_source_registry.py  ← unchanged
│   ├── test_confidence.py       ← unchanged
│   └── test_watchman.py         ← NEW: 5 Watchman tests
```

### References

- [Source: epics.md#Story 3.1] — acceptance criteria, all 4 error cases
- [Source: architecture.md#Agent Class Pattern] — class shape, `__init__` signature
- [Source: architecture.md#Config Injection Pattern] — no os.environ in agents
- [Source: architecture.md#Blind Spot Format Pattern] — human-readable reason, never exception class names
- [Source: architecture.md#Test Mock Pattern] — `pytest-mock`, patch at SDK boundary
- [Source: architecture.md#Error → blind spot conversion] — at agent boundary, main.py never sees exceptions
- [Source: prd.md#FR10] — "Watchman output malformed" exact blind spot text (AC 3)

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

### Completion Notes List

- Implemented `WatchmanAgent` with `_MODEL = "claude-haiku-4-5-20251001"` and double-brace-escaped `_PROMPT_TEMPLATE`
- All 3 exception branches implemented in correct order: `APITimeoutError` → `(JSONDecodeError, KeyError, ValueError)` → `Exception`
- `response.content[0].text` annotated `str` with `# type: ignore[union-attr]` per story notes
- 5 tests in `test_watchman.py` covering success, timeout, malformed output, generic exception, and Protocol compliance
- CI: ruff 0 issues, mypy 0 errors (7 source files), pytest 35/35 passed

### File List

- src/sentinel/watchman.py (NEW)
- tests/test_watchman.py (NEW)
