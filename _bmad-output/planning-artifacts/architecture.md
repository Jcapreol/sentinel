---
stepsCompleted: [1, 2, 3, 4, 5, 6, 7, 8]
lastStep: 8
status: 'complete'
completedAt: '2026-05-10'
inputDocuments:
  - '_bmad-output/planning-artifacts/prd.md'
workflowType: 'architecture'
project_name: 'Sentinel'
user_name: 'Jackson'
date: '2026-05-10'
---

# Architecture Decision Document

_This document builds collaboratively through step-by-step discovery. Sections are appended as we work through each architectural decision together._

## Project Context Analysis

### Requirements Overview

**Functional Requirements — 41 FRs across 7 capability areas:**

The FRs describe a pure-function pipeline: one input enters, one JSON verdict exits, nothing persists. The architecture has no state between runs, no background processes, no database, no web server. Every component exists to serve a single request-response cycle.

The most architecturally significant FRs:

- **FR5–6 (Corroboration Engine):** Two agents must run as independent pipelines — they cannot share state, data, or reasoning. This has a direct concurrency implication: parallel execution is not just an optimization, it is the correctness requirement.
- **FR10, FR39 (Error isolation):** Agent failures convert to named blind spots, never exceptions. Error handling is a first-class architectural concern at the agent boundary.
- **FR16, FR41 (Agent interface contract):** The consistent input-dict → result-dict interface is both an extensibility mechanism and a test surface. The architecture must enforce this contract structurally.
- **FR21–23 (Output contract):** Stable JSON schema across v1.x is a hard invariant. The schema must be defined explicitly and enforced, not assembled ad hoc from dict literals.
- **FR22 (stdout/stderr discipline):** All human-readable output goes to stderr. All machine-readable output goes to stdout. This separation must be architectural, not a per-call convention.
- **NFR2–3 (Timeout budget):** 10 seconds per agent, 25 seconds total agent budget, 5 seconds for formatting and output. Parallel agent execution is strongly preferred.

**Non-Functional Requirements — architectural drivers:**

| NFR | Architectural Impact |
|-----|---------------------|
| ≤30s cold start to complete JSON (NFR1) | Parallel agent execution; no lazy imports that delay startup |
| 10s per agent, configurable via `SENTINEL_TIMEOUT` (NFR2, NFR4) | Timeout wrapper at agent call boundary; env var read at startup |
| Never crash on any input (NFR13) | Top-level exception handler; agent-level try/except; all paths produce structured output |
| Agent failures isolated (NFR14) | Agent execution independent; one failure cannot propagate to sibling |
| JSON schema invariant across v1.x (NFR15) | Schema defined as TypedDict or dataclass, not assembled from loose dicts |
| No disk writes ever (NFR6) | No file I/O calls in any module; enforced by convention and tested |
| Credentials from env vars only (NFR5) | Config module reads env at startup; fails fast with clear error if absent |
| pip-installable entry point (NFR19) | `pyproject.toml` with `[project.scripts]` sentinel entry point |
| All tests pass on CI (NFR11) | GitHub Actions workflow; test suite runs on every push |

**Scale & Complexity:**

- **Primary domain:** CLI tool — single-process, request-response, no server
- **Complexity level:** Low operational complexity, high precision complexity (LLM output parsing, schema enforcement, source independence logic)
- **Estimated architectural components:** 6–8 Python modules
- **Solo developer constraint:** Every abstraction must justify itself; prefer flat over layered

### Technical Constraints & Dependencies

- **Python 3.10+** (Anthropic SDK minimum)
- **Anthropic SDK** — Watchman agent; sync client used for v1
- **VirusTotal API v3** — Cipher agent; REST over HTTP
- **AbuseIPDB API v2** — Cipher agent; REST over HTTP
- **Concurrency model:** `concurrent.futures.ThreadPoolExecutor` — parallel agent execution with simpler mental model than asyncio; no async propagation throughout codebase; migrate to asyncio in v1.5 if performance requires it
- **No framework dependencies** — stdlib + three API clients; no Flask, no Pydantic, no heavy dependencies
- **MIT license** — no dependency may introduce a conflicting license
- **Pinned requirements.txt** — all versions exact from first commit

### Cross-Cutting Concerns Identified

1. **Timeout enforcement** — applies to every agent call; must be consistent and configurable via `SENTINEL_TIMEOUT`
2. **Error → blind spot conversion** — every agent failure follows the same pattern: catch, name, continue; never propagate
3. **stdout/stderr discipline** — enforced at the output layer, not per-call; violations break pipeline tools
4. **JSON schema stability** — the output schema is a contract; defined once, referenced everywhere
5. **No disk I/O** — zero file writes; applies to every module; testable as a behavioral requirement
6. **Source independence registry** — shared data structure; centrally defined and contributor-extensible

## Starter Template Evaluation

### Primary Technology Domain

Python CLI package — single-command, no subcommands, ~300 lines of core logic. No web framework starter applies. The "starter" decision is the package structure, CLI entry point tooling, and CI setup.

### CLI Framework Decision

| Option | Dependency | Decision |
|--------|-----------|----------|
| **argparse** (stdlib) | Zero | ✅ Selected — single command, stdin/positional auto-detect, no subcommands, zero added dependency |
| Click | +1 package | Not selected — decorator patterns add complexity for a one-command CLI |
| Typer | +2 packages | Not selected — DX improvements don't justify two new dependencies at this scope |

**Selected: `argparse`** — stdlib only, consistent with minimal dependency footprint requirement (NFR8–9).

### Project Structure

**Selected: `src/` layout** — Python standard as of 2025; prevents import confusion during development and testing; scales to v1.5 cleanly.

```
sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py
│       ├── main.py              # Entry point: argparse, stdin/arg auto-detection, top-level error handler
│       ├── config.py            # Env var reading, startup validation, SENTINEL_TIMEOUT parsing
│       ├── watchman.py          # Watchman agent (Anthropic Claude)
│       ├── cipher.py            # Cipher agent (VirusTotal + AbuseIPDB)
│       ├── source_registry.py   # Source independence taxonomy, contributor-extensible registry
│       ├── confidence.py        # Confidence ladder: source count → Investigating/Probable/Confirmed
│       └── verdict.py           # Verdict schema (TypedDict), JSON formatter, stdout/stderr routing
├── tests/
│   ├── test_watchman.py
│   ├── test_cipher.py
│   ├── test_source_registry.py
│   ├── test_confidence.py
│   └── test_verdict.py
├── .github/
│   └── workflows/
│       └── ci.yml
├── pyproject.toml
├── requirements.txt             # Pinned exact versions
├── LICENSE                      # MIT
└── README.md
```

### Initialization

No generator — hand-crafted minimal package. Bootstrap:

```bash
mkdir -p sentinel/src/sentinel sentinel/tests sentinel/.github/workflows
touch sentinel/src/sentinel/__init__.py
cd sentinel && git init
```

### Architectural Decisions Established

**Entry point (`pyproject.toml`):**
```toml
[project.scripts]
sentinel = "sentinel.main:main"
```
Installed via `pip install -e .`; no manual PATH setup required (NFR19).

**Toolchain:**

| Tool | Role | Rationale |
|------|------|-----------|
| `argparse` | CLI parsing | stdlib, zero dependency |
| `pytest` | Testing | behavioral test style, de facto standard |
| `Ruff` | Linting | replaces flake8 + isort; single fast tool |
| `mypy` | Type checking | enforces TypedDict schema consistency at dev time |
| GitHub Actions | CI | pytest + ruff on every push; badge in README |

**Module constraint:** Each module has a single clear responsibility. No module imports from more than 2 siblings. 7 source modules, 5 test modules.

## Core Architectural Decisions

### Decision Priority Analysis

**Critical Decisions (Block Implementation):**
- Agent interface contract: `typing.Protocol` — structurally enforced by mypy at dev time
- Error → blind spot conversion: at agent boundary — `main.py` never sees raw exceptions
- HTTP client: `httpx` — zero-effort async migration path to v1.5

**Important Decisions (Shape Architecture):**
- Rate limiting: custom backoff implementation — no added dependency; covers free-tier limits
- CI pipeline: Python 3.10 + 3.12 matrix, 4-step pipeline with entry point smoke test

**Deferred Decisions (Post-MVP):**
- asyncio migration — v1.5 trigger; `httpx` already makes this zero-effort
- `tenacity` for advanced retry logic — v1.5 if retry complexity grows
- PyPI publishing — post-v1

### Data Architecture

No persistent storage for v1 (NFR6: no disk writes). All data flows in-process as TypedDicts within a single request-response cycle. No database, no file I/O, no caching layer.

**In-process data model:**

| TypedDict | Defined in | Purpose |
|---|---|---|
| `AgentResult` | `verdict.py` | Returned by every agent; carries findings, blind spots, error state |
| `BlindSpot` | `verdict.py` | Named gap: source name + reason + actionable next step |
| `VerdictSchema` | `verdict.py` | Final output; stable across all v1.x releases (NFR15) |

**Source independence registry:**

`source_registry.py` defines a module-level dict mapping source names to independence categories. Two sources in the same category count as one independent source, not two. Contributors extend by adding entries — no class hierarchy, no subclassing required.

```python
# source_registry.py
SOURCE_CATEGORIES: dict[str, str] = {
    "anthropic_claude": "llm_behavioral",
    "virustotal": "threat_intel_aggregator",
    "abuseipdb": "community_reputation",
}

def are_independent(source_a: str, source_b: str) -> bool:
    return SOURCE_CATEGORIES.get(source_a) != SOURCE_CATEGORIES.get(source_b)
```

### Authentication & Security

**Credential management — env vars only, fail-fast:**

Required environment variables: `ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`
Optional: `SENTINEL_TIMEOUT` (int seconds, default: 10)

**Startup validation sequence:**
1. `config.py` reads all env vars at module import time
2. Any missing required var → raises `ConfigError` with a human-readable message naming the missing variable(s)
3. `main.py` catches `ConfigError`, prints to stderr, exits with code 2 — before any agent is invoked
4. No env var reads occur anywhere except `config.py`

### API & Communication Patterns

**Agent interface contract — `typing.Protocol`:**

```python
# verdict.py — single source of truth for all shared types
from typing import Protocol, TypedDict

class AgentResult(TypedDict):
    source_name: str
    findings: list[str]
    blind_spots: list[str]
    raw_confidence: str | None
    error: str | None          # None = success; non-None = blind spot reason

class SentinelAgent(Protocol):
    def analyze(self, input_data: str) -> AgentResult: ...
```

Both `watchman.py` and `cipher.py` satisfy this Protocol structurally — no inheritance required. Mypy enforces the contract at dev time. Test mocks satisfy the Protocol without inheriting from anything.

**HTTP client — `httpx` (sync for v1):**

`cipher.py` uses `httpx.Client` for all VirusTotal v3 and AbuseIPDB v2 calls. Client instantiated once per agent call (not per request). Version as of pinning: `httpx>=0.27`. v1.5 migration: `httpx.Client` → `httpx.AsyncClient` — zero API surface change.

**Rate limiting — custom exponential backoff (v1):**

```python
# cipher.py — applied to API calls against free-tier rate limits
import time, httpx

def _call_with_backoff(fn, max_retries: int = 3, base_delay: float = 1.0):
    for attempt in range(max_retries):
        try:
            return fn()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429 and attempt < max_retries - 1:
                time.sleep(base_delay * (2 ** attempt))
                continue
            raise
    return fn()
```

No additional dependency. Covers VirusTotal free tier (4 req/min) and AbuseIPDB (1000/day). Upgrade to `tenacity` in v1.5 if retry logic grows in complexity.

**Error → blind spot conversion — at agent boundary:**

Each agent wraps its own execution. `main.py` inspects `error` on each `AgentResult` and routes to blind spots. No raw exceptions ever leave an agent module.

```python
# watchman.py — cipher.py mirrors this pattern exactly
def analyze(self, input_data: str) -> AgentResult:
    try:
        # ... Claude API call and response parsing ...
        return AgentResult(
            source_name="watchman", findings=[...],
            blind_spots=[], raw_confidence="Probable", error=None
        )
    except anthropic.APITimeoutError:
        return AgentResult(
            source_name="watchman", findings=[],
            blind_spots=["Watchman timed out — behavioral analysis unavailable"],
            raw_confidence=None, error="timeout"
        )
    except Exception as e:
        return AgentResult(
            source_name="watchman", findings=[],
            blind_spots=[f"Watchman failed: {type(e).__name__}"],
            raw_confidence=None, error=str(e)
        )
```

### Frontend Architecture

Not applicable — SENTINEL v1 is a pure CLI tool. No frontend, no web server, no UI layer. v2 minimal web UI deferred per roadmap (trigger: first compound incident).

### Infrastructure & Deployment

**CI pipeline — GitHub Actions:**

Python version matrix: **3.10 + 3.12** — catches compatibility regressions, contributor-friendly for those on newer Python.

Pipeline steps (sequential, all must pass on both versions):

| Step | Command | Purpose |
|---|---|---|
| 1 | `ruff check src/ tests/` | Linting + import sorting |
| 2 | `mypy src/` | Type checking — enforces Protocol contracts, TypedDict schema |
| 3 | `pytest tests/ -v` | Behavioral test suite |
| 4 | `pip install -e . && sentinel --help` | Entry point smoke test — catches packaging errors unit tests miss |

**Environment configuration:**
- No `.env` file support — env vars injected via shell or CI secrets
- CI uses GitHub Actions secrets for API keys in any integration tests; unit tests use mocked responses

**Scaling & hosting:**
- v1: local installation only (`pip install -e .`)
- No server, no daemon, no background process
- PyPI publishing: post-v1

### Decision Impact Analysis

**Implementation sequence (dependency order):**

1. `verdict.py` — define `AgentResult`, `BlindSpot`, `VerdictSchema` TypedDicts and `SentinelAgent` Protocol first; all other modules import from here
2. `config.py` — env var reading, `ConfigError`, `SENTINEL_TIMEOUT` parsing; agents import config
3. `source_registry.py` — independence taxonomy; `confidence.py` imports it
4. `confidence.py` — confidence ladder logic; depends only on `source_registry.py`
5. `watchman.py` + `cipher.py` — implement `SentinelAgent` Protocol; depend on `config.py` and `verdict.py`; can be built in parallel
6. `main.py` — orchestrator; imports all siblings; last to implement

**Cross-component dependencies:**

- `verdict.py` is the only module imported by all others — changes here have the widest blast radius; keep its public interface stable
- `config.py` imported by agents only — changes don't propagate to confidence/source logic
- `source_registry.py` imported by `confidence.py` only — contributor-extensible without touching any other module
- `main.py` imports all 6 siblings — if a module's public interface changes, `main.py` is always the integration point to update

## Implementation Patterns & Consistency Rules

**Conflict points identified:** 6 areas where independent agents could make incompatible choices without explicit patterns.

### Agent Class Pattern

Every agent is a class, never a module-level function.

**Required shape — all agents follow this exactly:**

```python
class WatchmanAgent:
    def __init__(self, config: Config) -> None:
        self._config = config

    def analyze(self, input_data: str) -> AgentResult:
        ...
```

`main.py` instantiates each agent once, passing the `Config` object, then calls `.analyze()`. The `SentinelAgent` Protocol is satisfied structurally — no inheritance from a base class. Test mocks implement `analyze()` directly on a plain class; no `MagicMock` attribute access to unchecked interfaces.

**Anti-pattern — never do this:**
```python
# ❌ module-level function — breaks Protocol, untestable without env mocking
def analyze(input_data: str) -> AgentResult:
    key = os.environ["ANTHROPIC_API_KEY"]  # hidden env dependency
    ...
```

### Config Injection Pattern

Agents never read `os.environ` directly. Config is built once in `main.py` and injected.

```python
# config.py — single source of truth for all env var access
from dataclasses import dataclass

@dataclass(frozen=True)
class Config:
    anthropic_api_key: str
    virustotal_api_key: str
    abuseipdb_api_key: str
    timeout_seconds: int = 10

def load() -> Config:
    # reads os.environ, raises ConfigError if any required var is missing
    ...
```

```python
# main.py
config = config.load()           # raises ConfigError → exit code 2 if missing vars
watchman = WatchmanAgent(config)
cipher = CipherAgent(config)
```

**Rule:** `os.environ` appears in exactly one file: `config.py`. Any module that reads `os.environ` directly is a bug.

### stderr Output Pattern

All human-readable output (progress, warnings, debug info) uses `print(..., file=sys.stderr)` directly. No logging module, no custom logger class.

```python
# ✅ correct — direct, explicit, zero boilerplate
print(f"[watchman] Analyzing input ({len(input_data)} chars)...", file=sys.stderr)

# ❌ anti-pattern — unnecessary complexity for a 30-second CLI
import logging
logger = logging.getLogger(__name__)
logger.info("Analyzing input...")
```

**Rule:** `sys.stdout` is touched only in `verdict.py`. All other modules write to `sys.stderr` or nowhere. Violations break pipeline tools that consume SENTINEL's JSON output.

### Blind Spot Format Pattern

`BlindSpot` has exactly three fields. All agents produce blind spots in this shape — never an ad-hoc dict, never a plain string.

```python
# verdict.py
class BlindSpot(TypedDict):
    source: str        # agent name: "watchman", "cipher"
    reason: str        # human-readable gap: what's missing and why
    next_step: str | None  # optional analyst instruction
```

**Reason field rule:** Always describes the gap in human terms — never an exception class name.

| ✅ Correct | ❌ Anti-pattern |
|---|---|
| `"Watchman timed out — behavioral analysis unavailable"` | `"APITimeoutError"` |
| `"VirusTotal returned no record for this IP"` | `"KeyError: 'data'"` |
| `"AbuseIPDB rate limit hit — confidence ceiling applies"` | `"429 Too Many Requests"` |

### Confidence Tier Pattern

Confidence tiers are an `Enum` defined only in `confidence.py`. No module outside `confidence.py` hardcodes the tier strings.

```python
# confidence.py
from enum import Enum

class ConfidenceTier(Enum):
    INVESTIGATING = "Investigating"
    PROBABLE = "Probable"
    CONFIRMED = "Confirmed"
```

**Rule:** All references to tier values use `ConfidenceTier.INVESTIGATING` etc. Mypy catches misuse. IDE autocomplete works correctly. A typo in `"Investigating"` is a definition-time error, not a runtime mismatch.

**Anti-pattern:**
```python
# ❌ raw string in verdict.py — mypy cannot catch typos
verdict["confidence_tier"] = "investigating"  # wrong case, silent bug
```

### Test Mock Pattern

`pytest-mock` (dev dependency only) for all agent mocking. Runtime dependencies (`anthropic`, `httpx`) are never in `requirements-dev.txt`.

**Dependency separation:**

| File | Contains |
|---|---|
| `requirements.txt` | Runtime only: `anthropic`, `httpx` (pinned exact versions) |
| `requirements-dev.txt` | Dev only: `pytest`, `pytest-mock`, `ruff`, `mypy` (pinned exact versions) |

**Agent mocking pattern:**

```python
# tests/test_watchman.py
def test_watchman_timeout_returns_blind_spot(mocker):
    mocker.patch("sentinel.watchman.anthropic.Anthropic.messages.create",
                 side_effect=anthropic.APITimeoutError(...))
    agent = WatchmanAgent(config=fake_config())
    result = agent.analyze("suspicious input")
    assert result["error"] == "timeout"
    assert len(result["blind_spots"]) == 1
```

Test mocks patch at the SDK boundary — never at the `os.environ` level (that's prevented by the config injection pattern).

### Import Discipline

**Import hierarchy — no module imports above its layer:**

```
verdict.py        ← imports nothing from sentinel.*
config.py         ← imports nothing from sentinel.*
source_registry.py ← imports nothing from sentinel.*
confidence.py     ← imports source_registry only
watchman.py       ← imports verdict, config
cipher.py         ← imports verdict, config
main.py           ← imports all siblings (top of hierarchy)
```

Circular imports are a build error. Ruff and mypy catch them at dev time. Any PR that introduces a circular import fails CI.

### Enforcement Summary

**All agents MUST:**
- Be a class with `__init__(self, config: Config)` and `analyze(self, input_data: str) -> AgentResult`
- Never read `os.environ` directly
- Catch all exceptions inside `analyze()` and return an `AgentResult` with `error` set
- Write to `sys.stderr` via `print(..., file=sys.stderr)` — never `sys.stdout`
- Use `ConfidenceTier` enum values — never hardcode tier strings
- Return `BlindSpot` TypedDicts with human-readable `reason` fields

**Pattern violations to watch for in code review:**
- `os.environ` outside `config.py`
- `print(...)` without `file=sys.stderr` outside `verdict.py`
- Raw string `"Investigating"` / `"Probable"` / `"Confirmed"` outside `confidence.py`
- `dict(...)` literals used where a typed TypedDict is expected
- Agent module imports that skip a layer in the hierarchy

## Project Structure & Boundaries

### Complete Project Directory Structure

```
sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py                 # Package marker; exposes version string only
│       ├── main.py                     # Argparse, stdin/arg auto-detect, ThreadPoolExecutor, top-level error handler
│       ├── config.py                   # Config dataclass, load(), ConfigError; single os.environ access point
│       ├── watchman.py                 # WatchmanAgent class; Claude behavioral analysis; error → blind spot
│       ├── cipher.py                   # CipherAgent class; VirusTotal v3 + AbuseIPDB v2; backoff; error → blind spot
│       ├── source_registry.py          # SOURCE_CATEGORIES dict; are_independent(); contributor entry point
│       ├── confidence.py               # ConfidenceTier enum; calculate_tier(); count_independent_sources()
│       └── verdict.py                  # AgentResult, BlindSpot, VerdictSchema TypedDicts; SentinelAgent Protocol; JSON formatter
├── tests/
│   ├── conftest.py                     # fake_config(), sample_alert, make_agent_result factory
│   ├── test_watchman.py                # WatchmanAgent behavioral tests; timeout → blind spot; malformed response → blind spot
│   ├── test_cipher.py                  # CipherAgent tests; VirusTotal/AbuseIPDB mocks; rate limit → backoff; error → blind spot
│   ├── test_source_registry.py         # are_independent() correctness; same-category returns False; new entry extensibility
│   ├── test_confidence.py              # ConfidenceTier ladder: 1 source → INVESTIGATING; 2 → PROBABLE; 3+ → CONFIRMED
│   └── test_verdict.py                 # JSON schema structure; stdout/stderr routing; blind spot format; schema stability
├── .github/
│   └── workflows/
│       └── ci.yml                      # ruff → mypy → pytest → pip install -e . smoke test; matrix: 3.10 + 3.12
├── pyproject.toml                      # [project.scripts] sentinel = "sentinel.main:main"; build metadata
├── requirements.txt                    # Runtime pinned: anthropic==0.100.0, httpx (exact versions on first pin)
├── requirements-dev.txt                # Dev pinned: pytest, pytest-mock, ruff, mypy (exact versions)
├── .env.example                        # ANTHROPIC_API_KEY=, VIRUSTOTAL_API_KEY=, ABUSEIPDB_API_KEY=, SENTINEL_TIMEOUT=10
├── .gitignore                          # venv/, __pycache__/, .env, dist/, *.egg-info/
├── LICENSE                             # MIT
├── CONTRIBUTING.md                     # How to add a source to SOURCE_CATEGORIES; agent pattern; test requirements; PR checklist
└── README.md                           # Three-sentence lead; install; usage; output example; API key setup
```

### Requirements to Structure Mapping

| Module | Functional Requirements |
|---|---|
| `main.py` | FR1–6 — input handling, parallel execution, source independence gate, top-level error handler, exit codes |
| `config.py` | FR36–38 — env var reading, fail-fast ConfigError, SENTINEL_TIMEOUT parsing |
| `watchman.py` | FR7–10, FR39 — Claude call, response parsing, behavioral findings, timeout → blind spot |
| `cipher.py` | FR11–15, FR39–40 — VirusTotal/AbuseIPDB calls, rate limiting backoff, error → blind spot, timeout |
| `source_registry.py` | FR18–20, FR41 — SOURCE_CATEGORIES, are_independent(), contributor extensibility |
| `confidence.py` | FR24–30 — independent source count, ConfidenceTier enum, ladder logic, confidence_tier int |
| `verdict.py` | FR16–17, FR21–23, FR31–35 — Protocol, TypedDicts, JSON schema, stdout/stderr routing, blind spot format, methodology/citations |
| `tests/conftest.py` | Cross-cutting — shared fixtures used across all 5 test modules |

### Data Flow

One request-response cycle, no persistent state:

```
stdin / positional arg
        │
        ▼
    main.py  ◄── config.py (Config built once, injected into agents)
        │
        ├─── ThreadPoolExecutor ──────────────────┐
        │                                         │
        ▼                                         ▼
  WatchmanAgent.analyze()              CipherAgent.analyze()
  (Claude Messages API)                (VirusTotal + AbuseIPDB)
        │                                         │
        ▼                                         ▼
   AgentResult                             AgentResult
   {findings, blind_spots, error}          {findings, blind_spots, error}
        └──────────────┬──────────────────────────┘
                       │ both results collected
                       ▼
              source_registry.are_independent()
                       │
                       ▼
              confidence.calculate_tier() → ConfidenceTier
                       │
                       ▼
              verdict.py → VerdictSchema (TypedDict)
                       │
              ┌────────┴────────┐
              ▼                 ▼
        stdout (JSON)     stderr (progress / warnings)
```

### Architectural Boundaries

**Foundation layer** — no `sentinel.*` imports; changes do not cascade:
- `verdict.py`, `config.py`, `source_registry.py`

**Logic layer** — imports foundation only:
- `confidence.py` → imports `source_registry`
- `watchman.py` → imports `verdict`, `config`
- `cipher.py` → imports `verdict`, `config`

**Orchestration layer** — imports everything; single wiring point:
- `main.py` → imports all 6 siblings

**External integration points:**

| Agent | External Service | Client | Error boundary |
|---|---|---|---|
| `WatchmanAgent` | Anthropic Messages API | `anthropic.Anthropic(timeout=config.timeout_seconds)` | Caught inside `analyze()` |
| `CipherAgent` | VirusTotal v3 REST | `httpx.Client` (session-level) | Caught inside `analyze()` |
| `CipherAgent` | AbuseIPDB v2 REST | Same `httpx.Client` session | Caught inside `analyze()` |

### Shared Test Fixtures

```python
# tests/conftest.py
import pytest
from sentinel.config import Config
from sentinel.verdict import AgentResult

@pytest.fixture
def fake_config():
    return Config(
        anthropic_api_key="test-key",
        virustotal_api_key="test-key",
        abuseipdb_api_key="test-key",
        timeout_seconds=5,
    )

@pytest.fixture
def sample_alert():
    return "Unusual outbound traffic to 185.220.101.45 on port 443 from prod-db-01"

def make_agent_result(source="watchman", findings=None, blind_spots=None, error=None):
    return AgentResult(
        source_name=source,
        findings=findings or [],
        blind_spots=blind_spots or [],   # list[BlindSpot]
        raw_confidence=None if error else "Probable",
        error=error,
    )
```

## Architecture Validation Results

### Coherence Validation ✅

**Decision Compatibility:**

| Pair | Compatible | Reason |
|---|---|---|
| Python 3.10+ ↔ anthropic 0.100.0 | ✅ | SDK requires 3.9+; 3.10 satisfies |
| anthropic SDK ↔ httpx | ✅ | Anthropic SDK uses httpx internally; no version conflicts |
| ThreadPoolExecutor ↔ sync clients | ✅ | anthropic and httpx sync clients are thread-safe |
| TypedDict + Protocol ↔ mypy | ✅ | Full support in Python 3.10+; structural typing enforced at dev time |
| ConfidenceTier Enum ↔ JSON output | ✅ | `.value` yields the string label; `confidence_tier` int is separate |
| Config frozen dataclass ↔ agent injection | ✅ | Immutable; no mutation risk across threads |

**Pattern Consistency:** All implementation patterns are internally consistent. Class-based agents satisfy the `SentinelAgent` Protocol structurally. Config injection eliminates all hidden env var dependencies. The `print(..., file=sys.stderr)` rule is enforceable by code review and Ruff custom rules.

**Structure Alignment:** Foundation → Logic → Orchestration layer hierarchy is respected by the module map and the import discipline rules. `verdict.py` as the sole source of shared types prevents drift.

### Validation Issues Found & Resolved

**Issue 1 — Critical (resolved before implementation):**

`AgentResult.blind_spots` was drafted as `list[str]` in Step 4 before the `BlindSpot` TypedDict was defined in Step 5. These are now reconciled.

**Corrected `AgentResult`:**
```python
class AgentResult(TypedDict):
    source_name: str
    findings: list[str]
    blind_spots: list[BlindSpot]   # ← corrected from list[str]
    raw_confidence: str | None
    error: str | None
```

All references to `AgentResult.blind_spots` in implementation must use `list[BlindSpot]`. Mypy will enforce this once the TypedDict is defined in `verdict.py`.

**Issue 2 — Important (resolved, implementation note added):**

`httpx.Client` timeout must be set explicitly using `config.timeout_seconds` so both agents enforce the same per-agent budget. The Anthropic client sets this via `anthropic.Anthropic(timeout=config.timeout_seconds)`; `httpx.Client` requires the same value passed as `httpx.Client(timeout=config.timeout_seconds)`.

**Issue 3 — Important (resolved, mapping specified):**

`ConfidenceTier` → `VerdictSchema` field mapping made explicit in `confidence.py`:

```python
# confidence.py
TIER_MAP: dict[ConfidenceTier, tuple[int, str]] = {
    ConfidenceTier.INVESTIGATING: (1, "Investigating"),
    ConfidenceTier.PROBABLE:      (2, "Probable"),
    ConfidenceTier.CONFIRMED:     (3, "Confirmed"),
}
```

`verdict.py` reads `TIER_MAP` to populate `confidence_tier` (int) and `verdict` (str) without reimplementing the mapping.

### Requirements Coverage Validation ✅

**Functional Requirements — all 41 FRs covered:**

| Module | FRs Addressed |
|---|---|
| `main.py` | FR1–6 — input, parallelism, independence gate, error handler, exit codes |
| `config.py` | FR36–38 — env vars, fail-fast, SENTINEL_TIMEOUT |
| `watchman.py` | FR7–10, FR39 — Claude call, findings, timeout → blind spot |
| `cipher.py` | FR11–15, FR39–40 — VirusTotal/AbuseIPDB, backoff, error → blind spot |
| `source_registry.py` | FR18–20, FR41 — taxonomy, independence check, extensibility |
| `confidence.py` | FR24–30 — source count, ConfidenceTier ladder, int mapping |
| `verdict.py` | FR16–17, FR21–23, FR31–35 — Protocol, TypedDicts, schema, routing, blind spot format |

**Non-Functional Requirements — all 19 NFRs addressed:**

| NFR | Mechanism | Status |
|---|---|---|
| ≤30s cold start (NFR1) | Parallel agents; no lazy imports | ✅ |
| 10s per agent (NFR2) | `timeout=config.timeout_seconds` on both clients | ✅ |
| 25s total budget (NFR3) | Parallel design: 10s phase + overhead ≪ 25s by construction | ✅ |
| SENTINEL_TIMEOUT env var (NFR4) | `config.py` reads and defaults to 10 | ✅ |
| Env vars only (NFR5) | `config.py` sole `os.environ` access point; enforcement rule | ✅ |
| No disk writes (NFR6) | No file I/O anywhere; testable behavioral requirement | ✅ |
| Minimal deps (NFR8–9) | Runtime: `anthropic` + `httpx` only | ✅ |
| All tests pass on CI (NFR11) | GitHub Actions 4-step pipeline; 3.10 + 3.12 matrix | ✅ |
| Never crash on any input (NFR13) | Top-level handler in `main.py`; agent-level try/except | ✅ |
| Agent failure isolation (NFR14) | Error → blind spot at agent boundary; orchestrator clean | ✅ |
| JSON schema stable v1.x (NFR15) | `VerdictSchema` TypedDict; single definition in `verdict.py` | ✅ |
| pip-installable (NFR19) | `pyproject.toml` `[project.scripts]` | ✅ |

### Implementation Readiness Validation ✅

**Decision Completeness:** All critical decisions documented with rationale. Technology versions verified (anthropic 0.100.0, httpx>=0.27, Python 3.10+). No blocking unknowns remain.

**Structure Completeness:** Complete file tree defined. Every file annotated with responsibility. All integration points specified including client timeout configuration.

**Pattern Completeness:** Six conflict categories resolved with enforceable rules and anti-pattern examples. Import hierarchy defined. Test mock strategy specified. Dev/runtime dependency split documented.

### Architecture Completeness Checklist

**Requirements Analysis**

- [x] Project context thoroughly analyzed
- [x] Scale and complexity assessed (low operational, high precision)
- [x] Technical constraints identified (Python 3.10+, three APIs, MIT license, solo dev)
- [x] Cross-cutting concerns mapped (6 concerns, all addressed)

**Architectural Decisions**

- [x] Critical decisions documented with versions (anthropic 0.100.0, httpx>=0.27)
- [x] Technology stack fully specified (7 modules, toolchain, CI)
- [x] Integration patterns defined (Protocol, TypedDicts, error boundary)
- [x] Performance considerations addressed (parallel execution, timeout budget)

**Implementation Patterns**

- [x] Naming conventions established (snake_case, ConfidenceTier enum, BlindSpot format)
- [x] Structure patterns defined (class-based agents, config injection, layer hierarchy)
- [x] Communication patterns specified (stdout/stderr discipline, TypedDict contracts)
- [x] Process patterns documented (error → blind spot, backoff, agent boundary enforcement)

**Project Structure**

- [x] Complete directory structure defined (all 16 files annotated)
- [x] Component boundaries established (foundation / logic / orchestration layers)
- [x] Integration points mapped (Anthropic, VirusTotal, AbuseIPDB with timeout config)
- [x] Requirements to structure mapping complete (all 41 FRs mapped to modules)

### Architecture Readiness Assessment

**Overall Status:** READY FOR IMPLEMENTATION

**Confidence Level:** High — all 16 checklist items confirmed; no critical gaps remain; three issues found during validation were resolved before this section was written.

**Key Strengths:**
- Pure-function pipeline design makes every component independently testable
- `verdict.py` as the single source of shared types eliminates schema drift across modules
- Error → blind spot conversion at agent boundary means `main.py` is structurally incapable of crashing on agent failure
- `ConfidenceTier` enum + `TIER_MAP` makes the confidence ladder a single definition point with no string literals scattered through the codebase
- Import hierarchy enforced by module design, not just convention — circular imports are a build error, not a style issue

**Areas for Future Enhancement (v1.5+):**
- asyncio migration: `httpx.AsyncClient` swap is zero-effort given httpx selection
- `tenacity` for advanced retry logic if backoff complexity grows
- `pytest-cov` coverage reporting once baseline test suite is established
- PyPI publishing workflow

### Implementation Handoff

**AI Agent Guidelines:**
- `verdict.py` is implemented first — all other modules import from it
- `AgentResult.blind_spots` is `list[BlindSpot]`, not `list[str]` — mypy enforces this
- `httpx.Client(timeout=config.timeout_seconds)` — explicit timeout required, matches Anthropic client
- `TIER_MAP` lives in `confidence.py` — `verdict.py` imports it; no mapping duplication
- All six pattern enforcement rules apply to every line of every module

**First Implementation Step:**
```bash
pip install -e ".[dev]"
# implement verdict.py first: AgentResult, BlindSpot, VerdictSchema TypedDicts + SentinelAgent Protocol
# mypy src/ must pass before any other module is written
```
