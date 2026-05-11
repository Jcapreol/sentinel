---
stepsCompleted: [1, 2, 3, 4]
inputDocuments:
  - '_bmad-output/planning-artifacts/prd.md'
  - '_bmad-output/planning-artifacts/architecture.md'
---

# Sentinel - Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for Sentinel, decomposing the requirements from the PRD and Architecture into implementable stories.

## Requirements Inventory

### Functional Requirements

FR1: An analyst can submit a security alert, log line, or IOC as a positional argument to SENTINEL
FR2: An analyst can submit input to SENTINEL via stdin pipe
FR3: SENTINEL auto-detects whether input arrives via stdin or positional argument without requiring user configuration
FR4: SENTINEL reports a clear, actionable error message and exits with code 2 when no input is provided
FR5: SENTINEL runs Watchman (LLM behavioral analysis) and Cipher (threat intelligence lookup) as independent analysis agents on every input
FR6: SENTINEL enforces source independence — signals from the same data pipeline count as one source regardless of how many data points they produce
FR7: SENTINEL maintains a source registry that categorizes each data source by independence group
FR8: SENTINEL produces a confidence tier based on the count of structurally independent corroborating sources
FR9: SENTINEL maps confidence tiers to human-readable labels: Investigating (1 independent source), Probable (2 independent sources), Confirmed (3+ independent sources)
FR10: SENTINEL returns an Investigating verdict with "Watchman output malformed" as a named blind spot when Watchman returns output that cannot be parsed — the analyst always receives a usable response
FR11: SENTINEL generates a methodology section in every verdict listing agents run, execution order, and analysis logic applied
FR12: SENTINEL generates a citations section in every verdict listing specific indicators, data sources, source identifiers, and independent source count
FR13: SENTINEL generates a named blind spots section in every verdict listing data sources that were unavailable and the specific uncertainty each gap creates
FR14: SENTINEL's named blind spots section is always present in output — it is an empty array when all sources returned data, never absent or null
FR15: Each named blind spot includes an actionable implication: what the analyst should check to close the gap
FR16: A contributor can extend SENTINEL's source registry to register a new corroboration source without modifying core engine logic
FR17: Cipher queries VirusTotal for IP, domain, and file hash reputation data
FR18: Cipher queries AbuseIPDB for IP reputation and abuse confidence data
FR19: Cipher returns a structured result with an explicit reason when a source is not applicable to the input type (e.g., internal IPs have no external threat intel)
FR20: SENTINEL documents VirusTotal free-tier rate limits explicitly in the README (4 req/min, 500 req/day)
FR21: SENTINEL outputs structured JSON to stdout on every completed analysis
FR22: SENTINEL outputs human-readable status and progress messages to stderr only — stdout is always clean JSON
FR23: SENTINEL's JSON output schema is stable across all v1.x patch releases — no field renames, removals, or type changes without a major version increment
FR24: SENTINEL's JSON output includes `confidence_tier` as a machine-readable integer: 1 = Investigating, 2 = Probable, 3 = Confirmed
FR25: SENTINEL's JSON output includes `verdict` as a string label matching the confidence tier
FR26: A pipeline tool can parse SENTINEL's JSON output and extract any field without SENTINEL-specific parsing logic
FR27: SENTINEL exits with code 0 when a verdict is produced at any confidence tier
FR28: SENTINEL exits with code 1 when analysis fails due to an unrecoverable API error
FR29: SENTINEL exits with code 2 when input is missing, empty, or required environment variables are not set
FR30: SENTINEL reads API credentials exclusively from environment variables (ANTHROPIC_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY)
FR31: SENTINEL fails immediately with a clear error message when required environment variables are absent
FR32: SENTINEL does not read credentials from config files, .env files, or command-line arguments
FR33: SENTINEL's test suite is publicly accessible in the repository and runs automatically on every commit
FR34: SENTINEL's repository displays a CI status badge showing whether the test suite is passing
FR35: SENTINEL's README states the data handling guarantee explicitly: no incident data is stored; the only external transmission is to the Anthropic and VirusTotal/AbuseIPDB APIs as required for analysis
FR36: SENTINEL's README states connectivity requirements and limitations explicitly: internet access to Anthropic and VirusTotal APIs required; air-gapped environments not supported in v1
FR37: A new user can reach a working verdict within 5 minutes of cloning the repository
FR38: SENTINEL's codebase is published under the MIT license from the first public commit
FR39: SENTINEL returns an Investigating verdict with Cipher named as a blind spot when Cipher cannot complete analysis — analysis errors in individual agents do not prevent a verdict from being produced
FR40: SENTINEL never writes input data, IOCs, or alert content to disk during or after analysis
FR41: SENTINEL analysis agents expose a consistent interface contract — each agent accepts a structured input and returns a structured result with a defined schema

### NonFunctional Requirements

NFR1: End-to-end verdict time — from command execution (Enter) to complete JSON fully printed on stdout — must not exceed 30 seconds on cold start. No warm-start exceptions; measured under worst case.
NFR2: Each analysis agent (Watchman, Cipher) has an individual timeout of 10 seconds by default. Agents that exceed their timeout window are treated as named blind spots; analysis proceeds with remaining sources.
NFR3: Total agent execution budget is 25 seconds maximum, leaving 5 seconds for verdict formatting and output.
NFR4: Agent timeout is configurable via the SENTINEL_TIMEOUT environment variable (integer seconds). Defaults to 10 seconds per agent if not set.
NFR5: API credentials are never stored in plaintext files, config files, or command-line arguments. Credentials exist only in the process environment during execution.
NFR6: No input data (alert content, IOCs, log lines) is written to disk at any point during analysis. All processing is in-memory only.
NFR7: No telemetry, usage tracking, or analytics data is transmitted from SENTINEL to any party.
NFR8: All production dependencies are pinned to exact versions in requirements.txt. No floating version ranges in v1.
NFR9: The dependency set is minimal — each dependency is a deliberate inclusion; transitive dependency bloat is avoided.
NFR10: SENTINEL is released under the MIT license. Full license text is present in the repository root from the first commit.
NFR11: All tests in the public test suite must pass on every commit. CI is the merge gate; no commit merges with a failing test suite.
NFR12: No coverage floor is enforced in v1. Test quality takes precedence over coverage percentage.
NFR13: SENTINEL must never crash or exit unhandled on any input, including malformed alerts, empty input, binary data, or agent failures. Every error path produces a structured exit or an Investigating verdict with the failure named as a blind spot.
NFR14: Agent failures are isolated — a timeout or error in one agent does not prevent the other agent from completing or a verdict from being produced.
NFR15: SENTINEL's JSON output schema produces the same field names, types, and structure on every run regardless of confidence tier or agent error state. Schema consistency is a hard invariant across all v1.x releases.
NFR16: Anthropic API (Watchman) integration must handle HTTP errors, connection timeouts, and malformed responses without propagating exceptions — all failures become named blind spots.
NFR17: VirusTotal and AbuseIPDB (Cipher) integrations must handle HTTP errors, 429 rate-limit responses, and connection timeouts gracefully. Rate-limit responses are surfaced as named blind spots in v1.
NFR18: SENTINEL's stdout JSON is parseable by standard tools (jq, Python json.loads, any JSON parser) without SENTINEL-specific libraries or schemas.
NFR19: The `sentinel` command is registered as a standard entry point installable via `pip install .` or `pip install -e .`; no manual PATH manipulation required after install.

### Additional Requirements

Architecture technical requirements that affect implementation:

- AR1: Implementation dependency order must be respected — verdict.py first (all modules import from it), then config.py and source_registry.py, then confidence.py, then watchman.py and cipher.py in parallel, then main.py last
- AR2: All agents must implement the SentinelAgent Protocol (typing.Protocol) with signature `analyze(self, input_data: str) -> AgentResult` — enforced by mypy
- AR3: Config is a frozen dataclass built once in main.py and injected into each agent's __init__; no agent module reads os.environ directly
- AR4: Three required env vars: ANTHROPIC_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY (architecture added ABUSEIPDB_API_KEY; PRD FR30 should be read as including all three)
- AR5: HTTP client for Cipher is httpx.Client with explicit timeout=config.timeout_seconds — must match Anthropic client's timeout budget
- AR6: ConfidenceTier is an Enum in confidence.py (INVESTIGATING, PROBABLE, CONFIRMED); no raw string literals for tier values anywhere else
- AR7: TIER_MAP in confidence.py maps ConfidenceTier → (int, str) for verdict output fields; verdict.py reads this mapping
- AR8: BlindSpot TypedDict has three fields: source (str), reason (str, human-readable — never an exception class name), next_step (str | None)
- AR9: AgentResult.blind_spots is list[BlindSpot] — not list[str]
- AR10: Error → blind spot conversion happens inside each agent's analyze() method; main.py never catches raw exceptions from agents
- AR11: CI pipeline: ruff check → mypy → pytest → pip install -e . smoke test; Python 3.10 + 3.12 matrix; all 4 steps must pass on both versions
- AR12: Runtime dependencies: anthropic + httpx only (pinned in requirements.txt); dev dependencies: pytest, pytest-mock, ruff, mypy (pinned in requirements-dev.txt)
- AR13: src/ layout with pyproject.toml [project.scripts] entry point: `sentinel = "sentinel.main:main"`
- AR14: CONTRIBUTING.md must document how to add a new source to SOURCE_CATEGORIES in source_registry.py
- AR15: conftest.py provides shared test fixtures: fake_config(), sample_alert, make_agent_result() factory

### UX Design Requirements

Not applicable — SENTINEL v1 is a pure CLI tool with no UI layer.

### FR Coverage Map

FR1: Epic 4 — argparse positional arg
FR2: Epic 4 — stdin detection
FR3: Epic 4 — auto-detect stdin vs. arg
FR4: Epic 4 — error message + exit code 2
FR5: Epic 4 — ThreadPoolExecutor parallel agents
FR6: Epic 2 — are_independent()
FR7: Epic 2 — SOURCE_CATEGORIES registry
FR8: Epic 2 — calculate_tier()
FR9: Epic 2 — ConfidenceTier labels
FR10: Epic 3 — Watchman malformed output → blind spot
FR11: Epic 4 — methodology section in verdict
FR12: Epic 4 — citations section in verdict
FR13: Epic 4 — named blind spots section
FR14: Epic 4 — always-present blind_spots array
FR15: Epic 4 — actionable blind spot implications
FR16: Epic 2 — contributor-extensible SOURCE_CATEGORIES
FR17: Epic 3 — VirusTotal IP/domain/hash lookup
FR18: Epic 3 — AbuseIPDB reputation lookup
FR19: Epic 3 — structured null for non-applicable inputs
FR20: Epic 4 — README rate limit documentation
FR21: Epic 4 — JSON to stdout
FR22: Epic 4 — human-readable to stderr only
FR23: Epic 4 — stable schema across v1.x
FR24: Epic 4 — confidence_tier integer
FR25: Epic 4 — verdict string label
FR26: Epic 4 — pipeable output
FR27: Epic 4 — exit code 0
FR28: Epic 4 — exit code 1
FR29: Epic 1 + 4 — env var validation (Epic 1); exit code 2 wired in main.py (Epic 4)
FR30: Epic 1 — config reads all 3 env vars (ANTHROPIC_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY)
FR31: Epic 1 — ConfigError fail-fast
FR32: Epic 1 — no config files
FR33: Epic 1 — CI pipeline + GitHub Actions
FR34: Epic 1 — CI badge in README
FR35: Epic 4 — README data handling guarantee
FR36: Epic 4 — README connectivity limitations
FR37: Epic 4 — ≤5-min setup in README
FR38: Epic 1 — MIT license
FR39: Epic 3 — agent error → blind spot (both agents)
FR40: Epic 1 + 3 — no disk writes enforced across all modules
FR41: Epic 1 + 3 — SentinelAgent Protocol defined (Epic 1); implemented by both agents (Epic 3)

## Epic List

### Epic 1: Project Foundation
The SENTINEL package is installable, configurable, and CI-verified from the first commit. A developer can clone, install, and get a proper error message — the scaffold is production-quality before any analysis logic exists.
**FRs covered:** FR29 (partial), FR31, FR32, FR33, FR34, FR38, FR40 (partial), FR41 (partial)
**NFRs covered:** NFR8, NFR9, NFR10, NFR11, NFR12, NFR19
**ARs covered:** AR1, AR2, AR3, AR4, AR11, AR12, AR13, AR15

### Epic 2: Source Independence & Confidence Engine
SENTINEL's epistemological core exists and is fully tested. The source independence checker correctly classifies data pipelines, and the confidence ladder maps independent source counts to human-readable tiers. A contributor can read and extend the source registry.
**FRs covered:** FR6, FR7, FR8, FR9, FR16
**ARs covered:** AR6, AR7

### Epic 3: Analysis Agents
Both analysis pipelines — Watchman (Claude behavioral analysis) and Cipher (VirusTotal + AbuseIPDB) — are implemented and independently testable with mocked APIs. Each agent converts its own failures to named blind spots; no exception leaves an agent boundary.
**FRs covered:** FR5 (partial), FR10, FR17, FR18, FR19, FR39, FR40 (partial), FR41 (full)
**NFRs covered:** NFR2, NFR4, NFR13, NFR14, NFR16, NFR17
**ARs covered:** AR2, AR3, AR5, AR8, AR9, AR10, AR12

### Epic 4: Verdict Orchestration & CLI Contract
SENTINEL is fully operational. An analyst can paste or pipe any security alert and receive a corroborated, structured verdict in under 30 seconds. The JSON output is stable, pipeable, and consistent across all v1.x releases. The README, CONTRIBUTING.md, and open-source hygiene are complete.
**FRs covered:** FR1, FR2, FR3, FR4, FR5 (full), FR11, FR12, FR13, FR14, FR15, FR20, FR21, FR22, FR23, FR24, FR25, FR26, FR27, FR28, FR29 (full), FR30, FR35, FR36, FR37, FR40 (full)
**NFRs covered:** NFR1, NFR3, NFR5, NFR6, NFR7, NFR15, NFR18, NFR19 (full)
**ARs covered:** AR14

---

## Epic 1: Project Foundation

The SENTINEL package is installable, configurable, and CI-verified from the first commit. A developer can clone, install, and get proper error handling — production-quality scaffold before any analysis logic exists.

### Story 1.1: Package Scaffold & CI Pipeline

As a developer,
I want the SENTINEL package installable and CI-verified from a fresh clone,
So that every subsequent story starts from a production-quality foundation with automated quality gates from day one.

**Acceptance Criteria:**

**Given** the repository is freshly cloned and `pip install -e ".[dev]"` is run,
**When** the developer types `sentinel --help`,
**Then** the command is available in PATH with exit code 0 and no manual PATH configuration required.

**Given** the GitHub Actions CI workflow triggers on push to main,
**When** any Python source file changes,
**Then** all four steps pass on both Python 3.10 and 3.12: `ruff check src/ tests/`, `mypy src/`, `pytest tests/ -v`, and `pip install -e . && sentinel --help`.

**Given** the repository root is inspected,
**When** a new contributor opens the project,
**Then** the following files are present: `pyproject.toml` (with `[project.scripts]` entry point `sentinel = "sentinel.main:main"`), `requirements.txt` (runtime deps pinned to exact versions), `requirements-dev.txt` (dev deps pinned to exact versions), `LICENSE` (MIT full text), `.gitignore` (excludes `venv/`, `.env`, `__pycache__/`, `dist/`, `*.egg-info/`), `.env.example` (lists all 3 required env vars with blank values and SENTINEL_TIMEOUT commented example), `README.md` (3-sentence placeholder — full content in Story 4.3).

**Given** `src/sentinel/__init__.py` is imported,
**When** `sentinel.__version__` is accessed,
**Then** a version string is returned without error.

---

### Story 1.2: Shared Type Definitions

As a developer,
I want all cross-module data contracts defined in a single source-of-truth module,
So that every other module can import typed structures, mypy enforces the contracts at dev time, and no module redefines types independently.

**Acceptance Criteria:**

**Given** `verdict.py` is implemented,
**When** `mypy src/` runs,
**Then** no type errors are reported for any TypedDict or Protocol definition.

**Given** `AgentResult` is imported from `sentinel.verdict`,
**When** its fields are inspected,
**Then** it has exactly: `source_name: str`, `findings: list[str]`, `blind_spots: list[BlindSpot]`, `raw_confidence: str | None`, `error: str | None`.

**Given** `BlindSpot` is imported from `sentinel.verdict`,
**When** its fields are inspected,
**Then** it has exactly: `source: str`, `reason: str`, `next_step: str | None`.

**Given** `VerdictSchema` is imported from `sentinel.verdict`,
**When** its fields are inspected,
**Then** it has exactly: `verdict: str`, `confidence_tier: int`, `methodology: list[dict]`, `citations: list[dict]`, `blind_spots: list[BlindSpot]`, `source_independence_confirmed: bool`, `execution_time_seconds: float`, `timestamp: str`.

**Given** `SentinelAgent` Protocol is imported from `sentinel.verdict`,
**When** a class with `analyze(self, input_data: str) -> AgentResult` is checked by mypy,
**Then** mypy accepts it as satisfying the Protocol without the class inheriting from anything.

**Given** `verdict.py` is inspected for imports,
**When** its import statements are reviewed,
**Then** it imports nothing from `sentinel.*` — it is the foundation layer with no intra-package dependencies.

**And** `tests/test_verdict.py` verifies schema field presence, correct types for all TypedDict fields, and that the Protocol signature matches the defined contract.

---

### Story 1.3: Config Module & Test Infrastructure

As a developer,
I want environment variable reading and validation isolated in one module and shared test fixtures available to all test files,
So that agents receive a typed `Config` object without touching `os.environ` directly, missing credentials are caught at startup before any API call, and all test files share a consistent set of fixtures.

**Acceptance Criteria:**

**Given** all three env vars (`ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) are set,
**When** `config.load()` is called,
**Then** a frozen `Config` dataclass is returned with all three keys populated and `timeout_seconds` defaulting to 10.

**Given** `SENTINEL_TIMEOUT` is set to `"15"`,
**When** `config.load()` is called,
**Then** the returned `Config` has `timeout_seconds == 15`.

**Given** any one of the three required env vars is absent,
**When** `config.load()` is called,
**Then** `ConfigError` is raised with a message that names the specific missing variable.

**Given** `config.py` is implemented,
**When** `mypy src/` runs,
**Then** no type errors are reported, and `os.environ` appears in `config.py` only — not in any other module.

**Given** `tests/conftest.py` is present,
**When** any test file imports from it,
**Then** the following are available: `fake_config()` fixture returning `Config` with dummy keys and `timeout_seconds=5`, `sample_alert` fixture returning a realistic security alert string, `make_agent_result(source, findings, blind_spots, error)` factory returning a valid `AgentResult`.

**And** `tests/test_config.py` passes for: all 3 vars present → Config returned with correct values, SENTINEL_TIMEOUT="15" → timeout_seconds=15, each of the 3 missing-var scenarios raises ConfigError naming the specific variable, SENTINEL_TIMEOUT not set → defaults to 10.

---

## Epic 2: Source Independence & Confidence Engine

SENTINEL's epistemological core exists and is fully tested. The source independence checker correctly classifies data pipelines, and the confidence ladder maps independent source counts to human-readable tiers. A contributor can read and extend the source registry.

### Story 2.1: Source Registry

As a contributor,
I want a clearly defined, extensible registry of independent source categories,
So that I can add a new corroboration source by adding one entry to one dict, and the independence check automatically applies without touching any other logic.

**Acceptance Criteria:**

**Given** `source_registry.py` is implemented,
**When** `are_independent("anthropic_claude", "virustotal")` is called,
**Then** it returns `True` — they are in different source categories (`llm_behavioral` vs `threat_intel_aggregator`).

**Given** two sources in the same category,
**When** `are_independent("virustotal", "virustotal")` is called,
**Then** it returns `False` — same category means one independent source, not two.

**Given** both VirusTotal and AbuseIPDB are classified,
**When** `are_independent("virustotal", "abuseipdb")` is called,
**Then** it returns `False` — both are in `community_reputation`, confirming Cipher counts as one independent source regardless of which sub-APIs returned data.

**Given** a contributor adds `"shodan": "network_scanning"` to `SOURCE_CATEGORIES`,
**When** `are_independent("shodan", "virustotal")` is called,
**Then** it returns `True` with no code changes outside `source_registry.py`.

**Given** an unknown source name is passed,
**When** `are_independent("unknown_source", "virustotal")` is called,
**Then** it returns `False` — unknown sources default to dependent (conservative classification).

**And** `source_registry.py` imports nothing from `sentinel.*`, and `tests/test_source_registry.py` covers: two independent sources → True, same source → False, same-category different names → False, unknown source → False, new entry extensibility.

---

### Story 2.2: Confidence Engine

As an analyst,
I want SENTINEL to map the count of independent corroborating sources to a human-readable confidence tier,
So that I know immediately whether to investigate further, escalate, or act — without interpreting opaque ML percentages.

**Acceptance Criteria:**

**Given** results from one independent source only,
**When** `calculate_tier([watchman_result])` is called,
**Then** it returns `ConfidenceTier.INVESTIGATING`.

**Given** results from two independent sources (Watchman + Cipher),
**When** `calculate_tier([watchman_result, cipher_result])` is called with `are_independent` confirming independence,
**Then** it returns `ConfidenceTier.PROBABLE`.

**Given** results from three or more independent sources,
**When** `calculate_tier([...])` is called,
**Then** it returns `ConfidenceTier.CONFIRMED`.

**Given** `ConfidenceTier` is defined as an `Enum`,
**When** its members are inspected,
**Then** `ConfidenceTier.INVESTIGATING.value == "Investigating"`, `ConfidenceTier.PROBABLE.value == "Probable"`, `ConfidenceTier.CONFIRMED.value == "Confirmed"`.

**Given** `TIER_MAP` is defined in `confidence.py`,
**When** `TIER_MAP[ConfidenceTier.PROBABLE]` is accessed,
**Then** it returns `(2, "Probable")` — the `(int, str)` tuple used to populate `confidence_tier` and `verdict` in `VerdictSchema`.

**Given** an agent result with `error` set,
**When** `count_independent_sources([watchman_result, failed_cipher_result])` is called,
**Then** the failed agent is excluded from the independence count — only successful results contribute to corroboration.

**And** `confidence.py` imports only from `source_registry` and `verdict`, and `tests/test_confidence.py` covers: 0 sources, 1 source, 2 independent sources, 2 dependent sources (counts as 1), 3+ sources, failed agent excluded from count.

---

## Epic 3: Analysis Agents

Both analysis pipelines — Watchman (Claude behavioral analysis) and Cipher (VirusTotal + AbuseIPDB) — are implemented and independently testable with mocked APIs. Each agent converts its own failures to named blind spots; no exception leaves an agent boundary.

### Story 3.1: Watchman Agent

As an analyst,
I want SENTINEL to run behavioral analysis on my alert using Claude,
So that I get structured findings about whether the alert pattern matches known threat TTPs — and a named blind spot if the analysis cannot complete, rather than a crash.

**Acceptance Criteria:**

**Given** a valid `Config` and alert text,
**When** `WatchmanAgent(config).analyze(input_data)` is called with a mocked Anthropic client returning a well-formed response,
**Then** it returns an `AgentResult` with `source_name="watchman"`, non-empty `findings`, `blind_spots=[]`, and `error=None`.

**Given** the Anthropic client raises `APITimeoutError`,
**When** `analyze(input_data)` is called,
**Then** it returns an `AgentResult` with `error="timeout"`, a `BlindSpot` in `blind_spots` with a human-readable `reason` (not "APITimeoutError"), and `findings=[]` — no exception propagates.

**Given** the Anthropic client returns a response that cannot be parsed into the expected schema,
**When** `analyze(input_data)` is called,
**Then** it returns an `AgentResult` with `error="malformed_output"` and `blind_spots` containing a `BlindSpot` with `reason="Watchman output malformed — behavioral analysis unavailable"` — satisfying FR10.

**Given** any other exception is raised during analysis,
**When** `analyze(input_data)` is called,
**Then** it returns an `AgentResult` with `error` set and a descriptive `BlindSpot` — no raw exception reaches the caller.

**Given** `WatchmanAgent` is inspected by mypy against `SentinelAgent` Protocol,
**When** type checking runs,
**Then** no type errors are reported — it satisfies the Protocol structurally without inheriting from anything.

**And** `WatchmanAgent.__init__` accepts only `config: Config` with no `os.environ` access inside the class, and `tests/test_watchman.py` uses `pytest-mock` to patch the Anthropic SDK at the call boundary, covering: success, timeout → blind spot, malformed output → blind spot, generic exception → blind spot.

---

### Story 3.2: Cipher Agent

As an analyst,
I want SENTINEL to look up my alert's IOCs against VirusTotal and AbuseIPDB,
So that I get independent threat intelligence on IPs, domains, and file hashes — and a named blind spot if the lookup cannot complete or the input type is not applicable, rather than a crash.

**Acceptance Criteria:**

**Given** a valid `Config` and an alert containing a public IP address,
**When** `CipherAgent(config).analyze(input_data)` is called with mocked httpx returning valid VirusTotal and AbuseIPDB responses,
**Then** it returns an `AgentResult` with `source_name="cipher"`, non-empty `findings` citing both sources, `blind_spots=[]`, and `error=None`.

**Given** the alert input contains no extractable IOC (e.g., a purely internal invocation with no external IP),
**When** `analyze(input_data)` is called,
**Then** it returns an `AgentResult` with `findings=[]`, `blind_spots` containing a `BlindSpot` with `reason` explaining why threat intel is not applicable, and `error=None` — a structured null result, not a failure (FR19).

**Given** VirusTotal returns HTTP 429 (rate limit),
**When** `analyze(input_data)` is called,
**Then** it returns an `AgentResult` with a `BlindSpot` naming VirusTotal as unavailable due to rate limiting and `error="rate_limited"` — no retry in v1; analysis continues with AbuseIPDB result if available.

**Given** `httpx.Client` raises a connection timeout,
**When** `analyze(input_data)` is called,
**Then** it returns an `AgentResult` with `error="timeout"` and a `BlindSpot` with a human-readable `reason` — no raw exception reaches the caller.

**Given** `CipherAgent` is inspected by mypy against `SentinelAgent` Protocol,
**When** type checking runs,
**Then** no type errors are reported.

**And** `CipherAgent.__init__` accepts only `config: Config` and instantiates `httpx.Client(timeout=config.timeout_seconds)`. `tests/test_cipher.py` uses `pytest-mock` to patch `httpx.Client` at the call boundary, covering: success (IP found), structured null (no IOC), rate limit → blind spot, timeout → blind spot, generic exception → blind spot.

---

## Epic 4: Verdict Orchestration & CLI Contract

SENTINEL is fully operational. An analyst can paste or pipe any security alert and receive a corroborated, structured verdict in under 30 seconds. The JSON output is stable and pipeable across all v1.x releases. README, CONTRIBUTING.md, and open-source hygiene are complete.

### Story 4.1: Verdict Assembly & JSON Output

As a pipeline builder,
I want SENTINEL to output a stable, complete JSON verdict to stdout on every run,
So that I can parse `confidence_tier` with `jq` reliably and my downstream tooling never breaks across v1.x patch releases.

**Acceptance Criteria:**

**Given** both agent results, the confidence tier, and the source independence check,
**When** `assemble_verdict(watchman_result, cipher_result, tier, start_time)` is called,
**Then** it returns a `VerdictSchema` TypedDict with all 8 fields populated: `verdict` (string from `TIER_MAP`), `confidence_tier` (int from `TIER_MAP`), `methodology` (list of agent steps), `citations` (list of source findings), `blind_spots` (merged list from both agents — never null, always a list), `source_independence_confirmed` (bool), `execution_time_seconds` (float), `timestamp` (ISO 8601 UTC string).

**Given** a fully assembled `VerdictSchema`,
**When** it is serialized and printed,
**Then** JSON goes to stdout only and all human-readable progress messages go to stderr only — no mixing.

**Given** the JSON is printed to stdout,
**When** parsed by `json.loads()` or `jq`,
**Then** it is valid JSON with no trailing text, no ANSI codes, and no extra whitespace breaking parsers.

**Given** both agents errored and produced only blind spots,
**When** the verdict is assembled,
**Then** `blind_spots` is a non-empty list (never `[]` or `null`), `confidence_tier` is 1 (Investigating), and the verdict still exits with code 0.

**Given** `blind_spots` from both agents are combined,
**When** the final verdict is assembled,
**Then** all blind spots from both agents appear in the output array — none are dropped.

**And** `tests/test_verdict.py` adds tests for: correct field values for each confidence tier, blind_spots always a list, JSON round-trip stability, stdout/stderr routing verified separately, schema field presence on every run regardless of agent outcome.

---

### Story 4.2: CLI Orchestrator

As an analyst,
I want to submit a security alert by argument or stdin pipe and have both agents run in parallel,
So that I get a verdict in under 30 seconds with correct exit codes for any outcome — success, analysis error, or missing input.

**Acceptance Criteria:**

**Given** a positional argument is provided (`sentinel "alert text"`),
**When** the command runs,
**Then** SENTINEL uses the argument as input and does not attempt to read stdin.

**Given** input is piped via stdin (`echo "alert" | sentinel`),
**When** the command runs,
**Then** SENTINEL reads from stdin automatically with no flag required.

**Given** neither argument nor stdin is provided,
**When** `sentinel` is run with no input,
**Then** it prints a usage message to stderr and exits with code 2.

**Given** a valid input and all env vars set,
**When** SENTINEL runs,
**Then** Watchman and Cipher are invoked concurrently via `ThreadPoolExecutor` and both results are collected before `assemble_verdict` is called.

**Given** one agent times out (exceeds `config.timeout_seconds`),
**When** `ThreadPoolExecutor` collects results,
**Then** the timed-out agent's result is treated as a blind spot and the other agent's result is used — analysis always produces a verdict, never hangs.

**Given** a verdict is produced at any confidence tier,
**When** the command completes,
**Then** it exits with code 0.

**Given** an unrecoverable error occurs (both agents fail and no verdict can be assembled),
**When** the command completes,
**Then** it exits with code 1.

**Given** required env vars are missing,
**When** `sentinel` is run,
**Then** `ConfigError` is caught at the top level, a clear message is printed to stderr naming the missing variable, and it exits with code 2.

**And** `main.py` imports all 6 sibling modules and is the only module that does so. The top-level handler catches all unhandled exceptions and always produces either a structured exit or a JSON verdict — SENTINEL never crashes with an unhandled traceback.

---

### Story 4.3: Documentation & Open-Source Hygiene

As a new user or contributor,
I want complete, honest documentation from the first public commit,
So that I can reach a working verdict in under 5 minutes and understand exactly what SENTINEL can and cannot do before I trust it with a real incident.

**Acceptance Criteria:**

**Given** `README.md` is complete,
**When** a new user reads it,
**Then** it contains in order: a three-sentence product description, install instructions (`git clone` → `pip install -e .` → set env vars → `sentinel "test"`), the data handling guarantee verbatim (*"SENTINEL does not store or transmit your incident data beyond the analysis APIs"*), the connectivity limitation verbatim (*"SENTINEL requires internet access to Anthropic and VirusTotal APIs. Air-gapped environments are not supported in v1"*), VirusTotal free-tier rate limits (4 req/min, 500 req/day), a sample JSON output block, and the CI status badge.

**Given** a new user follows only the README setup section,
**When** they run `sentinel "test alert"` with valid API keys,
**Then** they receive a verdict within 5 minutes of cloning — no undocumented steps required.

**Given** `CONTRIBUTING.md` is complete,
**When** a contributor wants to add Shodan as a new source,
**Then** the document explains exactly: add one entry to `SOURCE_CATEGORIES` in `source_registry.py`, implement a class satisfying `SentinelAgent` Protocol, add a test file following the existing pattern, open a PR — no other files need modification to register the new source.

**Given** `.env.example` is present,
**When** a user copies it to `.env` and fills in their keys,
**Then** all three required variables are listed (`ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) plus `SENTINEL_TIMEOUT` as a commented optional with its default value.

---

### Story 4.4: End-to-End Integration Test

As a developer,
I want a full pipeline integration test that exercises every module together with mocked external APIs,
So that I can verify the complete analysis flow — from raw input to final JSON — and catch any wiring errors that unit tests miss.

**Acceptance Criteria:**

**Given** mocked Watchman (successful) and mocked Cipher (successful),
**When** `main()` is called with a sample alert as a positional argument,
**Then** stdout is valid JSON with all 8 `VerdictSchema` fields, `confidence_tier` is 2 (Probable), `source_independence_confirmed` is `True`, and exit code is 0.

**Given** mocked Watchman times out and mocked Cipher succeeds,
**When** `main()` is called,
**Then** stdout JSON has `confidence_tier` of 1 (Investigating), `blind_spots` contains one entry for Watchman, and exit code is 0.

**Given** both agents are mocked to fail,
**When** `main()` is called,
**Then** stdout JSON has `confidence_tier` of 1 (Investigating), `blind_spots` contains entries for both agents, and exit code is 0.

**Given** no input is provided,
**When** `main()` is called,
**Then** nothing is written to stdout, a usage message is written to stderr, and exit code is 2.

**Given** `ANTHROPIC_API_KEY` is not set,
**When** `main()` is called,
**Then** nothing is written to stdout, an error naming the missing variable is written to stderr, and exit code is 2.

**Given** the full pipeline runs with mocked agents,
**When** `execution_time_seconds` is read from the JSON output,
**Then** it is a positive float — timing is always measured and always present.

**And** stdout and stderr are captured separately in all test cases — stdout purity (clean JSON only) is verified explicitly in every integration test.
