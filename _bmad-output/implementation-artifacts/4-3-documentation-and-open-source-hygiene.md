# Story 4.3: Documentation & Open-Source Hygiene

Status: ready-for-dev

## Story

As a new user or contributor,
I want complete, honest documentation from the first public commit,
So that I can reach a working verdict in under 5 minutes and understand exactly what SENTINEL can and cannot do before I trust it with a real incident.

## Acceptance Criteria

1. **Given** `README.md` is complete, **When** a new user reads it, **Then** it contains in order: a three-sentence product description, install instructions (`git clone` → `pip install -e .` → set env vars → `sentinel "test"`), the data handling guarantee verbatim ("SENTINEL does not store or transmit your incident data beyond the analysis APIs"), the connectivity limitation verbatim ("SENTINEL requires internet access to Anthropic and VirusTotal APIs. Air-gapped environments are not supported in v1"), VirusTotal free-tier rate limits (4 req/min, 500 req/day), a sample JSON output block, and the CI status badge.

2. **Given** a new user follows only the README setup section, **When** they run `sentinel "test alert"` with valid API keys, **Then** they receive a verdict within 5 minutes of cloning — no undocumented steps required.

3. **Given** `CONTRIBUTING.md` is complete, **When** a contributor wants to add Shodan as a new source, **Then** the document explains exactly: add one entry to `SOURCE_CATEGORIES` in `source_registry.py`, implement a class satisfying `SentinelAgent` Protocol, add a test file following the existing pattern, open a PR — no other files need modification to register the new source.

4. **Given** `.env.example` is present, **When** a user copies it to `.env` and fills in their keys, **Then** all three required variables are listed (`ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) plus `SENTINEL_TIMEOUT` as a commented optional with its default value.

## Tasks / Subtasks

- [ ] **Task 1: Rewrite `README.md`** (AC: 1, 2)
  - [ ] Keep existing CI badge at top (preserve exact URL: `https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml/badge.svg`)
  - [ ] Write three-sentence product description (first two sentences from current placeholder are correct — replace the third)
  - [ ] Add Install section: `git clone`, `pip install -e .`, env var export block, usage examples (positional + stdin)
  - [ ] Add Data Handling section with verbatim guarantee string
  - [ ] Add Connectivity Requirements section with verbatim limitation string
  - [ ] Add Rate Limits section: VirusTotal 4 req/min / 500 req/day with blind-spot behaviour note
  - [ ] Add Sample Output section with realistic JSON block (all 8 VerdictSchema fields)
  - [ ] Add License section linking to LICENSE file

- [ ] **Task 2: Create `CONTRIBUTING.md`** (AC: 3)
  - [ ] Explain how to add a new corroboration source (4-step process: SOURCE_CATEGORIES entry → SentinelAgent class → test file → PR)
  - [ ] Include the concrete Shodan example showing exactly what to add to `SOURCE_CATEGORIES`
  - [ ] Show the `SentinelAgent` Protocol signature the new class must satisfy
  - [ ] Reference the existing agent files (`watchman.py`, `cipher.py`) as patterns
  - [ ] Confirm no other files need modification beyond `source_registry.py` + new agent file + new test file

- [ ] **Task 3: Verify `.env.example`** (AC: 4)
  - [ ] Read existing `.env.example` — confirm all 3 required vars and commented `SENTINEL_TIMEOUT=10` are present
  - [ ] If correct, leave unchanged; if missing content, add it

- [ ] **Task 4: Verify CI green** (AC: all)
  - [ ] `py -m pytest tests/ -v` — all 48 existing tests pass (no new tests; no Python changes)
  - [ ] `pip install -e . && sentinel --help` — entry point smoke test

## Dev Notes

### Current State of Files

| File | Current State | Action |
|------|--------------|--------|
| `README.md` | 3-sentence placeholder + CI badge | REWRITE with full content |
| `CONTRIBUTING.md` | Does not exist | CREATE |
| `.env.example` | Already correct (all 3 vars + SENTINEL_TIMEOUT) | VERIFY only, do not overwrite |
| `LICENSE` | Already correct (MIT, Jackson Capreol, 2026) | Do not touch |

### README.md — Complete Content

The CI badge URL is already correct in the current README — keep it exactly as-is:
```
[![CI](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml)
```

**Complete README.md to write:**

```markdown
# SENTINEL

[![CI](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml)

SENTINEL is an open-source, MIT-licensed multi-agent AI SOC analyst for the terminal that accepts a raw security alert, log line, or IOC and produces a corroborated, structured verdict in under 30 seconds.
It runs two independent analysis agents — Watchman (Claude behavioral analysis) and Cipher (VirusTotal + AbuseIPDB threat intelligence) — and maps independent source count to human-readable confidence tiers (Investigating / Probable / Confirmed).
JSON output is stable across all v1.x releases and parseable by standard tools like `jq` without SENTINEL-specific libraries.

## Install

```bash
git clone https://github.com/Jcapreol/sentinel.git
cd sentinel
pip install -e .
```

Set your API keys:

```bash
export ANTHROPIC_API_KEY=your_anthropic_key
export VIRUSTOTAL_API_KEY=your_virustotal_key
export ABUSEIPDB_API_KEY=your_abuseipdb_key
```

Run:

```bash
sentinel "Unusual outbound traffic to 185.220.101.45 on port 443 from prod-db-01"
```

Or pipe via stdin:

```bash
echo "Brute force attempt from 185.220.101.45 on SSH" | sentinel
```

## Sample Output

```json
{
  "verdict": "Probable",
  "confidence_tier": 2,
  "methodology": [
    {"agent": "watchman", "status": "success", "error": null},
    {"agent": "cipher", "status": "success", "error": null}
  ],
  "citations": [
    {
      "source": "watchman",
      "finding": "Suspicious outbound connection to known Tor exit node on non-standard port"
    },
    {
      "source": "cipher",
      "finding": "VirusTotal: 185.220.101.45 flagged by 12 engines as malicious, 2 as suspicious"
    },
    {
      "source": "cipher",
      "finding": "AbuseIPDB: 185.220.101.45 abuse confidence 97% from 234 reports"
    }
  ],
  "blind_spots": [],
  "source_independence_confirmed": true,
  "execution_time_seconds": 4.231,
  "timestamp": "2026-05-11T18:42:03.456789+00:00"
}
```

## Data Handling

SENTINEL does not store or transmit your incident data beyond the analysis APIs.

No alert content, IOCs, or log lines are written to disk at any point. The only external transmissions are to the Anthropic API (Watchman behavioral analysis) and the VirusTotal/AbuseIPDB APIs (Cipher threat intelligence) as required to produce a verdict.

## Connectivity Requirements

SENTINEL requires internet access to Anthropic and VirusTotal APIs. Air-gapped environments are not supported in v1.

## Rate Limits

**VirusTotal free tier:** 4 requests/minute, 500 requests/day.

If SENTINEL hits the VirusTotal rate limit, Cipher returns a named blind spot (`"VirusTotal rate limit reached — reputation data unavailable"`) and analysis continues with Watchman results only. Upgrade to VirusTotal Premium to remove this ceiling.

## License

MIT — see [LICENSE](LICENSE).
```

### CONTRIBUTING.md — Complete Content

```markdown
# Contributing to SENTINEL

## Adding a New Corroboration Source

SENTINEL's source independence engine is designed to accept new sources with a single-file change. Adding Shodan, GreyNoise, or any other threat intelligence source requires exactly three files:

### Step 1: Register the source category

Add one entry to `SOURCE_CATEGORIES` in `src/sentinel/source_registry.py`:

```python
SOURCE_CATEGORIES: dict[str, str] = {
    "anthropic_claude": "llm_behavioral",
    "watchman": "llm_behavioral",
    "virustotal": "community_reputation",
    "abuseipdb": "community_reputation",
    "cipher": "community_reputation",
    "shodan": "network_scanning",     # ← add your source here
}
```

The category string determines independence grouping. Two sources in the same category count as one independent source, regardless of how many data points they return. Use an existing category if your source belongs to the same data pipeline, or a new string if it is structurally independent.

### Step 2: Implement the agent class

Create `src/sentinel/your_agent.py` as a class satisfying the `SentinelAgent` Protocol:

```python
from sentinel.config import Config
from sentinel.verdict import AgentResult, BlindSpot


class YourAgent:
    def __init__(self, config: Config) -> None:
        self._config = config

    def analyze(self, input_data: str) -> AgentResult:
        try:
            # ... your analysis logic ...
            return AgentResult(
                source_name="your_source",   # must match SOURCE_CATEGORIES key
                findings=[...],
                blind_spots=[],
                raw_confidence=None,
                error=None,
            )
        except Exception:
            return AgentResult(
                source_name="your_source",
                findings=[],
                blind_spots=[BlindSpot(
                    source="your_source",
                    reason="Human-readable description of what failed",
                    next_step="What the analyst should do to close this gap",
                )],
                raw_confidence=None,
                error="analysis_failed",
            )
```

**Rules:**
- The class must have `__init__(self, config: Config)` and `analyze(self, input_data: str) -> AgentResult`
- Never read `os.environ` directly — use `self._config` only
- All exceptions must be caught inside `analyze()` — no exception may leave the agent boundary
- `reason` in `BlindSpot` is always human-readable — never an exception class name
- See `src/sentinel/watchman.py` and `src/sentinel/cipher.py` for reference implementations

### Step 3: Add tests

Create `tests/test_your_agent.py` following the pattern in `tests/test_watchman.py` or `tests/test_cipher.py`. At minimum, cover:
- Success path (mocked API returning valid data)
- Timeout → blind spot
- Generic exception → blind spot
- Protocol conformance (`agent: SentinelAgent = YourAgent(config)`)

### Step 4: Open a PR

No other files need modification. The source registry, confidence engine, and verdict assembly all pick up the new source automatically once `SOURCE_CATEGORIES` has your entry.

## Development Setup

```bash
git clone https://github.com/Jcapreol/sentinel.git
cd sentinel
pip install -e ".[dev]"
```

## CI

All PRs must pass the full CI pipeline:

```bash
ruff check src/ tests/    # linting
mypy src/                 # type checking (strict mode)
pytest tests/ -v          # test suite
sentinel --help           # entry point smoke test
```

## Code Style

- Python 3.10+ syntax
- `mypy --strict` compliance required — all function parameters and return types annotated
- No `os.environ` outside `config.py`
- No `print()` without `file=sys.stderr` outside `verdict.py`
- BlindSpot reasons are always human-readable sentences, never exception names
```

### Verbatim Strings — Do NOT Paraphrase

The following strings must appear in README.md exactly as written (from FR35/FR36):

**Data handling guarantee:**
> SENTINEL does not store or transmit your incident data beyond the analysis APIs.

**Connectivity limitation:**
> SENTINEL requires internet access to Anthropic and VirusTotal APIs. Air-gapped environments are not supported in v1.

**Rate limits** (FR20):
> VirusTotal free tier: 4 requests/minute, 500 requests/day.

### Sample JSON — All 8 VerdictSchema Fields

The sample output block must show all 8 fields from `VerdictSchema` so users know the exact schema:

| Field | Type | Example |
|-------|------|---------|
| `verdict` | str | `"Probable"` |
| `confidence_tier` | int | `2` |
| `methodology` | list[dict] | one entry per agent, always 2 in v1 |
| `citations` | list[dict] | one entry per finding across all agents |
| `blind_spots` | list[BlindSpot] | `[]` when all sources returned data |
| `source_independence_confirmed` | bool | `true` when Watchman + Cipher both succeed |
| `execution_time_seconds` | float | positive float, measured end-to-end |
| `timestamp` | str | ISO 8601 UTC string |

### `.env.example` — Current Content (Do NOT Overwrite)

The file already contains the correct content. Read it first, verify, then leave it unchanged:

```
ANTHROPIC_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
# SENTINEL_TIMEOUT=10
```

If any of the 3 required vars or the commented `SENTINEL_TIMEOUT` line is missing, add it. Do not delete or reorder existing lines.

### No Python Changes

This story modifies zero Python files. Do not touch any `.py` file. CI passes because:
- ruff and mypy have nothing new to check
- pytest runs the existing 48 tests unchanged
- `sentinel --help` still works (argparse is already wired up)

### Project Structure After This Story

```
sentinel/
├── src/sentinel/            ← unchanged
├── tests/                   ← unchanged
├── README.md                ← REWRITTEN: full documentation
├── CONTRIBUTING.md          ← NEW: contributor guide
├── .env.example             ← unchanged (already correct)
├── LICENSE                  ← unchanged (MIT, correct)
├── pyproject.toml           ← unchanged
└── .github/workflows/ci.yml ← unchanged
```

### Previous Story Learnings

- **No Python changes in this story** — ruff/mypy don't apply to `.md` files
- **Preserve the CI badge URL exactly** — it's already correct in the current README
- **Do not overwrite `.env.example`** — it already has the right content
- **Do not touch `LICENSE`** — already correct with MIT text and correct copyright
- **48 tests currently passing** — must remain green; no new tests needed

### References

- [Source: epics.md#Story 4.3] — exact AC wording, verbatim strings, 5-minute setup goal
- [Source: epics.md#FR20] — VirusTotal rate limit documentation requirement
- [Source: epics.md#FR35] — data handling guarantee verbatim text
- [Source: epics.md#FR36] — connectivity limitation verbatim text
- [Source: architecture.md#AR14] — CONTRIBUTING.md must document SOURCE_CATEGORIES extension

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

### Completion Notes List

### File List
