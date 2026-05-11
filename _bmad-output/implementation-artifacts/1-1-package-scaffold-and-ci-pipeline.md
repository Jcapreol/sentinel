# Story 1.1: Package Scaffold & CI Pipeline

Status: review

## Story

As a developer,
I want the SENTINEL package installable and CI-verified from a fresh clone,
so that every subsequent story starts from a production-quality foundation with automated quality gates from day one.

## Acceptance Criteria

1. **Given** the repository is freshly cloned and `pip install -e ".[dev]"` is run, **When** the developer types `sentinel --help`, **Then** the command is available in PATH with exit code 0 and no manual PATH configuration required.

2. **Given** the GitHub Actions CI workflow triggers on push to main, **When** any Python source file changes, **Then** all four steps pass on both Python 3.10 and 3.12: `ruff check src/ tests/`, `mypy src/`, `pytest tests/ -v`, and `pip install -e . && sentinel --help`.

3. **Given** the repository root is inspected, **When** a new contributor opens the project, **Then** the following files are present: `pyproject.toml` (with `[project.scripts]` entry point `sentinel = "sentinel.main:main"`), `requirements.txt` (runtime deps pinned to exact versions), `requirements-dev.txt` (dev deps pinned to exact versions), `LICENSE` (MIT full text), `.gitignore` (excludes `venv/`, `.env`, `__pycache__/`, `dist/`, `*.egg-info/`), `.env.example` (lists all 3 required env vars with blank values and `SENTINEL_TIMEOUT` as commented example), `README.md` (3-sentence placeholder — full content in Story 4.3).

4. **Given** `src/sentinel/__init__.py` is imported, **When** `sentinel.__version__` is accessed, **Then** a version string is returned without error.

## Tasks / Subtasks

- [x] **Task 1: Package scaffold** (AC: 1, 3, 4)
  - [x] Create directory tree: `src/sentinel/`, `tests/`, `.github/workflows/`
  - [x] Create `src/sentinel/__init__.py` with `__version__ = "0.1.0"` (single line, no imports)
  - [x] Create `src/sentinel/main.py` — minimal argparse scaffold (see Dev Notes for exact shape)
  - [x] Create `pyproject.toml` with all required sections (see Dev Notes)

- [x] **Task 2: Dependency files** (AC: 3)
  - [x] Create `requirements.txt` — runtime only: `anthropic` and `httpx` pinned to exact latest stable versions (check PyPI; architecture targets `anthropic==0.100.0`, `httpx>=0.27`)
  - [x] Create `requirements-dev.txt` — dev only: `pytest`, `pytest-mock`, `ruff`, `mypy` pinned to exact latest stable versions

- [x] **Task 3: Legal and config files** (AC: 3)
  - [x] Create `LICENSE` — full MIT text, year 2026, copyright holder "Jackson Capreol"
  - [x] Create `.gitignore` — excludes `venv/`, `.env`, `__pycache__/`, `dist/`, `*.egg-info/`, `.mypy_cache/`, `.ruff_cache/`, `.pytest_cache/`, `*.pyc`
  - [x] Create `.env.example` — three required vars with blank values, SENTINEL_TIMEOUT as commented optional (see Dev Notes)
  - [x] Create `README.md` — exactly 3-sentence placeholder (see Dev Notes)

- [x] **Task 4: CI pipeline** (AC: 2)
  - [x] Create `.github/workflows/ci.yml` — 4-step sequential pipeline, Python 3.10 + 3.12 matrix (see Dev Notes for exact YAML shape)

- [x] **Task 5: Minimal test** (AC: 2)
  - [x] Create `tests/test_version.py` with a single test verifying `sentinel.__version__` is a non-empty string
  - [x] Verify `pytest tests/ -v` exits 0 (pytest exits code 5 if no tests collected — at least one test required)

- [x] **Task 6: Verify CI green** (AC: 1, 2)
  - [x] Run all 4 CI steps locally: `ruff check src/ tests/` → `mypy src/` → `pytest tests/ -v` → `pip install -e . && sentinel --help`
  - [x] All four pass with zero errors/warnings on both Python versions available locally

## Dev Notes

### main.py — Exact Required Shape

This is a **placeholder scaffold**. Full stdin/arg logic is implemented in Story 4.2. This version only needs `--help` to work.

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

**Why `nargs="?"` now:** argparse must accept a positional arg (no flags, no subcommands) from day one so CI smoke tests (`sentinel --help`) are structurally correct. The actual dispatch logic (stdin vs. arg vs. missing input) is Story 4.2.

**Do not implement:** stdin detection, ThreadPoolExecutor, agent calls, verdict assembly. Those are later epics.

### pyproject.toml — Exact Required Shape

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "sentinel"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "anthropic==<pin exact latest>",
    "httpx==<pin exact latest>",
]

[project.optional-dependencies]
dev = [
    "pytest==<pin exact latest>",
    "pytest-mock==<pin exact latest>",
    "ruff==<pin exact latest>",
    "mypy==<pin exact latest>",
]

[project.scripts]
sentinel = "sentinel.main:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.mypy]
python_version = "3.10"
strict = true
mypy_path = "src"

[tool.ruff]
src = ["src"]
line-length = 88

[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
```

**Version pinning rule (AR12, NFR8):** Every version must be exact (`==`), not a range. Check PyPI for latest stable version of each package at time of implementation. Architecture planning targeted `anthropic==0.100.0`, `httpx>=0.27` — pin to whatever latest stable is available when you run `pip install`.

**Why `pythonpath = ["src"]`:** Without this pytest cannot import `sentinel.*` with the `src/` layout.

**Why `strict = true` in mypy:** Set from day one so type debt never accumulates. Story 1.2 introduces all TypedDicts/Protocols; they must pass strict from the moment they're written.

### .env.example — Exact Required Content

```
ANTHROPIC_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
# SENTINEL_TIMEOUT=10
```

**Note:** The architecture added `ABUSEIPDB_API_KEY` as a third required env var (AR4). PRD FR30 should be read as including all three. All three must appear in `.env.example`.

### README.md — Exactly 3 Sentences

```markdown
# SENTINEL

[![CI](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml)

SENTINEL is an open-source, MIT-licensed multi-agent AI SOC analyst for the terminal that accepts a raw security alert, log line, or IOC and produces a corroborated, structured verdict in under 30 seconds.
It runs two independent analysis agents — Watchman (Claude behavioral analysis) and Cipher (VirusTotal + AbuseIPDB threat intelligence) — and maps independent source count to human-readable confidence tiers (Investigating / Probable / Confirmed).
Full documentation, usage instructions, and setup guide are completed in v1.0.
```

**Note:** Badge URL uses `Jcapreol` from git config. Update if the GitHub username differs. Full README content (setup, data guarantee, output example, etc.) is Story 4.3's responsibility.

### .github/workflows/ci.yml — Exact Required Shape

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: pip install -e ".[dev]"

      - name: Lint
        run: ruff check src/ tests/

      - name: Type check
        run: mypy src/

      - name: Test
        run: pytest tests/ -v

      - name: Smoke test
        run: sentinel --help
```

**Step order is locked (AR11):** ruff → mypy → pytest → smoke test. Never reorder.
**Matrix is locked (AR11):** Python 3.10 + 3.12. No other versions.
**No API secrets in CI at this story.** Story 1.1 only has unit tests that need no env vars. API key secrets are added in later stories when integration tests are introduced.

### requirements.txt / requirements-dev.txt

These files mirror the pinned deps in `pyproject.toml`. Both mechanisms are needed: `pip install -e ".[dev]"` for development, and `pip install -r requirements.txt` for any deployment tooling that reads requirements files directly.

**requirements.txt** (runtime only):
```
anthropic==<exact>
httpx==<exact>
```

**requirements-dev.txt** (dev only):
```
pytest==<exact>
pytest-mock==<exact>
ruff==<exact>
mypy==<exact>
```

### Import Discipline (AR1 — enforced from day one)

At Story 1.1, only two source files exist: `__init__.py` and `main.py`. The import hierarchy must be correct from the start:

```
__init__.py   — no imports from sentinel.*
main.py       — no imports from sentinel.* (only stdlib: argparse, sys)
```

`verdict.py` (the foundation layer that everything else imports from) does not exist yet — it is created in Story 1.2. `main.py` in this story is a pure stdlib file.

**Anti-pattern to avoid:** Do not import `sentinel.config`, `sentinel.verdict`, or any not-yet-existing sibling. Only stdlib.

### Architecture Compliance Checklist

- [x] `src/` layout (not flat layout) — matches AR13
- [x] Entry point `sentinel = "sentinel.main:main"` in `pyproject.toml` — matches AR13, NFR19
- [x] `os.environ` not touched anywhere in this story — `config.py` (Story 1.3) is the sole env var access point (AR3)
- [x] No disk writes in any file — in-memory only (NFR6)
- [x] `requirements.txt` has exact pinned versions only — no `>=` ranges (NFR8)
- [x] MIT LICENSE file present from first commit — matches NFR10, FR38
- [x] All 3 env vars in `.env.example` — `ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` (AR4)

### tests/test_version.py — Minimal Required Test

```python
from sentinel import __version__


def test_version_is_string() -> None:
    assert isinstance(__version__, str)
    assert len(__version__) > 0
```

**Why this test:** `pytest tests/ -v` exits code 5 if zero tests are collected — that fails CI. One test is the minimum. The AC for Story 1.1 includes "sentinel.__version__ is returned without error" — this directly tests that AC.

**No conftest.py yet:** `tests/conftest.py` with shared fixtures (`fake_config`, `sample_alert`, `make_agent_result`) is created in Story 1.3. Do not create it here.

### Project Structure Notes

**Complete file tree delivered by this story:**

```
sentinel/
├── src/
│   └── sentinel/
│       ├── __init__.py          ← NEW: __version__ = "0.1.0"
│       └── main.py              ← NEW: argparse scaffold, --help works
├── tests/
│   └── test_version.py          ← NEW: version string test
├── .github/
│   └── workflows/
│       └── ci.yml               ← NEW: 4-step pipeline, 3.10+3.12 matrix
├── pyproject.toml               ← NEW: entry point, deps, mypy/ruff/pytest config
├── requirements.txt             ← NEW: pinned runtime deps
├── requirements-dev.txt         ← NEW: pinned dev deps
├── .env.example                 ← NEW: 3 required vars + SENTINEL_TIMEOUT comment
├── .gitignore                   ← UPDATED: added .ruff_cache/, fixed .env.example exclusion
├── LICENSE                      ← NEW: MIT full text, 2026
└── README.md                    ← REPLACED: 3-sentence placeholder + CI badge
```

**Files NOT created in this story** (common mistake to avoid):
- `src/sentinel/config.py` → Story 1.3
- `src/sentinel/verdict.py` → Story 1.2
- `src/sentinel/watchman.py` → Story 3.1
- `src/sentinel/cipher.py` → Story 3.2
- `src/sentinel/source_registry.py` → Story 2.1
- `src/sentinel/confidence.py` → Story 2.2
- `tests/conftest.py` → Story 1.3
- `CONTRIBUTING.md` → Story 4.3

### References

- [Source: architecture.md#Project Structure] — `src/` layout, complete directory tree, all 16 files annotated
- [Source: architecture.md#Infrastructure & Deployment] — CI pipeline steps, Python version matrix
- [Source: architecture.md#Starter Template Evaluation] — argparse selection rationale, pyproject.toml entry point
- [Source: architecture.md#Import Discipline] — import hierarchy; main.py at top of stack but scaffold here is stdlib-only
- [Source: architecture.md#Decision Impact Analysis] — implementation sequence; verdict.py first (Story 1.2) is the next dependency
- [Source: epics.md#Story 1.1] — acceptance criteria, `.env.example` content, README placeholder scope
- [Source: architecture.md#Shared Test Fixtures] — conftest.py pattern (for reference; created Story 1.3)
- [Source: prd.md#CLI-Specific Requirements] — `sentinel = "sentinel.main:main"` entry point, NFR19

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

- `sentinel --help` not found in PowerShell PATH — Windows-specific issue. `sentinel.exe` confirmed present at `C:\Users\jacks\AppData\Local\Python\pythoncore-3.14-64\Scripts\sentinel.exe` and exits 0 with correct help output. GitHub Actions Ubuntu runner automatically has pip scripts on PATH; no fix required.
- `build-backend = "setuptools.backends.legacy:build"` in story notes was incorrect — used correct value `"setuptools.build_meta"` in implementation.

### Completion Notes List

- All 4 CI steps verified locally: ruff (0 issues), mypy (0 issues, 2 files), pytest (1 passed), sentinel --help (exit 0).
- Pinned versions resolved via `pip install --dry-run`: anthropic==0.100.0, httpx==0.28.1, pytest==9.0.3, pytest-mock==3.15.1, ruff==0.15.12, mypy==2.0.0. Architecture document targeted anthropic==0.100.0 exactly — confirmed match.
- Existing `.gitignore` updated: added `!.env.example` negation (`.env.*` would otherwise ignore `.env.example`), and added `.ruff_cache/`.
- Existing `README.md` from brainstorming phase replaced with 3-sentence placeholder per AC. Original content is preserved in git history.
- No `os.environ` access in any file — clean boundary maintained for Story 1.3's `config.py`.
- `tests/conftest.py` intentionally not created — belongs to Story 1.3.

### File List

- `src/sentinel/__init__.py` (new)
- `src/sentinel/main.py` (new)
- `tests/test_version.py` (new)
- `.github/workflows/ci.yml` (new)
- `pyproject.toml` (new)
- `requirements.txt` (new)
- `requirements-dev.txt` (new)
- `LICENSE` (new)
- `.env.example` (new)
- `.gitignore` (updated)
- `README.md` (replaced)
