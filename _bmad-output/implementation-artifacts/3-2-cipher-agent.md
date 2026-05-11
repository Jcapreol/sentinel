# Story 3.2: Cipher Agent

Status: review

## Story

As an analyst,
I want SENTINEL to look up my alert's IOCs against VirusTotal and AbuseIPDB,
So that I get independent threat intelligence on IPs — and a named blind spot if the lookup cannot complete or the input type is not applicable, rather than a crash.

## Acceptance Criteria

1. **Given** a valid `Config` and an alert containing a public IP address, **When** `CipherAgent(config).analyze(input_data)` is called with mocked httpx returning valid VirusTotal and AbuseIPDB responses, **Then** it returns an `AgentResult` with `source_name="cipher"`, non-empty `findings` citing both sources, `blind_spots=[]`, and `error=None`.

2. **Given** the alert input contains no extractable IOC (e.g., no external IP), **When** `analyze(input_data)` is called, **Then** it returns an `AgentResult` with `findings=[]`, `blind_spots` containing a `BlindSpot` with `reason` explaining why threat intel is not applicable, and `error=None` — a structured null result, not a failure (FR19).

3. **Given** VirusTotal returns HTTP 429 (rate limit), **When** `analyze(input_data)` is called, **Then** it returns an `AgentResult` with a `BlindSpot` naming VirusTotal as unavailable due to rate limiting and `error="rate_limited"` — no retry in v1; analysis continues with AbuseIPDB result if available.

4. **Given** `httpx.Client` raises a connection timeout, **When** `analyze(input_data)` is called, **Then** it returns an `AgentResult` with `error="timeout"` and a `BlindSpot` with a human-readable `reason` — no raw exception reaches the caller.

5. **Given** `CipherAgent` is inspected by mypy against `SentinelAgent` Protocol, **When** type checking runs, **Then** no type errors are reported.

6. **And** `CipherAgent.__init__` accepts only `config: Config` and instantiates `httpx.Client(timeout=config.timeout_seconds)`. `tests/test_cipher.py` uses `pytest-mock` to patch `httpx.Client` at the call boundary, covering: success (IP found), structured null (no IOC), rate limit → blind spot, timeout → blind spot, generic exception → blind spot.

## Tasks / Subtasks

- [x] **Task 1: Implement `cipher.py`** (AC: 1–5)
  - [x] Create `src/sentinel/cipher.py` importing `re`, `httpx`, `sentinel.config.Config`, `sentinel.verdict.AgentResult`, `sentinel.verdict.BlindSpot`
  - [x] Define module-level regex constants `_IP_PATTERN` and `_PRIVATE_IP`, and URL constants `_VT_URL` / `_ABUSEIPDB_URL`
  - [x] Implement module-level `_extract_public_ips(text: str) -> list[str]`
  - [x] Implement `CipherAgent.__init__(self, config: Config)` — stores config, instantiates `httpx.Client`
  - [x] Implement `analyze(self, input_data: str) -> AgentResult` with no-IOC path, dual-API queries, and all exception branches (see Dev Notes)

- [x] **Task 2: Write `tests/test_cipher.py`** (AC: 6)
  - [x] Test: success path — mocked VT + AbuseIPDB → 2 findings, `error=None`
  - [x] Test: no extractable IOC → `error=None`, 1 blind spot with "not applicable" in reason
  - [x] Test: HTTP 429 → `error="rate_limited"`, blind spot naming rate limit
  - [x] Test: `httpx.ReadTimeout` → `error="timeout"`, 1 blind spot with source="cipher"
  - [x] Test: generic exception (`httpx.ConnectError`) → `error` set, blind spots present
  - [x] Test: Protocol compliance — `agent: SentinelAgent = CipherAgent(config=fake_config)` annotation

- [x] **Task 3: Verify CI green** (AC: all)
  - [x] `py -m ruff check src/ tests/` — 0 issues
  - [x] `py -m mypy src/` — 0 errors across all 8 source files
  - [x] `py -m pytest tests/ -v` — all 35 existing tests pass + new test_cipher.py tests

## Dev Notes

### cipher.py — Exact Implementation

```python
import re

import httpx

from sentinel.config import Config
from sentinel.verdict import AgentResult, BlindSpot

_VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PRIVATE_IP = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)


def _extract_public_ips(text: str) -> list[str]:
    return [ip for ip in _IP_PATTERN.findall(text) if not _PRIVATE_IP.match(ip)]


class CipherAgent:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._client = httpx.Client(timeout=config.timeout_seconds)

    def analyze(self, input_data: str) -> AgentResult:
        try:
            ips = _extract_public_ips(input_data)
            if not ips:
                return AgentResult(
                    source_name="cipher",
                    findings=[],
                    blind_spots=[
                        BlindSpot(
                            source="cipher",
                            reason="No external IOCs found in alert — threat intelligence lookup not applicable",
                            next_step="Verify alert contains an external IP address, domain, or file hash",
                        )
                    ],
                    raw_confidence=None,
                    error=None,
                )

            ip = ips[0]
            findings: list[str] = []
            blind_spots: list[BlindSpot] = []
            overall_error: str | None = None

            # VirusTotal lookup
            try:
                vt_resp = self._client.get(
                    _VT_URL.format(ip=ip),
                    headers={"x-apikey": self._config.virustotal_api_key},
                )
                if vt_resp.status_code == 429:
                    blind_spots.append(
                        BlindSpot(
                            source="virustotal",
                            reason="VirusTotal rate limit reached — reputation data unavailable",
                            next_step="Wait 60 seconds or upgrade to VirusTotal Premium",
                        )
                    )
                    overall_error = "rate_limited"
                else:
                    vt_data = vt_resp.json()
                    stats = (
                        vt_data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    findings.append(
                        f"VirusTotal: {ip} flagged by {malicious} engines as malicious, "
                        f"{suspicious} as suspicious"
                    )
            except httpx.TimeoutException:
                raise
            except Exception:
                blind_spots.append(
                    BlindSpot(
                        source="virustotal",
                        reason="VirusTotal lookup failed — reputation data unavailable",
                        next_step=None,
                    )
                )
                if overall_error is None:
                    overall_error = "analysis_failed"

            # AbuseIPDB lookup
            try:
                ab_resp = self._client.get(
                    _ABUSEIPDB_URL,
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": self._config.abuseipdb_api_key,
                        "Accept": "application/json",
                    },
                )
                if ab_resp.status_code == 429:
                    blind_spots.append(
                        BlindSpot(
                            source="abuseipdb",
                            reason="AbuseIPDB rate limit reached — abuse report data unavailable",
                            next_step="Wait before retrying or upgrade your AbuseIPDB plan",
                        )
                    )
                    if overall_error is None:
                        overall_error = "rate_limited"
                else:
                    ab_data = ab_resp.json()
                    score = ab_data.get("data", {}).get("abuseConfidenceScore", 0)
                    reports = ab_data.get("data", {}).get("totalReports", 0)
                    findings.append(
                        f"AbuseIPDB: {ip} abuse confidence {score}% from {reports} reports"
                    )
            except httpx.TimeoutException:
                raise
            except Exception:
                blind_spots.append(
                    BlindSpot(
                        source="abuseipdb",
                        reason="AbuseIPDB lookup failed — abuse report data unavailable",
                        next_step=None,
                    )
                )
                if overall_error is None:
                    overall_error = "analysis_failed"

            return AgentResult(
                source_name="cipher",
                findings=findings,
                blind_spots=blind_spots,
                raw_confidence=None,
                error=overall_error,
            )

        except httpx.TimeoutException:
            return AgentResult(
                source_name="cipher",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="cipher",
                        reason="Cipher timed out — threat intelligence lookup unavailable",
                        next_step="Retry when VirusTotal and AbuseIPDB APIs are reachable or increase SENTINEL_TIMEOUT",
                    )
                ],
                raw_confidence=None,
                error="timeout",
            )
        except Exception:
            return AgentResult(
                source_name="cipher",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="cipher",
                        reason="Cipher analysis failed — threat intelligence lookup unavailable",
                        next_step=None,
                    )
                ],
                raw_confidence=None,
                error="analysis_failed",
            )
```

### IOC Extraction Design

`_extract_public_ips` extracts IPv4 addresses from free-form text and filters out RFC 1918 private ranges and loopback:

```python
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PRIVATE_IP = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)
```

- `\b` word boundary prevents matching partial numbers like "1234.5.6.7"
- `_PRIVATE_IP` uses anchored `^` matching against the IP string directly
- Only the FIRST extracted public IP is queried in v1 (sufficient for alert-based use cases)
- Domains and file hashes are future work (FR17 scope note — v1 implements IP only)

**Private ranges filtered:**
| Range | Prefix matched |
|-------|---------------|
| 10.0.0.0/8 | `10.` |
| 172.16.0.0/12 | `172.16–31.` |
| 192.168.0.0/16 | `192.168.` |
| 127.0.0.0/8 | `127.` |
| 0.0.0.0/8 | `0.` |

**Structured null (AC 2, FR19):** When no public IP is found, return `error=None` (not a failure). This is a successful, definitive answer — "no applicable threat intel." The blind spot explains why, with a next step.

### Exception Handling Architecture

**Two-tier exception handling:** VT and AbuseIPDB each have their own inner try/except, allowing partial success (VT fails, AbuseIPDB succeeds). The outer try/except catches timeout for the entire analyze() call.

**Critical exception ordering in inner blocks:**
```python
try:
    ...  # API call
except httpx.TimeoutException:
    raise  # ← MUST be first; re-raises to outer handler
except Exception:
    ...  # per-API blind spot; does NOT propagate
```

`httpx.TimeoutException` is a subclass of `Exception`. Without the first `except httpx.TimeoutException: raise`, the `except Exception:` block would swallow timeouts and return `error="analysis_failed"` instead of `error="timeout"`. Exception order is critical.

**`httpx.TimeoutException` hierarchy (httpx==0.28.1):**
- `TimeoutException` → `TransportError` → `RequestError` → `HTTPError` → `Exception`
- Subclasses: `ConnectTimeout`, `ReadTimeout`, `WriteTimeout`, `PoolTimeout` (all match `except httpx.TimeoutException`)

**`httpx.ConnectError` is NOT a `TimeoutException`:**
- `ConnectError` → `NetworkError` → `TransportError` → ... → `Exception`
- Caught by `except Exception:` in inner blocks → produces per-API blind spot, NOT timeout

This distinction matters for the generic exception test: using `httpx.ConnectError` correctly exercises the non-timeout branch.

### httpx API Patterns

**Client construction (in `__init__`):**
```python
self._client = httpx.Client(timeout=config.timeout_seconds)
```
`timeout=config.timeout_seconds` (int) is accepted by httpx 0.28.1 and applies to all request phases.

**VirusTotal v3 IP lookup:**
```python
self._client.get(
    "https://www.virustotal.com/api/v3/ip_addresses/{ip}",
    headers={"x-apikey": self._config.virustotal_api_key},
)
```
Response JSON shape (success):
```json
{"data": {"attributes": {"last_analysis_stats": {"malicious": N, "suspicious": N, "harmless": N}}}}
```
- 429 → rate limited; no body parsing needed
- Other non-2xx → caught by `except Exception` in inner block

**AbuseIPDB v2 check:**
```python
self._client.get(
    "https://api.abuseipdb.com/api/v2/check",
    params={"ipAddress": ip, "maxAgeInDays": 90},
    headers={"Key": self._config.abuseipdb_api_key, "Accept": "application/json"},
)
```
Response JSON shape (success):
```json
{"data": {"abuseConfidenceScore": N, "totalReports": N, "countryCode": "US"}}
```
- 429 → rate limited; `overall_error` only set if not already set (VT 429 takes precedence)

### httpx Exception Constructors (httpx==0.28.1)

```python
# Both take: (message: str, *, request: Request | None = None)
httpx.ReadTimeout("timed out")        # timeout subclass — caught by outer handler
httpx.ConnectError("connection refused")  # NOT a timeout — caught by inner Exception
```

### Test Mocking Pattern for httpx

Mock `httpx.Client` at the import boundary in `cipher.py`:

```python
mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
mock_client = mock_httpx.return_value  # this is self._client in __init__
```

**Success test (two calls, different responses):**
```python
mock_client.get.side_effect = [vt_response, ab_response]
```
`side_effect` as a list returns items sequentially — first `get()` returns `vt_response`, second returns `ab_response`.

**Rate limit test (all calls return 429):**
```python
mock_429 = mocker.MagicMock()
mock_429.status_code = 429
mock_client.get.return_value = mock_429
```

**Timeout test (raises on get):**
```python
mock_client.get.side_effect = httpx.ReadTimeout("timed out")
```

**Generic exception test:**
```python
mock_client.get.side_effect = httpx.ConnectError("connection refused")
```

### test_cipher.py — Exact Implementation

```python
import httpx
import pytest

from sentinel.cipher import CipherAgent
from sentinel.config import Config
from sentinel.verdict import SentinelAgent


def test_cipher_success(
    mocker: pytest.MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    vt_response = mocker.MagicMock()
    vt_response.status_code = 200
    vt_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 2}
            }
        }
    }

    ab_response = mocker.MagicMock()
    ab_response.status_code = 200
    ab_response.json.return_value = {
        "data": {"abuseConfidenceScore": 87, "totalReports": 12}
    }

    mock_client.get.side_effect = [vt_response, ab_response]

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["source_name"] == "cipher"
    assert result["error"] is None
    assert result["blind_spots"] == []
    assert len(result["findings"]) == 2


def test_cipher_no_ioc_returns_structured_null(fake_config: Config) -> None:
    agent = CipherAgent(config=fake_config)
    result = agent.analyze("Authentication failure for admin from internal system")

    assert result["error"] is None
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert "not applicable" in result["blind_spots"][0]["reason"]


def test_cipher_rate_limit_returns_blind_spot(
    mocker: pytest.MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value

    mock_429 = mocker.MagicMock()
    mock_429.status_code = 429
    mock_client.get.return_value = mock_429

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "rate_limited"
    assert result["findings"] == []
    assert len(result["blind_spots"]) >= 1
    assert any("rate limit" in bs["reason"].lower() for bs in result["blind_spots"])


def test_cipher_timeout_returns_blind_spot(
    mocker: pytest.MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    mock_client.get.side_effect = httpx.ReadTimeout("timed out")

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] == "timeout"
    assert result["findings"] == []
    assert len(result["blind_spots"]) == 1
    assert result["blind_spots"][0]["source"] == "cipher"


def test_cipher_generic_exception_returns_blind_spot(
    mocker: pytest.MockerFixture, fake_config: Config, sample_alert: str
) -> None:
    mock_httpx = mocker.patch("sentinel.cipher.httpx.Client")
    mock_client = mock_httpx.return_value
    mock_client.get.side_effect = httpx.ConnectError("connection refused")

    agent = CipherAgent(config=fake_config)
    result = agent.analyze(sample_alert)

    assert result["error"] is not None
    assert result["findings"] == []
    assert len(result["blind_spots"]) >= 1


def test_cipher_satisfies_sentinel_agent_protocol(
    mocker: pytest.MockerFixture, fake_config: Config
) -> None:
    mocker.patch("sentinel.cipher.httpx.Client")
    agent: SentinelAgent = CipherAgent(config=fake_config)
    assert callable(getattr(agent, "analyze", None))
```

### Import Requirements

**cipher.py must import exactly:**
- `re` — stdlib, for `_IP_PATTERN` and `_PRIVATE_IP`
- `httpx` — runtime dep (already in requirements.txt), for `httpx.Client` and `httpx.TimeoutException`
- `sentinel.config.Config` — foundation layer
- `sentinel.verdict.AgentResult, BlindSpot` — foundation layer

**No other imports.** No `os`, no `json`, no `typing`.

**test_cipher.py must import exactly:**
- `httpx` — for `httpx.ReadTimeout`, `httpx.ConnectError` (exception types in tests)
- `pytest` — for `pytest.MockerFixture` annotation
- `sentinel.cipher.CipherAgent` — class under test
- `sentinel.config.Config` — fixture annotation
- `sentinel.verdict.SentinelAgent` — Protocol test annotation

All 5 must appear in test code or ruff F401 fires.

### mypy Annotations Required

**`_extract_public_ips`:** Return type `list[str]` + param `text: str` — explicit, required under `--disallow-untyped-defs`.

**Local variables in `analyze()`** — must be annotated:
```python
findings: list[str] = []
blind_spots: list[BlindSpot] = []
overall_error: str | None = None
```

**Response JSON:** `vt_resp.json()` → `Any`; chaining `.get()` on `Any` is fine. No annotation needed on `vt_data`/`ab_data`/`stats`/`score`/`reports`.

**`self._client`:** mypy infers `httpx.Client` from the assignment. No annotation needed.

**`self._config`:** mypy infers `Config`. No annotation needed.

### No Prompt Template Needed

Unlike Watchman, Cipher makes structured REST API calls — no LLM prompt, no double-brace escaping, no `json.loads` on LLM output. The response parsing uses `.json()` and `.get()` chains only.

### Exception Order — Both Inner and Outer Blocks

Inner block (per-API):
1. `except httpx.TimeoutException: raise` — MUST be first; re-raises to outer
2. `except Exception:` — per-API failure blind spot

Outer block:
1. `except httpx.TimeoutException:` — `error="timeout"`, 1 "Cipher timed out" blind spot
2. `except Exception:` — `error="analysis_failed"`, 1 "Cipher analysis failed" blind spot

### Import Discipline

```
verdict.py          ← foundation
config.py           ← foundation
source_registry.py  ← foundation
confidence.py       ← logic layer
watchman.py         ← logic layer: imports verdict + config
cipher.py           ← logic layer: imports verdict + config ONLY  ← THIS FILE
main.py             ← orchestration
```

`cipher.py` must NEVER import from `confidence.py`, `source_registry.py`, `watchman.py`, or `main.py`.

### Existing Files — Do NOT Modify

| File | Reason |
|------|--------|
| `src/sentinel/__init__.py` | Unchanged since 1.1 |
| `src/sentinel/main.py` | Unchanged until 4.2 |
| `src/sentinel/verdict.py` | Foundation, complete |
| `src/sentinel/config.py` | Foundation, complete |
| `src/sentinel/source_registry.py` | Complete as of 2.2 |
| `src/sentinel/confidence.py` | Complete as of 2.2 |
| `src/sentinel/watchman.py` | Complete as of 3.1 |
| `tests/conftest.py` | Complete — fixtures available |
| All prior test files | Must remain passing |

The `sample_alert` fixture (`"Unusual outbound traffic to 185.220.101.45 on port 443 from prod-db-01"`) contains `185.220.101.45` which IS a public IP. It will be extracted correctly by `_extract_public_ips`.

### Architecture Compliance Checklist

- [ ] `cipher.py` imports: `re` (stdlib), `httpx` (runtime dep), `sentinel.config`, `sentinel.verdict` only
- [ ] No `os.environ` anywhere in `cipher.py` — config is injected (AR3)
- [ ] `CipherAgent.__init__` signature: `(self, config: Config) -> None`
- [ ] `analyze` signature: `(self, input_data: str) -> AgentResult` — matches `SentinelAgent` Protocol
- [ ] `source_name="cipher"` in all returned `AgentResult` instances
- [ ] All `BlindSpot.reason` fields are human-readable strings — no exception class names
- [ ] `except httpx.TimeoutException: raise` is FIRST in each inner except block (before `except Exception`)
- [ ] `except httpx.TimeoutException:` in outer block catches and returns `error="timeout"`
- [ ] No-IOC path returns `error=None` (structured null, not failure)
- [ ] `httpx.Client(timeout=config.timeout_seconds)` — explicit timeout (AR5)
- [ ] `mypy src/` passes with 0 errors on all 8 source files

### Previous Story Learnings (from Stories 1.3–3.1)

- **`py -m` prefix** on Windows for all tooling: `py -m ruff`, `py -m mypy`, `py -m pytest`.
- **mypy strict parameter annotations:** ALL test function parameters must be typed. `mocker: pytest.MockerFixture`, `fake_config: Config`, `sample_alert: str`. Import `pytest` for `MockerFixture`.
- **ruff F401 trap:** every import must be used in test code. In `test_cipher.py`: `httpx` (for exception types), `pytest` (for `MockerFixture`), `CipherAgent` (obviously), `Config` (annotation), `SentinelAgent` (Protocol test). All 5 must appear.
- **`test_cipher_no_ioc_returns_structured_null` does NOT need `mocker`** — creating an `httpx.Client` instance in `__init__` makes no network calls; no patching required for that test.
- **`side_effect` as list** for sequential mock responses: `mock_client.get.side_effect = [vt_response, ab_response]` — first call returns `vt_response`, second returns `ab_response`.
- **35 tests currently passing** — must remain green after this story.

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
│       ├── watchman.py          ← unchanged
│       └── cipher.py            ← NEW: CipherAgent class
├── tests/
│   ├── conftest.py              ← unchanged
│   ├── test_version.py          ← unchanged
│   ├── test_verdict.py          ← unchanged
│   ├── test_config.py           ← unchanged
│   ├── test_source_registry.py  ← unchanged
│   ├── test_confidence.py       ← unchanged
│   ├── test_watchman.py         ← unchanged
│   └── test_cipher.py           ← NEW: 6 Cipher tests
```

### References

- [Source: epics.md#Story 3.2] — acceptance criteria, structured null, rate limit behavior
- [Source: architecture.md#Agent Class Pattern] — class shape, `__init__` signature
- [Source: architecture.md#Config Injection Pattern] — no os.environ in agents (AR3)
- [Source: architecture.md#Blind Spot Format Pattern] — human-readable reason, never exception names
- [Source: architecture.md#Test Mock Pattern] — `pytest-mock`, patch at SDK boundary
- [Source: architecture.md#Error → blind spot conversion] — agent boundary, main.py never sees exceptions
- [Source: architecture.md#API Patterns] — httpx.Client(timeout=config.timeout_seconds) (AR5)
- [Source: epics.md#FR19] — structured null for non-applicable inputs
- [Source: epics.md#NFR17] — 429 responses → named blind spots in v1

## Dev Agent Record

### Agent Model Used

claude-sonnet-4-6

### Debug Log References

### Completion Notes List

- Implemented `CipherAgent` with RFC 1918 IP filtering (`_PRIVATE_IP` regex), dual-API queries (VirusTotal v3 + AbuseIPDB v2)
- Two-tier exception handling: inner `except httpx.TimeoutException: raise` per-API, outer `except httpx.TimeoutException` catches re-raised timeouts
- No-IOC path returns `error=None` (structured null per FR19) — not a failure
- 429 handling produces `error="rate_limited"` blind spot per API; analysis continues to next API
- `httpx.ConnectError` (not a TimeoutException) correctly exercises the non-timeout branch → per-API blind spots
- 6 tests in `test_cipher.py`; `test_cipher_no_ioc_returns_structured_null` requires no mock (no network calls in that path)
- CI: ruff 0 issues, mypy 0 errors (8 source files), pytest 41/41 passed

### File List

- src/sentinel/cipher.py (NEW)
- tests/test_cipher.py (NEW)
