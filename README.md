# SENTINEL

[![CI](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml)

SENTINEL is an open-source, MIT-licensed multi-agent AI SOC analyst for the terminal that accepts a raw security alert, log line, or IOC and produces a corroborated, structured verdict in under 30 seconds.
It runs two independent analysis agents — Watchman (Claude behavioral analysis) and Cipher (VirusTotal + AbuseIPDB threat intelligence) — and maps independent source count to human-readable confidence tiers (Investigating / Probable / Confirmed).
JSON output is stable across all v1.x releases and parseable by standard tools like `jq` without SENTINEL-specific libraries.

## Demo

Real run against a credential dumping alert:

```
$ sentinel "Sysmon Event ID 10: C:\Users\Public\update.exe (unsigned) accessed lsass.exe with GrantedAccess 0x1410 on WORKSTATION-42"
[sentinel] Analyzing alert...

Verdict:          Probable
Confidence tier:  2

Watchman findings:
  - Unsigned/unknown binary executing from Public user directory attempting privileged access
  - Direct access to lsass.exe process indicates potential credential dumping
  - GrantedAccess value 0x1410 includes PROCESS_QUERY_INFORMATION and PROCESS_VM_READ
    permissions commonly used in credential theft
  - Execution from C:\Users\Public\ directory suggests persistence mechanism or staging location
  - lsass.exe targeting is characteristic of lateral movement and privilege escalation attacks

Named blind spot:
  - No external IOCs found — verify alert contains an external IP address, domain, or file hash

Execution time: 2.57 seconds
```

Two independent agents analyzed the alert. Watchman flagged the behavioral TTPs (lsass access + unsigned binary from a world-writable directory). Cipher found no external IOCs to corroborate — which it tells you explicitly so you know exactly what to check next, rather than silently dropping the gap.

## Install

```bash
git clone https://github.com/Jcapreol/sentinel.git
cd sentinel
pip install -e .
```

> **Windows:** use `py -m pip install -e .` if `pip` is not on your PATH.

Set your API keys:

**macOS / Linux:**
```bash
export ANTHROPIC_API_KEY=your_anthropic_key
export VIRUSTOTAL_API_KEY=your_virustotal_key
export ABUSEIPDB_API_KEY=your_abuseipdb_key
```

**Windows (PowerShell):**
```powershell
$env:ANTHROPIC_API_KEY="your_anthropic_key"
$env:VIRUSTOTAL_API_KEY="your_virustotal_key"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_key"
```

Run:

```bash
sentinel "Unusual outbound traffic to 185.220.101.45 on port 443 from prod-db-01"
```

Or pipe via stdin:

```bash
echo "Brute force attempt from 185.220.101.45 on SSH" | sentinel
```

## Sample JSON Output

SENTINEL writes structured JSON to stdout on every run. All 8 fields are always present regardless of confidence tier or agent error state.

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

Pipe to `jq` to extract any field:

```bash
sentinel "alert text" | jq '.verdict'
sentinel "alert text" | jq '.blind_spots[].reason'
```

## How Confidence Tiers Work

SENTINEL counts structurally independent corroborating sources — not raw data points. Watchman (LLM behavioral analysis) and Cipher (community threat reputation) are in separate independence groups, so both succeeding yields tier 2 regardless of how many individual findings each returns.

| Tier | Label | Sources |
|------|-------|---------|
| 1 | Investigating | 0–1 independent sources returned data |
| 2 | Probable | 2 independent sources corroborate |
| 3 | Confirmed | 3+ independent sources corroborate |

A named blind spot is always surfaced when a source can't contribute — so you know the confidence ceiling and what to check to raise it.

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
