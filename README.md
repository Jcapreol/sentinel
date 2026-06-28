# SENTINEL

[![CI](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml)

## Quick Start

```bash
git clone https://github.com/Jcapreol/sentinel.git
cd sentinel
pip install -e .
cp .env.example .env   # then fill in your four API keys
sentinel "Unusual outbound traffic to 185.220.101.45 on port 443 from prod-db-01"
```

API keys required: Anthropic (pay-per-use, fractions of a cent per run), VirusTotal (free tier), AbuseIPDB (free tier), URLhaus (free tier — get one at auth.abuse.ch).

---

SENTINEL is an open-source, MIT-licensed multi-agent AI SOC analyst for the terminal that accepts a raw security alert, log line, or IOC and produces a corroborated, structured verdict in under 30 seconds.
It runs two independent analysis agents — Watchman (Claude behavioral analysis) and Cipher (VirusTotal + AbuseIPDB + URLhaus threat intelligence) — and weighs their combined evidence into a human-readable verdict (Benign / Investigating / Probable / Confirmed). A clean reputation lookup pulls a verdict toward benign; concrete malicious reputation pushes it toward confirmed; behavioral suspicion alone is reported but not treated as proof.
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

Two independent agents analyzed the alert. Watchman flagged the behavioral TTPs (lsass access + unsigned binary from a world-writable directory). Cipher found no external IOC to corroborate against threat intelligence — so the verdict rests on a single source (Watchman) and lands at Probable rather than Confirmed. Cipher reports the gap explicitly so you know exactly what to add to the alert to raise confidence, rather than silently dropping it.

## Install

```bash
git clone https://github.com/Jcapreol/sentinel.git
cd sentinel
pip install -e .
```

> **Windows:** use `py -m pip install -e .` if `pip` is not on your PATH.

Set your API keys. SENTINEL reads them from a `.env` file in the project root (copy `.env.example` to `.env` and fill in your keys), or from environment variables:

**.env file:**
```
ANTHROPIC_API_KEY=your_anthropic_key
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
URLHAUS_API_KEY=your_urlhaus_key
```

**Or export directly (macOS / Linux):**
```bash
export ANTHROPIC_API_KEY=your_anthropic_key
export VIRUSTOTAL_API_KEY=your_virustotal_key
export ABUSEIPDB_API_KEY=your_abuseipdb_key
export URLHAUS_API_KEY=your_urlhaus_key
```

**Or export directly (Windows PowerShell):**
```powershell
$env:ANTHROPIC_API_KEY="your_anthropic_key"
$env:VIRUSTOTAL_API_KEY="your_virustotal_key"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_key"
$env:URLHAUS_API_KEY="your_urlhaus_key"
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

SENTINEL writes structured JSON to stdout on every run. All fields are always present regardless of confidence tier or agent error state.

```json
{
  "verdict": "Confirmed",
  "confidence_tier": 3,
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

## How Verdicts Work

SENTINEL does not treat behavioral suspicion as proof, and it does not treat a quiet alert as safe. The verdict is a function of two independent signals: what Cipher's threat intelligence says about the indicator, and how confident Watchman's behavioral analysis is. Crucially, a *clean* reputation lookup ("checked, 0 engines flagged it") is treated differently from *no* lookup ("nothing to check") — only the former is exonerating evidence.

| Cipher (threat intel) | Watchman (behavioral) | Verdict |
|----------------------|------------------------|---------|
| Malicious | High / Medium | **Confirmed** |
| Malicious | Low / No data | **Probable** |
| Clean | High | **Investigating** (suspicious behavior, but indicator cleared) |
| Clean | Low / No data | **Benign** |
| No data | High | **Probable** (single-source) |
| No data | Medium / Low | **Investigating** |

| Tier | Label | Meaning |
|------|-------|---------|
| 0 | Benign | Indicator cleared by threat intel; no corroborating threat behavior |
| 1 | Investigating | Mixed or single weak signal; needs analyst follow-up |
| 2 | Probable | Strong signal from one source, or malicious intel without behavioral corroboration |
| 3 | Confirmed | Malicious reputation corroborated by independent behavioral analysis |

A named blind spot is always surfaced when a source can't contribute — so you know the confidence ceiling and what to check to raise it.

## Threat Intelligence Coverage

Cipher extracts indicators from the alert text and queries three independent sources:

- **IP addresses** — VirusTotal reputation + AbuseIPDB abuse reports + URLhaus malware-host lookup
- **Domains** — VirusTotal domain reputation + URLhaus malware-host lookup (AbuseIPDB is IP-only and is reported as a blind spot for domains)
- **URLs** — the host/IP is extracted and looked up across all three sources

Each source covers different threat infrastructure. VirusTotal aggregates antivirus engine verdicts; AbuseIPDB tracks community-reported abuse; URLhaus specifically indexes active malware distribution hosts, catching freshly weaponized IOCs that other feeds haven't yet flagged. A miss on any single source is treated as no-data, not as exoneration — only a confirmed clean result counts as evidence of safety.

Private/internal IP ranges are filtered out automatically so only externally routable indicators are queried.

## Evaluation

SENTINEL ships with a small evaluation harness (`eval/run_eval.py`) that runs a labeled set of indicators through the full pipeline and scores the verdicts against known ground truth. The labeled set (`eval/labeled_set.json`) contains known-benign infrastructure (Cloudflare/Google DNS, major domains) and live malicious samples pulled from URLhaus.

The harness has been used to validate two successive improvements to the pipeline. The original implementation derived the verdict purely from the count of agents that returned findings, which meant a clean indicator and a malicious one received the same verdict. The changes below were made iteratively, each measured against the same labeled set:

| Metric | Baseline (source-count verdict) | After evidence-weighting | After URLhaus added |
|--------|--------------------------------|--------------------------|---------------------|
| Precision | 50.0% | 100.0% | **100.0%** |
| Recall | 100.0% | 80.0% | **100.0%** |
| F1 | 66.7% | 88.9% | **100.0%** |

Confusion matrix (positive class = malicious), current:

```
                 predicted MAL   predicted BEN
actual MAL          TP = 5          FN = 0
actual BEN          FP = 0          TN = 5
```

The recall improvement from 80% to 100% came from adding URLhaus as a third intel source. The single false negative in the evidence-weighting run was a URLhaus-listed malicious IP that VirusTotal had not yet flagged — a real-world illustration of threat-intel source latency. URLhaus indexes active malware distribution hosts and caught that indicator when VirusTotal lagged, closing the gap.

Reproduce it yourself:

```bash
py eval/run_eval.py
```

### Known limitation

Because Cipher depends on live threat-intelligence feeds, eval scores vary between runs as those feeds update. The numbers above reflect the current state of the labeled set against live feeds. Treat them as representative figures rather than fixed benchmarks — a freshly weaponized indicator may still lag on some feeds even with three sources, which is exactly why SENTINEL keeps Watchman's behavioral analysis as an independent signal rather than relying on reputation alone.

## Data Handling

SENTINEL does not store or transmit your incident data beyond the analysis APIs.

No alert content, IOCs, or log lines are written to disk at any point. The only external transmissions are to the Anthropic API (Watchman behavioral analysis) and the VirusTotal, AbuseIPDB, and URLhaus APIs (Cipher threat intelligence) as required to produce a verdict.

## Connectivity Requirements

SENTINEL requires internet access to the Anthropic, VirusTotal, AbuseIPDB, and URLhaus APIs. Air-gapped environments are not supported in v1.

## Rate Limits

**VirusTotal free tier:** 4 requests/minute, 500 requests/day.

If SENTINEL hits the VirusTotal rate limit, Cipher returns a named blind spot (`"VirusTotal rate limit reached - reputation data unavailable"`) and analysis continues with Watchman results only. Upgrade to VirusTotal Premium to remove this ceiling.

## License

MIT — see [LICENSE](LICENSE).
