---
stepsCompleted: ['step-01-init', 'step-02-discovery', 'step-02b-vision', 'step-02c-executive-summary', 'step-03-success', 'step-04-journeys', 'step-05-domain', 'step-06-innovation', 'step-07-project-type', 'step-08-scoping', 'step-09-functional', 'step-10-nonfunctional', 'step-11-polish', 'step-12-complete']
workflowStatus: complete
completedAt: '2026-05-10'
releaseMode: phased
inputDocuments:
  - '_bmad-output/brainstorming/brainstorming-session-2026-05-09-0000.md'
workflowType: 'prd'
briefCount: 0
researchCount: 0
brainstormingCount: 1
projectDocsCount: 0
classification:
  projectType: 'cli_tool'
  domain: 'cybersecurity'
  complexity: 'high'
  projectContext: 'greenfield'
  scope: 'v1 MVP — 30-day CLI corroboration engine'
  licenseModel: 'MIT open-source from day one'
  teamConstraint: 'solo developer — hard constraint for v1'
---

# Product Requirements Document - Sentinel

**Author:** Jackson
**Date:** 2026-05-10

## Executive Summary

SENTINEL is an open-source, MIT-licensed multi-agent AI SOC analyst for the terminal. It accepts a raw security alert, log line, or IOC and produces a corroborated, structured verdict in under 30 seconds — no dashboard, no SaaS account, no black-box confidence scores. The v1 30-day MVP targets the solo security engineer at a Series A startup who is paged at midnight with no team, no playbook, and no margin for error.

**Problem:** Every commercial SOC tool responds to analyst panic with more data. SENTINEL responds with a verdict: real or noise, confidence tier, methodology, evidence citations, and named blind spots. The analyst's cognitive load drops from "where do I start?" to "do I agree with this assessment?"

**Target user:** The solo security engineer at a 50–150 person company who is simultaneously the analyst, the CTO, and the compliance owner. They cannot send incident data to third-party SaaS. They need a defensible output they can show a board, an auditor, or a cyber insurer — generated in seconds, not hours.

**Why now:** Claude's API and VirusTotal/AbuseIPDB free tiers make this buildable by one developer in 30 days with ~300 lines of Python. That combination did not exist 18 months ago. No equivalent free or open-source tool exists.

### What Makes This Special

The corroboration engine requires independent confirmation from structurally unconnected sources before issuing any verdict. Two signals from the same log pipeline count as one source — not two. The confidence ladder maps to human-readable tiers (Investigating / Probable / Confirmed) that trigger distinct analyst behaviors, not ML percentages nobody trusts.

Every verdict ships with a mandatory three-part standard: methodology (agents run, order, logic), evidence citations (specific indicators, log sources, source count), and named blind spots (data sources unavailable and the exact gap they create). Named blind spots are not a failure mode — they tell the analyst exactly where to look next and give an auditor the system's honest limits.

SENTINEL's output format is a stable, pipeable CLI contract. Downstream tools can parse SENTINEL verdicts without breakage. The CLI interface (commands, flags, output schema) is a first-class v1 commitment. The entire codebase is MIT-licensed and auditable from the first commit.

## Project Classification

- **Project Type:** CLI tool (v1); web app (v2); hosted SaaS (v3)
- **Domain:** Cybersecurity — threat intelligence, incident triage, structured security analysis
- **Complexity:** High — multi-agent AI orchestration, threat intel API integration, stable public CLI contract, audit-grade output format
- **Project Context:** Greenfield
- **License:** MIT open-source from day one
- **v1 Scope:** 30-day CLI corroboration engine; solo developer hard constraint
- **API Stability Commitment:** Stable CLI interface (commands, flags, output schema); pipeable output format is a first-class v1 requirement; Python module API deferred to v2

## Success Criteria

### User Success

- A solo security engineer pastes or pipes a real security alert and receives a defensible three-part verdict in under 30 seconds
- The verdict output is sufficient to present to a board, auditor, or cyber insurer without additional documentation
- Zero learning curve beyond API key setup — an analyst unfamiliar with SENTINEL can run their first analysis without reading more than the README
- The analyst knows exactly what SENTINEL couldn't see: every output names data sources that were unavailable and the specific gap they create

### Business Success

- **North star metric:** First external contributor submits a PR — this signals the codebase is clean and documented enough that a stranger trusted it. Stars are vanity; a real contributor means the project is real.
- README data handling guarantee published from first commit: *"SENTINEL does not store or transmit your incident data beyond the analysis APIs."*
- MIT license on GitHub from day one; no release gates before public availability

### Technical Success

- Verdict produced end-to-end in ≤30 seconds (hard requirement — gates v1 ship)
- Source independence confirmed for every verdict: two signals from the same log pipeline count as one source, not two
- Confidence ladder tier present in every output: Investigating / Probable / Confirmed
- Three-part verdict standard complete in every output: methodology, evidence citations, named blind spots
- No data persistence: SENTINEL processes alerts in memory only — no files written, no database touched
- No data transmission beyond two API calls: Anthropic Claude (Watchman) and VirusTotal/AbuseIPDB (Cipher)
- Stable CLI contract maintained across all v1.x patch releases: commands, flags, and output schema do not break
- Pipeable output format: downstream tools can parse SENTINEL verdicts reliably

### Measurable Outcomes

| Outcome | Target | Type |
|---------|--------|------|
| Time to verdict | ≤30 seconds | Hard gate — blocks ship |
| First external contributor PR | 1 PR merged | North star adoption metric |
| Data persistence | Zero | Hard requirement |
| External data transmission | 2 API calls only (Anthropic, VirusTotal/AbuseIPDB) | Hard requirement |
| CLI schema stability | Zero breaking changes across v1.x | Hard requirement |
| Setup time | ≤5 minutes from clone to first verdict | Target |

## User Journeys

### Journey 1: The Midnight Analyst — Primary User, Success Path

**Persona:** Maya, sole security engineer at an 80-person SaaS company. She is the analyst, the CTO's escalation path, and the person who will talk to the cyber insurer if this goes badly. She has been burned before: three hours investigating a noisy GuardDuty alert that turned out to be a misconfigured Lambda. She cannot afford to repeat that.

**Opening scene:** 2:47 AM. GuardDuty fires. An IAM role assumption from an IP she doesn't recognize, followed by S3 API calls. Her stomach drops. She opens her terminal.

**Rising action:** She pipes the raw GuardDuty JSON into SENTINEL. Watchman runs behavioral analysis against Claude: the role assumption pattern — admin API calls followed by bucket enumeration within four minutes — matches known credential stuffing TTPs. Cipher runs independently: the source IP has 12 recent VirusTotal reports from unrelated security vendors and an AbuseIPDB confidence score of 90%. The source independence checker confirms: behavioral analysis (Claude) and IP reputation (VirusTotal/AbuseIPDB) are structurally unconnected pipelines. Two independent sources.

**Climax:** Twenty-three seconds after she ran the command, the verdict appears:

> **PROBABLE** — Two independent sources converge on malicious activity.
> Methodology: Watchman behavioral analysis → Cipher IP reputation → independence confirmed.
> Citations: IAM role assumption 02:47 UTC, source IP 198.51.100.42, 12 VirusTotal reports (independent vendors), AbuseIPDB score 90%.
> Blind spots: VPN logs unavailable — confidence ceiling 72%. CloudTrail for us-west-2 not checked.

**Resolution:** Maya doesn't start from zero. She starts from "do I agree with Probable?" She sees the blind spots, pulls CloudTrail for us-west-2, finds matching exfiltration attempt. Her assessment moves to Confirmed. She rotates the compromised credentials, locks down the role, and files the incident report using SENTINEL's three-part output as the evidence base — verbatim. The whole thing takes 18 minutes. Without SENTINEL it would have taken three hours and ended with a triage doc she couldn't defend.

*Capabilities revealed: paste/pipe input, Watchman agent, Cipher agent, source independence check, confidence ladder, three-part verdict formatter, named blind spots, sub-30-second execution.*

---

### Journey 2: The Uncertain Analyst — Primary User, Edge Case

**Persona:** Same Maya, different night. This time SENTINEL's job is to be honest about what it doesn't know.

**Opening scene:** A Lambda function triggered at 3:12 AM. Unusual, but this function does run occasionally for on-call jobs. No external IP involved — internal invocation only. Maya isn't sure if this is worth waking up for.

**Rising action:** She pipes the alert into SENTINEL. Watchman runs: the timing is unusual, but the function signature matches a known legitimate pattern. Ambiguous. Cipher runs: the invocation source is an internal AWS resource — no external IP, no applicable threat intelligence data. Cipher returns a structured null result with an explicit reason.

**Climax:** The verdict appears:

> **INVESTIGATING** — One independent source. Insufficient corroboration to confirm or dismiss.
> Methodology: Watchman behavioral analysis (ambiguous) → Cipher IP lookup (not applicable — internal source).
> Citations: Lambda function triggered 03:12 UTC, internal invocation by scheduled event.
> Blind spots: Lambda execution logs unavailable — cannot confirm function behavior. CloudWatch metrics not checked. No external threat intel applicable for internal invocation. Confidence ceiling: Investigating.

**Resolution:** Maya reads the verdict. She is not frustrated — she is oriented. SENTINEL did not guess. It told her exactly what it could and could not see. She checks the Lambda execution logs: a legitimate on-call database backup job. She marks it a false positive. The whole interaction took four minutes. SENTINEL's value here is not the verdict — it is the named blind spots that tell her exactly where to look to close the investigation herself.

*Capabilities revealed: Investigating confidence tier, structured null result from Cipher for non-applicable inputs, named blind spots as primary output when corroboration is insufficient, honest uncertainty communication.*

---

### Journey 3: The Contributor — Secondary User, First PR

**Persona:** Reza, security engineer at a 200-person company. He has used SENTINEL for two weeks and wants to add Shodan as a third corroboration source. He has never contributed to this project before. He is deciding whether the codebase is worth his time.

**Opening scene:** Reza clones the repository and opens the README. Three sentences describe what SENTINEL does. The setup section gets him to a working verdict in four minutes. He reads the Contributing section.

**Rising action:** He opens the source tree. The architecture is legible from file names alone: `watchman.py`, `cipher.py`, `source_independence.py`, `confidence_ladder.py`, `verdict_formatter.py`. Each agent file has the same interface: accepts a structured input dict, returns a structured result dict with a defined schema. The source independence checker maintains a registry of source identifiers. Reza understands the pattern from reading two files.

**Climax:** He writes `shodan.py` following the same interface. He adds a `SHODAN` entry to the source registry. He updates the confidence ladder to handle three-source verdicts. He runs the test suite. It passes. He opens a PR: *"Add Shodan integration as third corroboration source."* The PR description writes itself because the code tells the story. He does not need to ask how anything works.

**Resolution:** The PR is merged. This is the moment v1 success is real: a stranger read the code, understood the architecture, extended it correctly, and trusted it enough to submit. The stable agent interface made the contribution possible. The clean architecture made it obvious. This is what "MIT open-source from day one" actually means in practice.

*Capabilities revealed: consistent agent interface contract, documented source registry, clear module boundaries, contributing documentation, test suite, readable architecture.*

---

### Journey 4: The Pipeline Builder — Power User, Stable Output Contract

**Persona:** Diego, security operations at a 120-person fintech. He does not use SENTINEL interactively — he runs it as a step in his automated alert triage workflow.

**Opening scene:** Diego writes a Python script that ingests GuardDuty findings from an SNS topic, pipes each alert through SENTINEL, and routes the verdict to the right destination. He needs SENTINEL's output to be machine-readable and stable — his script cannot break every time SENTINEL releases a patch.

**Rising action:** SENTINEL outputs structured JSON to stdout on every run:

```json
{
  "verdict": "Probable",
  "confidence_tier": 2,
  "methodology": ["watchman_behavioral", "cipher_ip_reputation"],
  "citations": [{"source": "VirusTotal", "indicator": "198.51.100.42", "reports": 12}],
  "blind_spots": ["VPN logs unavailable — confidence ceiling 72%"],
  "timestamp": "2026-05-10T02:47:33Z"
}
```

Diego's script reads `confidence_tier`. If ≥ 2 (Probable or Confirmed), it creates a PagerDuty incident and pages the on-call engineer. If 1 (Investigating), it posts to a Slack channel for human review during business hours. If 0 (insufficient data), it logs and drops.

**Climax:** Two months later, Diego upgrades SENTINEL from v1.0 to v1.2. His script still works. The JSON schema did not change. No field was renamed, removed, or restructured. The `confidence_tier` integer contract held. He did not have to touch his downstream tooling.

**Resolution:** Diego's workflow handles 40–60 GuardDuty alerts per week. Approximately 15% reach Probable or Confirmed and page on-call. The rest are triaged asynchronously. His team's mean time to first response on high-confidence alerts drops from 23 minutes to 4 minutes. SENTINEL is not a tool anyone on his team opens — it is infrastructure they depend on. The stable output contract is what made that possible.

*Capabilities revealed: structured JSON output to stdout, stable schema across v1.x patch releases, confidence_tier as machine-readable integer, documented output schema, semantic versioning commitment for CLI contract.*

---

### Journey Requirements Summary

| Capability | Required By |
|-----------|-------------|
| Paste or pipe input (raw alert, log line, IOC) | Journeys 1, 2 |
| Watchman agent (Claude behavioral analysis) | Journeys 1, 2 |
| Cipher agent (VirusTotal/AbuseIPDB IOC lookup) | Journeys 1, 2 |
| Structured null/N/A result from Cipher for non-applicable inputs | Journey 2 |
| Source independence checker with source registry | Journeys 1, 2, 3 |
| Confidence ladder (Investigating / Probable / Confirmed) | Journeys 1, 2, 4 |
| `confidence_tier` as machine-readable integer in output | Journey 4 |
| Three-part verdict formatter (methodology, citations, blind spots) | Journeys 1, 2 |
| Named blind spots detector with gap implications | Journeys 1, 2 |
| Structured JSON output to stdout | Journeys 1, 4 |
| Stable JSON output schema across v1.x releases | Journey 4 |
| Documented output schema | Journeys 3, 4 |
| Consistent agent interface contract (input dict → result dict) | Journey 3 |
| Source registry (extensible by contributors) | Journey 3 |
| Test suite | Journey 3 |
| Contributing documentation | Journey 3 |
| Sub-30-second end-to-end execution | Journey 1 |

## Domain-Specific Requirements

### Credential & Secret Handling

- API keys sourced exclusively from environment variables: `ANTHROPIC_API_KEY` and `VIRUSTOTAL_API_KEY`
- No config files store credentials in v1 — no `.env` file parsing, no settings JSON with keys
- SENTINEL fails fast with a clear error if required environment variables are not set
- Rationale: environment variable–only credential handling is auditable, matches security engineer expectations, and eliminates credential-at-rest risk in the project directory

### Supply Chain Security

- All dependencies pinned to exact versions in `requirements.txt` from the first commit
- Dependency footprint kept minimal — every dependency is a deliberate decision, no transitive trees pulled in for convenience
- Dependencies reviewed for security history before inclusion
- Rationale: SENTINEL is a security tool and will be scrutinized by security engineers before deployment; a minimal, pinned dependency tree is itself a trust signal

### API Rate Limiting

- VirusTotal free-tier limits documented explicitly in README: 4 requests/minute, 500 requests/day
- In v1, if VirusTotal returns a 429 rate-limit response, Cipher surfaces it as a named blind spot and analysis continues — the analyst receives an Investigating verdict rather than a hard failure
- Exponential backoff with retry ships in v1.1; it is the one explicitly deferrable v1 item (see Project Scope)
- Rationale: pipeline use cases require graceful degradation; a named blind spot is more useful than a crash, and backoff complexity is deferred to keep v1 shippable in 30 days

### Connectivity Requirements & Limitations

- **v1 requirement:** SENTINEL requires active internet access to two external APIs — Anthropic Claude and VirusTotal/AbuseIPDB
- **Explicit documented limitation:** *"SENTINEL requires internet access to Anthropic and VirusTotal APIs. Air-gapped and offline environments are not supported in v1."*
- This limitation is stated prominently in the README, not buried in a footnote
- Local LLM support (Ollama or equivalent) is a v2 roadmap item — explicitly out of scope for v1

### Data Handling Guarantee

- SENTINEL processes all input in memory only — no alert data, IOCs, or log lines are written to disk
- The only external transmission of input data is to the two analysis APIs (Anthropic, VirusTotal/AbuseIPDB) as required for analysis
- No telemetry, no usage tracking, no logging of user inputs
- README states explicitly: *"SENTINEL does not store or transmit your incident data beyond the analysis APIs."*
- This guarantee is a v1 hard requirement, not a preference

## Innovation & Novel Patterns

### Detected Innovation Areas

**1. The Corroboration Engine — Journalism's Standard Applied to Security**

Every existing SIEM and threat detection platform correlates signals from the same data infrastructure and calls that corroboration. SENTINEL's corroboration engine enforces a harder standard borrowed from investigative journalism: independent confirmation requires structurally unconnected sources. Two signals from the same log pipeline count as one source, not two. This single distinction eliminates an entire class of false positives that plague correlation-based detection — confirmed signals that turn out to be the same artifact observed through two lenses.

No open-source security tool enforces source independence as a structural requirement. Commercial tools (Darktrace, Vectra, Chronicle) correlate within their own data pipelines by design. SENTINEL's independence check is architecturally incompatible with that model — and that incompatibility is the moat.

**2. Multi-Agent AI as Corroborating Peers, Not Copilots**

Existing AI security tools are copilots: they assist the analyst in querying data. SENTINEL's agents are peers: each agent is responsible for an independent data stream, and no verdict is issued until independent agents confirm from independent sources. Watchman (Claude behavioral analysis) and Cipher (VirusTotal/AbuseIPDB reputation) do not share data or reasoning — their independence is the mechanism, not a side effect.

This is the first open-source implementation of multi-agent AI used specifically to enforce epistemological independence in security analysis.

**3. Named Blind Spots as First-Class Output**

The standard design pattern for security tools is to output findings and omit gaps. SENTINEL inverts this: named blind spots — data sources that were unavailable and the specific uncertainty they create — are a mandatory component of every verdict. A verdict without named blind spots is structurally incomplete.

This transforms uncertainty from a liability into a navigational instrument: the analyst knows exactly where to look next. It also produces a compliance artifact: an auditor can see not just what SENTINEL found, but what its limits were at the time of analysis.

**4. Confidence as Epistemology, Not Probability**

ML-based security tools output confidence as a percentage (0–100%). No analyst has a calibrated intuition for what 73% confidence means in practice. SENTINEL's confidence ladder maps to independent source count and maps directly to analyst behavior:

- **Investigating** (1 source): insufficient corroboration — analyst investigates further using named blind spots as a guide
- **Probable** (2 independent sources): escalate and prepare response; do not wait for confirmation
- **Confirmed** (3+ independent sources): act; the corroboration standard is met

The ladder is interpretable, auditable, and defensible to a board or insurer.

### Market Context & Competitive Landscape

- **Commercial SIEM/detection (Darktrace, Vectra, Chronicle):** SaaS, $50k–$500k/year, black-box AI, correlates within vendor's data infrastructure, not auditable, cannot be deployed where data cannot leave the network
- **Open-source SIEM (Wazuh, OpenSearch Security):** Rule-based correlation, no AI analysis, no source independence, no structured verdict format — they produce alerts, not verdicts
- **AI security copilots (various):** Chat interfaces over existing data; assist analysts in querying but do not autonomously analyze and corroborate; do not produce audit-grade output
- **SENTINEL's position:** First open-source, MIT-licensed, multi-agent AI security analysis tool that enforces source independence, produces structured three-part verdicts with named blind spots, and outputs a stable, pipeable CLI contract — auditable, self-hostable, free

No existing tool occupies this position. The gap is structural, not a feature gap.

### Validation Approach

| Innovation | Validation Method | Done Condition |
|-----------|------------------|----------------|
| Corroboration engine source independence | Test with real GuardDuty alert + IP with VirusTotal hits; verify independence checker correctly classifies both as unconnected | Independence confirmed; verdict issued at Probable tier |
| Named blind spots accuracy | Test with missing API key or unavailable data source; verify gap is named and described | Blind spot names the missing source and the specific uncertainty created |
| Confidence ladder behavior | Test edge cases: single source, two sources, rate-limited source returning null | Each tier triggers correct output; null source handled gracefully |
| Sub-30-second execution | Time end-to-end on cold start with real alert | Verdict appears ≤30 seconds from input |
| Pipeable output | Pipe SENTINEL output to `jq` and parse `confidence_tier` | Downstream tool successfully parses output; schema stable |

### Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| LLM behavioral analysis produces inconsistent verdicts | Watchman prompt engineered with explicit output schema; verdict formatter validates schema before output; inconsistent output is a test failure |
| Source independence check incorrectly classifies dependent sources as independent | Independence checker uses source registry with explicit source taxonomy; registry is contributor-extensible and auditable |
| VirusTotal rate limiting degrades verdict quality | Exponential backoff built in; if Cipher cannot complete, verdict is issued at Investigating with Cipher as a named blind spot |
| Named blind spots are vague rather than actionable | Blind spot formatter uses structured templates: *"[Source] was unavailable. This creates a specific gap: [implication]. To close it, check: [next action]."* |

## CLI-Specific Requirements

### Project-Type Overview

SENTINEL is a scriptable CLI tool designed for two equal use cases: interactive terminal use by an analyst and pipeline integration by automated workflows. Every design decision serves both contexts simultaneously.

### Command Structure

```
sentinel [INPUT]
```

- **Positional argument:** `sentinel "paste alert or IOC here"` — input passed as a string argument
- **Stdin pipe:** `echo "alert" | sentinel` or `cat alert.json | sentinel` — input read from stdin
- **Auto-detection:** if stdin has data, read from stdin; if a positional argument is provided, use that; if neither, print usage and exit with code 2
- No subcommands in v1 — the single action is analysis; complexity via flags only if needed
- Shell completion is a v2 feature — not in scope for v1

### Output Formats

**Primary output: structured JSON to stdout**

```json
{
  "verdict": "Probable",
  "confidence_tier": 2,
  "methodology": [
    {"agent": "watchman", "action": "behavioral_analysis", "result": "suspicious"},
    {"agent": "cipher", "action": "ip_reputation", "result": "malicious"}
  ],
  "citations": [
    {"source": "VirusTotal", "indicator": "198.51.100.42", "reports": 12},
    {"source": "AbuseIPDB", "indicator": "198.51.100.42", "confidence": 90}
  ],
  "blind_spots": [
    "VPN logs unavailable — confidence ceiling 72%. To close: check VPN access logs for this IP in the same window."
  ],
  "source_independence_confirmed": true,
  "execution_time_seconds": 18.4,
  "timestamp": "2026-05-10T02:47:33Z"
}
```

- **Schema is stable across all v1.x patch releases** — no field renames, removals, or type changes without a major version bump
- `confidence_tier` is always an integer: 0 = insufficient data, 1 = Investigating, 2 = Probable, 3 = Confirmed
- `verdict` is always a string matching the tier: "Insufficient" / "Investigating" / "Probable" / "Confirmed"
- `blind_spots` is always an array, never null — empty array `[]` if no blind spots exist
- Human-readable summary may be printed to stderr for interactive use without polluting stdout

### Config Schema

All configuration via environment variables — no config files in v1:

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | API key for Watchman (Claude behavioral analysis) |
| `VIRUSTOTAL_API_KEY` | Yes | API key for Cipher (VirusTotal/AbuseIPDB lookup) |

- SENTINEL fails fast on startup if required variables are not set, printing a clear error message to stderr
- No `.env` file support, no config JSON, no settings files — environment variables only

### Exit Codes

| Code | Meaning | When |
|------|---------|------|
| `0` | Success | Verdict produced at any confidence tier |
| `1` | Analysis error | API failure, rate limit exhausted after backoff, network error |
| `2` | Input error | Empty input, missing required env vars, unparseable argument |

- Exit codes are for script error handling only — confidence tier is read from JSON output, not from exit code
- A verdict at Investigating tier exits `0` — the analysis completed; the tier is a finding, not a failure

### Scripting Support

- **Pipeable:** stdout is always clean JSON; human-readable messages go to stderr only
- **Composable:** `sentinel "alert" | jq '.confidence_tier'` works as expected
- **Predictable:** same input always produces structurally identical output (field presence, types); LLM analysis content may vary but schema does not
- **Non-interactive:** SENTINEL never prompts for input; if input is missing, it exits with code 2

### Implementation Considerations

- Python 3.10+ minimum (match Anthropic SDK requirements)
- Single entry point: `sentinel` command registered via `pyproject.toml` or `setup.py`
- All modules independently importable (even if Python module API is not a v1 public commitment, clean module boundaries enable the Contributor journey)
- `requirements.txt` with pinned exact versions; minimal dependency footprint

## Product Scope & Phased Development

### MVP Strategy & Philosophy

**Approach:** Problem-solving MVP — ship the minimum that produces a defensible, audit-grade verdict in under 30 seconds. Every v1 feature exists to serve the midnight analyst. No feature ships that doesn't serve that user directly.

**Resource requirements:** Solo developer, Python + Anthropic SDK + VirusTotal/AbuseIPDB APIs. ~300 lines of well-structured code. 30-day hard constraint.

**Deferral rule:** If week 3 shows the solo developer is behind, rate-limiting backoff is the one deferrable item — document the VirusTotal limits clearly in the README and add backoff in v1.1. Every other v1 MVP item is non-negotiable for ship.

### Phase 1 — MVP Feature Set (v1, 30 days)

**Core user journeys supported:** All four — Midnight Analyst (success), Uncertain Analyst (edge case), Contributor (first PR), Pipeline Builder (stable output contract)

**Non-negotiable capabilities (all must ship for v1):**
- Paste or pipe input (positional arg + stdin auto-detection)
- Watchman agent: Claude behavioral analysis with structured output schema
- Cipher agent: VirusTotal/AbuseIPDB IOC lookup with structured result
- Source independence checker with source registry
- Confidence ladder (Investigating / Probable / Confirmed) tied to independent source count
- Three-part verdict formatter (methodology, citations, named blind spots)
- Named blind spots detector — including "Watchman output malformed" as a valid blind spot (agent error is surfaced as a gap, never a crash)
- Structured JSON output to stdout with stable schema
- Exit codes: 0 / 1 / 2
- Environment variable credential handling (`ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`)
- MIT license, open-source on GitHub from commit one
- README: product description, ≤5-minute setup, data handling guarantee, connectivity limitations
- Public test suite running on every commit with CI badge — trust is verifiable, not claimed
- Pinned dependencies, minimal footprint

**Deferrable to v1.1 if behind schedule (one item only):**
- VirusTotal rate-limiting backoff — replaced by explicit documentation of free-tier limits (4 req/min, 500 req/day) in the README; user handles retry; backoff ships in v1.1

### Phase 2 — Growth Features (v1.5)

**Trigger:** First compound incident detected — two alerts converge in holding state and produce a joint verdict the terminal cannot adequately display.

- SQLite alert storage: corroboration count, source list, reassessment timer, alert status (active / dormant / closed)
- APScheduler background reassessment job per dormant alert
- Retroactive corroboration: new alert queries dormant alerts for pattern match, increments count on match
- Alert reactivation: dormant alert reaching two independent sources re-enters triage
- Living Alerts CLI output: dormant count, reactivation events
- VirusTotal rate-limiting backoff with exponential retry (if deferred from v1)
- Python module API: importable library with stable public interface

### Phase 3 — Vision (v2+)

**Trigger:** Living Alerts operational; first analyst reports they need to see case relationships visually.

- Minimal local web UI: active cases, corroboration counts, reassessment timers, convergence indicators
- Full agent suite: Phoenix (response playbooks), Bastion (hardening verification)
- Pattern Projection Engine: MITRE ATT&CK kill chain convergence detection across dormant alerts
- Hosted deployment tier for teams
- Enterprise support for regulated industries (SLAs)
- Local LLM support via Ollama (air-gapped environments)
- **Living Retraction Record:** when a verdict is invalidated by new evidence, a formal retraction document attaches to the original permanently; the original assessment is preserved unmodified; retractions log what was assessed, what overturned it, and what gap allowed the error — every false positive becomes a tuning artifact and an audit trail entry

### Risk Mitigation Strategy

**Technical risks:**

| Risk | Mitigation |
|------|-----------|
| Watchman (Claude) returns malformed output | Return Investigating verdict with "Watchman output malformed" as named blind spot — analyst gets a usable response, never a crash or silent failure |
| Source independence taxonomy ambiguous | Source registry uses explicit identifiers; registry is auditable and contributor-extensible; ambiguous sources default to same-source classification (conservative) |
| VirusTotal rate limit hit in pipeline context | Document limits clearly in v1 README; backoff ships in v1.1; analyst is warned via named blind spot if Cipher cannot complete |

**Market risks:**

| Risk | Mitigation |
|------|-----------|
| Security engineers distrust an unknown tool | MIT license, auditable codebase, public CI badge, named blind spots, glass-box reasoning chain — quality is verifiable, not claimed |
| Competitors ship a similar open-source tool first | Source independence enforcement is the structural moat; it cannot be added to an existing correlation-based tool without rebuilding the engine |

**Resource risks:**

| Risk | Mitigation |
|------|-----------|
| Solo developer falls behind in week 3 | Rate-limiting backoff is the only deferrable item; all other MVP features are non-negotiable; scope is already minimal by design |
| API costs exceed free-tier budget during development | Anthropic free tier sufficient for MVP testing; VirusTotal free tier (500 req/day) sufficient for development volume |

## Functional Requirements

### Input Handling

- **FR1:** An analyst can submit a security alert, log line, or IOC as a positional argument to SENTINEL
- **FR2:** An analyst can submit input to SENTINEL via stdin pipe
- **FR3:** SENTINEL auto-detects whether input arrives via stdin or positional argument without requiring user configuration
- **FR4:** SENTINEL reports a clear, actionable error message and exits with code 2 when no input is provided

### Corroboration Engine

- **FR5:** SENTINEL runs Watchman (LLM behavioral analysis) and Cipher (threat intelligence lookup) as independent analysis agents on every input
- **FR6:** SENTINEL enforces source independence — signals from the same data pipeline count as one source regardless of how many data points they produce
- **FR7:** SENTINEL maintains a source registry that categorizes each data source by independence group
- **FR8:** SENTINEL produces a confidence tier based on the count of structurally independent corroborating sources
- **FR9:** SENTINEL maps confidence tiers to human-readable labels: Investigating (1 independent source), Probable (2 independent sources), Confirmed (3+ independent sources)
- **FR10:** SENTINEL returns an Investigating verdict with "Watchman output malformed" as a named blind spot when Watchman returns output that cannot be parsed — the analyst always receives a usable response

### Verdict Generation

- **FR11:** SENTINEL generates a methodology section in every verdict listing agents run, execution order, and analysis logic applied
- **FR12:** SENTINEL generates a citations section in every verdict listing specific indicators, data sources, source identifiers, and independent source count
- **FR13:** SENTINEL generates a named blind spots section in every verdict listing data sources that were unavailable and the specific uncertainty each gap creates
- **FR14:** SENTINEL's named blind spots section is always present in output — it is an empty array when all sources returned data, never absent or null
- **FR15:** Each named blind spot includes an actionable implication: what the analyst should check to close the gap
- **FR16:** A contributor can extend SENTINEL's source registry to register a new corroboration source without modifying core engine logic

### Threat Intelligence

- **FR17:** Cipher queries VirusTotal for IP, domain, and file hash reputation data
- **FR18:** Cipher queries AbuseIPDB for IP reputation and abuse confidence data
- **FR19:** Cipher returns a structured result with an explicit reason when a source is not applicable to the input type (e.g., internal IPs have no external threat intel)
- **FR20:** SENTINEL documents VirusTotal free-tier rate limits explicitly in the README (4 req/min, 500 req/day)

### Output & CLI Integration

- **FR21:** SENTINEL outputs structured JSON to stdout on every completed analysis
- **FR22:** SENTINEL outputs human-readable status and progress messages to stderr only — stdout is always clean JSON
- **FR23:** SENTINEL's JSON output schema is stable across all v1.x patch releases — no field renames, removals, or type changes without a major version increment
- **FR24:** SENTINEL's JSON output includes `confidence_tier` as a machine-readable integer: 1 = Investigating, 2 = Probable, 3 = Confirmed
- **FR25:** SENTINEL's JSON output includes `verdict` as a string label matching the confidence tier
- **FR26:** A pipeline tool can parse SENTINEL's JSON output and extract any field without SENTINEL-specific parsing logic
- **FR27:** SENTINEL exits with code 0 when a verdict is produced at any confidence tier
- **FR28:** SENTINEL exits with code 1 when analysis fails due to an unrecoverable API error
- **FR29:** SENTINEL exits with code 2 when input is missing, empty, or required environment variables are not set

### Credential & Configuration

- **FR30:** SENTINEL reads API credentials exclusively from environment variables (`ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`)
- **FR31:** SENTINEL fails immediately with a clear error message when required environment variables are absent
- **FR32:** SENTINEL does not read credentials from config files, `.env` files, or command-line arguments

### Trust, Transparency & Data Handling

- **FR33:** SENTINEL's test suite is publicly accessible in the repository and runs automatically on every commit
- **FR34:** SENTINEL's repository displays a CI status badge showing whether the test suite is passing
- **FR35:** SENTINEL's README states the data handling guarantee explicitly: no incident data is stored; the only external transmission is to the Anthropic and VirusTotal/AbuseIPDB APIs as required for analysis
- **FR36:** SENTINEL's README states connectivity requirements and limitations explicitly: internet access to Anthropic and VirusTotal APIs required; air-gapped environments not supported in v1
- **FR37:** A new user can reach a working verdict within 5 minutes of cloning the repository
- **FR38:** SENTINEL's codebase is published under the MIT license from the first public commit

### Error & Edge Case Handling

- **FR39:** SENTINEL returns an Investigating verdict with Cipher named as a blind spot when Cipher cannot complete analysis — analysis errors in individual agents do not prevent a verdict from being produced
- **FR40:** SENTINEL never writes input data, IOCs, or alert content to disk during or after analysis
- **FR41:** SENTINEL analysis agents expose a consistent interface contract — each agent accepts a structured input and returns a structured result with a defined schema

## Non-Functional Requirements

### Performance

- **NFR1:** End-to-end verdict time — from command execution (Enter) to complete JSON fully printed on stdout — must not exceed 30 seconds on cold start with no prior process warm-up. No warm-start exceptions; the constraint is measured under the worst case.
- **NFR2:** Each analysis agent (Watchman, Cipher) has an individual timeout of 10 seconds by default. If an agent does not return within its timeout window, it is treated as a named blind spot and analysis proceeds with remaining sources.
- **NFR3:** Total agent execution budget is 25 seconds maximum, leaving 5 seconds for verdict formatting and output. The 30-second wall clock includes all phases: input parsing, agent execution, verdict formatting, and JSON output.
- **NFR4:** Agent timeout is configurable via the `SENTINEL_TIMEOUT` environment variable (integer seconds). If not set, defaults to 10 seconds per agent.

### Security

- **NFR5:** API credentials are never stored in plaintext files, config files, or command-line arguments. Credentials exist only in the process environment during execution.
- **NFR6:** No input data (alert content, IOCs, log lines) is written to disk at any point during analysis. All processing is in-memory only.
- **NFR7:** No telemetry, usage tracking, or analytics data is transmitted from SENTINEL to any party, including the developer.
- **NFR8:** All production dependencies are pinned to exact versions in `requirements.txt`. No floating version ranges in v1.
- **NFR9:** The dependency set is minimal — each dependency is a deliberate inclusion; transitive dependency bloat is avoided.
- **NFR10:** SENTINEL is released under the MIT license. The full license text is present in the repository root from the first commit.

### Reliability

- **NFR11:** All tests in the public test suite must pass on every commit. CI is the gate; no commit merges with a failing test suite.
- **NFR12:** No coverage floor is enforced in v1. Test quality takes precedence over coverage percentage — a small suite of well-written behavioral tests is the standard.
- **NFR13:** SENTINEL must never crash or exit unhandled on any input, including malformed alerts, empty input, binary data, or agent failures. Every error path produces either a structured error exit (code 1 or 2) or an Investigating verdict with the failure named as a blind spot.
- **NFR14:** Agent failures are isolated — a timeout or error in one agent does not prevent the other agent from completing or a verdict from being produced.
- **NFR15:** SENTINEL's JSON output schema produces the same field names, types, and structure on every run regardless of confidence tier or agent error state. Schema consistency is a hard invariant across all v1.x releases.

### Integration

- **NFR16:** Anthropic API (Watchman) integration must handle HTTP errors, connection timeouts, and malformed responses without propagating exceptions to the user — all failures become named blind spots.
- **NFR17:** VirusTotal and AbuseIPDB (Cipher) integrations must handle HTTP errors, 429 rate-limit responses, and connection timeouts gracefully. In v1, rate-limit responses are surfaced as a named blind spot with the free-tier limits documented in the README. Exponential backoff ships in v1.1.
- **NFR18:** SENTINEL's stdout JSON is parseable by standard tools (`jq`, Python `json.loads`, any JSON parser) without SENTINEL-specific libraries or schemas.
- **NFR19:** The `sentinel` command is registered as a standard entry point installable via `pip install .` or `pip install -e .`; no manual PATH manipulation required after install.
