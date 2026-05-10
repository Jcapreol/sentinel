# SENTINEL

SENTINEL is a multi-agent AI SOC analyst that tells you if a security alert is real, why it thinks so, and exactly what it couldn't see. It runs in your terminal. No dashboard, no SaaS, no black box verdicts.

---

## The Problem

You get paged at midnight. AWS GuardDuty fired on something you don't recognize. You have no SOC team, no incident response retainer, and no playbook. You have a laptop, a terminal, and the weight of knowing that if this is real and you miss it, it's on you.

Every SIEM and XDR on the market responds by giving you *more data*. More alerts. More dashboards. More things to click through while the clock runs.

SENTINEL does the opposite.

---

## How It Works

Drop in an alert, log line, or IOC. SENTINEL routes it through multiple independent agents, requires corroboration from structurally unconnected sources before issuing a verdict, and returns a single defensible output:

```
SENTINEL VERDICT
───────────────────���────────────────────
Status:     PROBABLE — 2 independent sources confirmed
Confidence: 68% (ceiling: 72%)

METHODOLOGY
Watchman:  Analyzed process behavior — PowerShell spawned from
           winword.exe, base64-encoded command, outbound connection
           attempt to 185.220.x.x on port 4444
Cipher:    Threat intel lookup — 185.220.x.x confirmed C2 node
           associated with Cobalt Strike infrastructure (VirusTotal,
           AbuseIPDB, 47 community flags)

CITATIONS
[1] Process tree anomaly — winword.exe → powershell.exe (T1566.001)
[2] C2 destination — 185.220.x.x flagged malicious, 3 independent sources

NAMED BLIND SPOTS
⚠ VPN logs unavailable — cannot confirm external origin of parent session
⚠ EDR telemetry not connected — process memory not examined
  Confidence ceiling capped at 72% until these sources are added

RECOMMENDED ACTIONS
1. Isolate host [hostname] immediately — block outbound on port 4444
2. Revoke active sessions for associated user account
3. Pull memory dump before reimaging — preserve forensic evidence
────────────────────────────────────────
```

No black box. No "our AI detected a threat." Every verdict shows its work.

---

## Agents

| Agent | Role |
|-------|------|
| **Watchman** | Behavioral analysis — reads the alert, identifies anomalies, maps to MITRE ATT&CK |
| **Cipher** | Threat intelligence — enriches IOCs against external sources, confirms or refutes |
| **Phoenix** | Incident response — generates specific, ordered response actions for this incident |
| **Bastion** | Hardening — identifies what control gap allowed this and how to close it |

v1 ships Watchman + Cipher. Phoenix and Bastion follow in v2.

---

## Design Principles

**Corroboration over confidence.** SENTINEL never issues a high-confidence verdict from a single source. Three structurally independent sources pointing to the same conclusion is the publication standard. One source is a lead, not a verdict.

**Living alerts, not dead tickets.** Low-priority alerts are never permanently closed — they enter a monitored holding state. When new signals arrive, SENTINEL checks them against every dormant alert. The attack that looked like noise at 2am may look like stage one of something larger by 6am.

**Named blind spots.** SENTINEL tells you exactly what it couldn't see and what that means for confidence. A gap statement is more useful than a false 95% score.

**Human final call, always.** SENTINEL is a research assistant, not a decision maker. Every output is designed to be read, verified, and signed off by a human analyst. The audit trail documents that a structured, evidence-based process was followed — not that the AI was infallible.

---

## Status

**Building in public. v1 in progress.**

- [x] Architecture designed
- [x] Agent roles defined
- [ ] Watchman agent (Anthropic API behavioral analysis)
- [ ] Cipher agent (VirusTotal / AbuseIPDB threat intel)
- [ ] Source independence checker
- [ ] Confidence ladder + verdict output
- [ ] Three-part verdict format with named blind spots
- [ ] CLI interface

Follow along. Star the repo. The founding user is a solo security engineer getting paged at midnight — if that's you, this is being built for you.

---

## Roadmap

**v1 — Terminal** *(in progress)*
Python CLI. Paste or pipe an alert. Get a defensible, evidence-backed verdict in under 30 seconds. Two agents, two independent sources, full methodology output.

**v2 — Living Alerts**
Persistent alert state with automatic reassessment on timers. Dormant alerts wake up when new signals arrive. Compound incident detection across correlated cases.

**v3 — Web UI**
Minimal local web interface showing active cases, corroboration counts, and which dormant alerts are trending toward convergence. Still self-hosted. Still no SaaS.

---

## Self-Hosted by Design

SENTINEL runs in your environment. Your incident data never leaves your infrastructure. The code is open so you can read exactly what it does with your security data. For healthcare, fintech, and anyone under compliance requirements — that's not a nice-to-have.

---

## Setup *(coming with v1)*

```bash
git clone https://github.com/Jcapreol/sentinel.git
cd sentinel
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key
export VIRUSTOTAL_API_KEY=your_key
python sentinel.py --alert "your alert here"
```

---

## Contributing

Open source, MIT licensed. Issues and PRs welcome. If you're a security engineer who wants to help shape what this becomes — open an issue and tell me what your midnight looks like.

---

*Built by a cybersecurity student who got tired of security tools that make the problem harder.*
