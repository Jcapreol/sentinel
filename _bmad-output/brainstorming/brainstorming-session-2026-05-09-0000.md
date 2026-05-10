---
stepsCompleted: [1, 2, 3, 4]
session_active: false
workflow_completed: true
inputDocuments: []
session_topic: 'SENTINEL - open source multi-agent AI-powered SOC platform using BMAD cyber-ops agents (Watchman, Cipher, Phoenix, Bastion) to give small security teams enterprise-grade SOC capabilities'
session_goals: 'Clear product vision, target users, core features, differentiation from competitors, buildable roadmap for solo Python/AI developer'
selected_approach: 'ai-recommended'
techniques_used: ['First Principles Thinking', 'Cross-Pollination', 'Resource Constraints']
ideas_generated: []
context_file: ''
---

# Brainstorming Session Results

**Facilitator:** Jackson
**Date:** 2026-05-09

## Session Overview

**Topic:** SENTINEL — Open source multi-agent AI-powered SOC platform
**Goals:** Product vision · Target users · Core features · Differentiation · Buildable roadmap

### Session Setup

Solo developer, 18-year-old cybersecurity student, Python + AI APIs, open-source project.
Constraint is a feature: lean, AI-native, no enterprise baggage.

## Technique Selection

**Approach:** AI-Recommended Techniques
**Analysis Context:** Complex technical domain, competitive market, solo developer constraints

**Recommended Techniques:**
- **First Principles Thinking:** Deconstruct what a SOC actually is to find the defensible moat
- **Cross-Pollination:** Import unexpected patterns from other domains (newsrooms, ERs, open-source incident response)
- **Resource Constraints:** Use solo/student/Python constraints to force the essential MVP and roadmap

**AI Rationale:** Strip assumptions first, generate genuine differentiation second, scope to what can actually ship third.

---

## Idea Organization and Prioritization

### Theme 1: Product Vision & Philosophy
*What SENTINEL fundamentally is — and why it's a new category, not a better SIEM.*

- **The Verdict Engine** — SENTINEL's core value is decisional clarity under pressure. Every other SOC tool gives you more data when you're panicking. SENTINEL gives you a verdict first: real or noise, confidence score, why. The analyst's cognitive load drops from 100% to 20% before they've typed a single query.
- **The 3-Step Bleeding Stopper** — When a threat is confirmed, SENTINEL surfaces exactly three actions, ordered by impact, tailored to this incident, this environment, right now. Not a runbook. A response written for this attacker.
- **The 2am Second Brain** — SENTINEL isn't a tool the analyst uses — it's a colleague who's already looked at it. The psychological function is confirmation of judgment, not information delivery. The multi-agent architecture IS that second brain.
- **The Glass Box Principle** — Every output exposes its full reasoning chain. The format structurally enforces transparency — you cannot produce a verdict that doesn't show its work.
- **Calibrated Uncertainty as a Feature** — SENTINEL actively communicates what it doesn't know. Named gaps are as important as findings — they tell the analyst exactly where to look next.
- **The Research Assistant Architecture** — Watchman reads everything first. Cipher knows what it means. Phoenix knows what to do. Bastion closes the gap after. The human orchestrates. SENTINEL researches.

---

### Theme 2: Market & Buyers
*Three distinct buyers for the same feature — and one founding user who makes it real.*

- **The Three-Buyer Stack** — The same incident report serves three stakeholders: the analyst needs a decision, the CTO needs a defensible narrative, the compliance team needs an artifact. One output, three buyers, three reasons to pay.
- **The Cyber Insurance Wedge** — SENTINEL generates an insurance-ready evidence package automatically. Insurers now require proof of documented incident response process. No SOC tool is positioned as an insurance compliance instrument. This is an unserved market in chaos.
- **The Solo Analyst as Three Roles** — At companies under 200 people, the analyst IS the CTO, IS the compliance owner, IS the person who talks to the insurance broker. All three outputs go to one exhausted person — which makes the tool even more compelling.
- **The Founding User** — Solo security engineer, Series A startup, 50–150 employees, paged at midnight by an AWS GuardDuty alert they don't recognize. No SOC team. No retainer. No playbook. They will clone SENTINEL and drop in that alert within 10 minutes because the alternative is 3 hours of manual IOC lookups and an uncertain triage doc they can't defend. This person exists at thousands of startups right now. Every SENTINEL feature is validated against: does this make their midnight better?

---

### Theme 3: Business Model & Positioning
*Why open-source is the moat, not the compromise.*

- **The Sovereignty Moat** — Healthcare and fintech cannot send incident data to third-party SaaS without legal exposure. SENTINEL runs in their environment, touches nothing external, code is auditable. Every commercial SOC SaaS is structurally disqualified from regulated verticals. SENTINEL is qualified by default.
- **Quality as the Only Moat** — Open-source forces a discipline VC-funded competitors don't have. The product must be genuinely good because there's no sales layer to hide mediocrity. In a market full of AI security theater, a product that proves its quality through transparency is a category of one.
- **The Open-Core Ladder** — Free self-hosted builds community and trust. Hosted deployment serves teams who want SENTINEL but not the DevOps burden. Enterprise support serves regulated companies needing SLAs. Three revenue layers, each unlocked as the user grows. Classic model (Grafana, GitLab, n8n) applied to a space that has never had a credible open-source player.
- **Open Source From Day One** — GitHub goes live before v1 ships. Security engineers who watch SENTINEL get built in public trust it more than a product that appears fully formed. The README IS the product's first output: *"SENTINEL is a multi-agent AI SOC analyst that tells you if a security alert is real, why it thinks so, and exactly what it couldn't see. It runs in your terminal. No dashboard, no SaaS, no black box verdicts."*

---

### Theme 4: Core Detection Architecture
*The technical foundation that makes SENTINEL structurally different from every SIEM.*

- **The Corroboration Engine** — SENTINEL never issues a verdict from a single data source. Every assessment requires independent confirmation from structurally unconnected sources. Three unconnected sources converging = high-confidence verdict. One source = investigating. Two = probable, escalate. Three+ = confirmed, act.
- **The Source Independence Test** — Not all corroboration is equal. Two signals from the same log pipeline count as one source, not two. This distinction — independence vs. mere multiplicity — is what separates rigorous analysis from correlated noise. It eliminates an entire class of false positives.
- **The Confidence Ladder** — Outputs map to human-readable, auditable states that trigger different agent behaviors. Security tools use ML scores (0–100%) nobody trusts. SENTINEL's ladder is interpretable, defensible, and maps directly to actions.
- **Living Alert Protocol** — No alert is ever permanently closed — only put into a monitored holding state with a reassessment timer and dormant correlation window. When new signals arrive, they're checked against every dormant alert. Dead tickets become living cases. This is the structural mechanism for catching APTs.
- **Retroactive Corroboration** — When a new signal arrives, SENTINEL queries the dormant holding state first. If it raises the corroboration count on a sleeping alert from one source to two, that alert reactivates with the new signal attached. Stage 1 looks like noise. Stage 2 looks like noise. Stage 3 triggers the compound verdict on all three simultaneously.
- **The Never-Miss Protocol** — Certain IOC patterns always trigger specific agent workflows regardless of confidence score. A process spawning from an Office document always routes to Cipher. Admin credential use outside business hours always triggers Bastion to verify MFA status. Not because these are definitely attacks — because missing them when they are is unacceptable.

---

### Theme 5: Multi-Agent Orchestration
*The ATC-grade operational architecture that makes multi-agent AI reliable.*

- **The Ownership Protocol** — Every alert has exactly one owner at all times: an agent, a human analyst, or the monitored holding state. An alert without an owner is a system error, not a normal state. The architecture cannot produce an alert in limbo.
- **The Structured Handoff Brief** — Ownership transfer requires a documented briefing: what was found, what couldn't be resolved, the specific question for the receiving agent. The receiving agent confirms before ownership transfers. Every handoff brief is logged — the full reasoning chain is reconstructable from the briefs alone.
- **Flow Control and Agent Focus** — Under load, SENTINEL applies flow control: high-confidence, high-severity alerts get dedicated agent focus. Everything else enters the monitored holding state. Agents do one thing well rather than ten things badly. The system degrades gracefully instead of catastrophically.
- **Pattern Projection Engine** — SENTINEL continuously models convergence scenarios across all dormant alerts. Using MITRE ATT&CK kill chain mapping, it recognises when dormant alerts collectively spell a known attack pattern — even before any individual alert reaches confirmation threshold. Detection happens at the pattern level, not the event level.
- **Pre-Positioning Protocol** — When pattern projection identifies a convergence trending toward a compound incident, SENTINEL pre-assigns Phoenix as incident commander, pre-loads the relevant response playbook, and alerts the analyst: "Two dormant cases are trending toward a ransomware prelude. Neither has confirmed. Recommend review now."
- **Kill Chain Shape Recognition** — SENTINEL maps every dormant alert to its MITRE ATT&CK tactic. When the combination covers three or more sequential tactics in a known attack chain, compound confidence rises regardless of individual alert confidence. Attackers who stay below individual thresholds ("living off the land") are now detectable by pattern shape.

---

### Theme 6: Trust & Compliance Layer
*The peer-review standard that makes SENTINEL defensible to boards, auditors, and insurers.*

- **The Three-Part Verdict Standard** — Every verdict ships with three mandatory attachments: methodology (agents run, order, logic), citations (specific indicators, log sources, timestamps, source count), confidence interval (sources confirmed, never-miss criteria matched, specific named gaps). A verdict without all three is structurally incomplete.
- **Named Blind Spots** — SENTINEL explicitly names what it couldn't see. "VPN logs were unavailable. This creates a specific gap: confidence ceiling 72%." The gap statement tells the analyst exactly where to look next and tells the auditor exactly what the system's limits were. Named blind spots turn a liability into a feature.
- **The Living Retraction Record** — When a verdict is invalidated, a formal retraction document attaches to the original permanently. The original assessment is preserved unmodified. Retractions document what was assessed, what overturned it, and what gap allowed the error. Every false positive becomes a tuning artifact. The record of being wrong is part of the audit trail — which is what an insurer or auditor actually wants to see.

---

### Theme 7: Roadmap
*Three phases, each with a hard "done" condition, all buildable solo in Python.*

- **The SENTINEL v1 Soul** — Three features done right: Corroboration Engine (structural differentiation), Living Alerts (APT detection), Three-Part Verdict Standard with Named Blind Spots (trust layer). Everything else is v2. Shipping these three without anything else is shipping a complete product.
- **The 30-Day MVP** — Python CLI. Input: paste or pipe a single alert, log line, or IOC. Watchman (Anthropic API) + Cipher (VirusTotal/AbuseIPDB) run independently, source independence confirmed. Output: confidence ladder verdict + three-part standard. Zero setup beyond API keys. 30 seconds in a terminal. No equivalent exists in any free or open-source tool.
- **The v2 Trigger and Scope** — v2 ships when Living Alerts produces its first compound incident — the moment a terminal can't show the relationship between converging cases. v2 adds a minimal local web UI: active cases, corroboration count, reassessment timer, convergence indicator. Flask or FastAPI backend. Still local, still self-hosted. The UI exists to show one thing: which dormant alerts are moving toward each other.

---

## Prioritization Results

**Top 3 Protected (v1 Soul — non-negotiable):**
1. **Corroboration Engine** — structural differentiation, the idea that makes SENTINEL not a SIEM
2. **Living Alerts** — the APT-catching feature nothing else on the market does
3. **Three-Part Verdict Standard + Named Blind Spots** — the trust layer that makes SENTINEL a professional instrument

**Quick Win (30-day MVP):**
- Python CLI, Anthropic API + VirusTotal/AbuseIPDB, source independence check, confidence ladder, structured three-part output
- Single input format (paste alert or IOC), single output format (terminal), two agents only
- Open-source from day one on GitHub

**v2 Scope (after first compound incident):**
- SQLite alert storage + APScheduler for timers
- Retroactive corroboration on new signal arrival
- Minimal web UI for case relationships and convergence indicators

**v3 Scope (production-ready):**
- Full agent suite (Phoenix response playbooks, Bastion hardening)
- Pattern Projection Engine (MITRE ATT&CK kill chain convergence)
- Hosted deployment tier for teams who don't want self-hosting
- Enterprise support offering for regulated industries

---

## Action Plans

### Priority 1: Ship the 30-Day MVP

**Week 1–2: Core Engine**
1. Set up Python project structure, Anthropic SDK, VirusTotal API integration
2. Build Watchman agent: prompt engineering for behavioral analysis of alert/IOC input
3. Build Cipher agent: structured VirusTotal/AbuseIPDB lookup with parsed output
4. Build source independence checker: confirm the two sources are structurally unconnected
5. Build confidence ladder logic: tally independent source count → verdict tier

**Week 3–4: Output Layer**
1. Build three-part verdict formatter: methodology section, citations section, confidence interval section
2. Build named blind spots detector: if a data source was unavailable, name it explicitly
3. Polish CLI interface: clean terminal output, readable formatting
4. Write README (three sentences first, then full docs)
5. Push to GitHub, open-source under MIT or Apache 2.0

**Resources needed:** Anthropic API key (free tier sufficient for MVP), VirusTotal API key (free tier: 4 requests/minute), Python 3.10+, ~300 lines of well-structured code
**Done condition:** Drop in a real GuardDuty alert and get a defensible three-part verdict in under 30 seconds

---

### Priority 2: Build Living Alerts (v1.5)

**Week 5–8: Persistent State**
1. Add SQLite database: alert storage schema with corroboration count, source list, reassessment timer, status (active/dormant/closed)
2. Integrate APScheduler: background reassessment job fires on timer per dormant alert
3. Build retroactive corroboration: on new alert input, query dormant alerts for pattern match, increment corroboration count if match found
4. Build alert reactivation: when dormant alert reaches two sources, pull from holding state and re-enter triage
5. Update CLI: show dormant alert count, reactivation events

**Done condition:** Submit two related alerts 30 minutes apart and watch the second one reactivate the first with a compound verdict

---

### Priority 3: v2 Web UI

**Trigger condition:** First compound incident (two alerts converge in the holding state)
**Scope:** Flask backend exposing alert state via REST API, minimal HTML/JS frontend showing active cases, corroboration counts, timers, convergence indicators
**Done condition:** An analyst can see at a glance which dormant alerts are trending toward each other without reading terminal output

---

## Session Summary and Insights

**Key Achievements:**
- Defined a new product category: threat prediction at the pattern level, not the event level
- Identified three distinct buyers (analyst, CTO, compliance) from a single core feature (audit trail)
- Derived SENTINEL's entire detection architecture from journalism, ER triage, and air traffic control — not from existing security tooling
- Produced a complete v1 spec buildable solo in Python in 30 days
- Identified the founding user with surgical precision: solo security engineer, Series A startup, midnight GuardDuty alert

**Creative Breakthroughs:**
- "Most tools give you more data when you're panicking. That makes it worse." — the entire SIEM market failure in one sentence
- "Living alerts that breathe and reassess instead of dead tickets that close and disappear" — product copy and architecture spec simultaneously
- "The record of being wrong is part of the audit trail" — reframes false positives from failures into trust-building artifacts
- Three buyers for the same feature — analyst gets decision support, CTO gets liability protection, compliance gets documentation

**The Product in One Paragraph:**
SENTINEL is a multi-agent AI SOC analyst that operates at the pattern level, not the event level. It requires journalism-grade corroboration (three independent sources) before issuing a verdict. It never closes an alert — only puts it in a monitored holding state that wakes up when new signals arrive. Every verdict ships with a full methodology, evidence citations, and named blind spots. It runs in your terminal, open-source, in your environment, with no data leaving your infrastructure. It serves the solo security engineer who gets paged at midnight with no team, no playbook, and no margin for error — and it produces outputs defensible to a board, an auditor, and a cyber insurer.

**What Makes This Session Valuable:**
The product vision, architecture, trust model, business model, target user, and roadmap were all derived from first principles — not from copying existing tools. SENTINEL's differentiation is structural, not superficial. That's the kind of moat that can't be replicated by a feature sprint.

**Facilitator Notes:**
Jackson arrived with a strong concept and left with a complete product. The breakthrough moment was "most tools give you more data when you're panicking" — that single insight reframed every subsequent decision. The multi-domain cross-pollination (journalism → ER → ATC → peer review) produced an architecture that no competitor has assembled because no competitor started from these first principles.
