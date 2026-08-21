# Finding: Header Auth Structurally Outweighs Content Analysis

Date: 2026-08-20, revised 2026-08-21
Status: Confirmed on live production data. Two distinct mechanisms. No fix
proposed.

## Summary

Email authentication proves a sender controls the domain they claim. It does
not prove the domain is trustworthy. Sentinel weights auth heavily enough that
a message passing SPF and DMARC cannot be flagged on content evidence alone,
no matter how much of it there is.

Five confirmed-phishing messages in the live store demonstrate this, arriving
by two different routes.

## Two mechanisms

### Mechanism A: compromised legitimate account

An attacker sends from a real organization's mailbox. Auth passes because the
organization configured it correctly, years ago, for legitimate reasons. The
attacker borrows that reputation.

Requires first breaching a real organization.

### Mechanism B: attacker-registered domain with correct auth

An attacker registers a domain, points SPF at their own server, publishes
DMARC with a reject policy, and sends. Every authentication check passes
because the attacker genuinely does control the domain.

Requires a credit card. Roughly ten dollars.

Mechanism B is cheaper, more scalable, and equally invisible to auth-weighted
detection. The finding as originally written only described Mechanism A.

## Domain age separates them cleanly

| Sending domain | Registered | Mechanism |
|---|---|---|
| u.tsukuba.ac.jp | University of Tsukuba, National University | A |
| sp46.waw.pl | 2013-10-02 | A |
| bizgital.com | 2016-02-11 | A |
| jerryas.org | 2026-05-19T06:36:37Z | B |
| jillas.org | 2026-05-19T06:36:37Z | B |

jerryas.org and jillas.org share a registration timestamp to the second, same
registrar (Dynadot), one-year terms. That is scripted bulk registration, not
two independent purchases. Both were roughly three months old when they sent.

## The records

All five are confirmed phishing. Weights are as recorded in the evidence store.

| Sender | Auth signals | Benign auth weight | Watchman total | Verdict |
|---|---|---|---|---|
| s2240102@u.tsukuba.ac.jp | spf pass, dkim pass, dmarc pass | 1.05 | 0.50 | Benign 0.000 |
| lion.soulaphy@bizgital.com | spf pass, dkim pass, no dmarc | 0.60 | 0.50 | Deferred 0.500 |
| 4750948u@sp46.waw.pl | spf softfail, dkim pass, no dmarc | 0.35 | 0.50 | Malicious 1.000 |
| from@jillas.org | spf pass, dmarc pass, no dkim | 0.70 | 0.70 | Deferred 0.500 |
| from@jerryas.org | spf pass, dmarc pass, no dkim | 0.70 | 0.70 | Deferred 0.500 |

The three Mechanism A records are the same campaign, same display name
("Matthias Mckusker"), photo-sharing pretexts, eight days apart, all via
Microsoft 365 infrastructure. The only variable across them is the compromised
account's auth posture, and it determines the verdict entirely.

The two Mechanism B records are a separate campaign with a different lure
(romantic/apology framing) and no DKIM at all. DMARC passes on SPF alignment
alone, so the attacker skipped signing. Minimum viable authentication.

## Watchman's contribution is tier-capped, not fixed

An earlier version of this document claimed Watchman's output is "normalized
to a fixed total regardless of how many findings it produces," based on three
records where it summed to 0.50 (6 x 0.0833, 7 x 0.0714, 8 x 0.0625). The
jillas and jerryas records total 0.70 instead (7 x 0.1, 8 x 0.0875), which
disproves the "fixed" part. The mechanism has now been traced.

The weight lives in `src/sentinel/watchman.py`, not `confidence.py` — that
file is the older CLI tool's Watchman/Cipher corroboration tiering, unrelated
to phishing-triage scoring.

    _CONFIDENCE_WEIGHT = {"confirmed": 0.7, "probable": 0.5, "investigating": 0.3}
    weight = _CONFIDENCE_WEIGHT[tier] / len(findings)

Each finding gets `tier_weight / N`, where `tier_weight` is one of exactly
three values keyed to Watchman's own self-reported confidence for that
message, and N is how many findings it listed. The division by N was added in
Story 2.2 specifically so that one LLM inference listing more findings does
not get more total influence for being verbose — N findings collectively
contribute the same total weight-mass to the score that a single finding at
the tier weight would.

So Watchman's total per message is always exactly 0.3, 0.5, or 0.7 — never a
universal constant, but never anything outside those three values either.
Finding count only changes how that total is split across individual
EvidenceItems.

jillas.org and jerryas.org both scored "confirmed" — Watchman's maximum tier,
its strongest possible self-assessment — and both still resolved Deferred.

The ceiling matters beyond these two records. 0.7 is the most Watchman can
ever contribute, at any confidence level, with any number of findings. Full
authentication passing all three mechanisms contributes 1.05 (the tsukuba
record). 0.7 < 1.05. On a fully-authenticated sender, no Watchman output —
not more findings, not higher confidence, not both — can outweigh auth. The
ceiling is structural, not incidental to these particular records.

### The 0.70 parity is coincidence

Watchman's total equaled the benign auth weight exactly in the two Mechanism
B records (0.70 = 0.70) and not in any of the three Mechanism A records (0.50
against 1.05, 0.60, and 0.35 — see the table above). Five records, two
independently-computed numbers, agreement in two of five: consistent with two
small, unrelated value sets occasionally colliding, not with a shared
mechanism.

There is no code path connecting the two numbers. `watchman.py`'s
`_CONFIDENCE_WEIGHT` and `headers.py`'s `_MECHANISM_PASS_WEIGHT` are
independent constants in separate modules, computed from unrelated inputs — an
LLM's categorical self-assessment of email content versus a deterministic
header check. In the jillas/jerryas case, 0.70 came from Watchman rating
"confirmed" (0.7) and separately from SPF pass (0.25) + DMARC pass (0.45) with
no DKIM signal at all — both domains skip signing entirely. Different
mechanisms, same number, by chance.

## Watchman was correct every time

On the record scored Benign 0.000, Watchman reported an obfuscated
non-standard domain, a social-engineering subject pretext, a URL fragment
suggesting credential harvesting, manufactured false familiarity, a spoofed or
compromised sender identity, and suspicious domain character patterns.

On the jillas record its first finding began "Phishing email with deceptive
subject line." Not hedged. Still Deferred.

The content analysis is not the weak component.

## Threat intelligence contributed nothing

Across all five records: VirusTotal returned 404 or zero detections, AbuseIPDB
does not support domain lookups at all, URLhaus had no match. One VirusTotal
lookup (jerryas.org) returned "0 malicious, 1 suspicious" and was recorded
with weight 0.20, direction neutral — contributing nothing directional.

That is deliberate, not a gap. `cipher.py`'s `_vt_weight_and_direction` only
returns `direction="malicious"` when at least one engine flags malicious
outright; a suspicious-only result gets weight but never direction. The
scoring function defines a neutral item's contribution to the signed sum as
exactly 0.0 regardless of its weight — the weight only feeds the denominator,
damping the score toward the neutral prior, never pushing it toward a
verdict. Cipher's reputation checks are already barred from ever asserting
"benign"; this extends the same conservatism to weak "malicious" signals —
"suspicious" alone doesn't clear the bar either.

Freshly registered infrastructure does not appear in reputation feeds. That is
expected, and it is exactly why behavioral analysis exists. It also means the
cases where content analysis matters most are the cases where it is most
outweighed.

## This contradicts an earlier conclusion

In Epic 4 the auth-alignment question was investigated and closed as
"hypothesized but unconfirmed." That investigation ranked stored records by
malicious weight and found every top-weighted sender legitimate.

That method could not have found this. It examined what got flagged. This
failure mode is a true positive being suppressed, which by definition does not
appear in that ranking.

Lesson: to find false negatives, look at what was called benign, not at what
was called malicious.

## Why the obvious fix is wrong

Raising Watchman's weight would resolve these cases and break a larger one.

A DIOR marketing email in the same store produced six Watchman findings:
obfuscated tracking URLs, base64-encoded parameters, all links through one
tracking domain, promotional structure described as "typical of spear-phishing
campaigns." All true. It resolved Benign 0.000 because auth passed cleanly.

Legitimate commercial email is structurally indistinguishable from phishing at
the content level. Header auth is what separates them. Weakening it would
flood the system with false positives on ordinary marketing mail.

## What might actually help

Not proposals, directions. None are scoped.

Domain age is not currently used and is freely available via whois. A domain
publishing a reject policy three months after registration is a different
proposition from one that has published it since 2013. This would address
Mechanism B specifically and cheaply.

DMARC policy strength is now captured (Story 9.1) but not weighted. Note it
would not have helped here: jerryas.org publishes p=REJECT.

Sender history, or treating auth-pass as weaker evidence when the sending
domain has no prior relationship with the recipient, addresses both mechanisms
but requires state Sentinel does not keep.

A meta-classifier that recognizes strong disagreement between content and auth
signals, rather than averaging them.

## Artifacts

Four .eml files with full headers in sentinel-samples, preserved before
Gmail's 30-day spam deletion. Five decrypted verdict records. Raw-header
verification independent of Sentinel's parsing on two of them, including
`dmarc=pass (p=REJECT sp=REJECT dis=NONE)` on jerryas.org.

## Status

Not scoped for a fix. The problem is understood; the solution is not. Any
proposal must survive the DIOR case, which rules out simple reweighting, and
must account for both mechanisms rather than only compromised accounts.
