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

## Watchman's contribution is not fixed

An earlier version of this document claimed Watchman's output is "normalized
to a fixed total regardless of how many findings it produces," based on three
records where it summed to 0.50 (6 x 0.0833, 7 x 0.0714, 8 x 0.0625).

That claim is wrong. The jillas and jerryas records total 0.70 (7 x 0.1 and
8 x 0.0875). The total varies.

In both of those records it lands exactly equal to the benign auth weight,
which is either coincidence twice over or a property of the algorithm. The
mechanism has not been traced. It is under investigation; this document should
be updated once the answer is known rather than guessed at again.

What holds regardless: Watchman's contribution is capped well below what full
authentication contributes, and in every case above the verdict follows the
auth arithmetic rather than the content evidence.

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
lookup returned "1 suspicious" and was recorded with direction neutral,
contributing nothing directional.

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
