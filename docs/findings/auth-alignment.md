# Finding: Header Auth Structurally Outweighs Content Analysis

Date: 2026-08-20
Status: Confirmed on live production data. No fix proposed yet.

## Summary

One phishing campaign sent three messages to the monitored inbox over eight
days. Sentinel produced three different verdicts: Benign, Deferred, and
Malicious. The content analysis was correct all three times. The verdict was
determined entirely by the SPF/DKIM/DMARC posture of the compromised account
used to send it.

A phishing message sent from a compromised account with correctly configured
email authentication is currently undetectable by Sentinel, regardless of how
much malicious content evidence exists.

## The campaign

Same display name, same social-engineering pattern, three compromised accounts
at three institutions in three countries. All three arrived via Microsoft 365
infrastructure (outbound.protection.outlook.com), meaning three separate
legitimate M365 tenants were sending on the attacker's behalf.

Subject lines use photo-sharing pretexts: "Re: Photos from 2007", "2 (pics)",
"9 (2026)". Each contains a link to a freshly registered obfuscated domain.
All three were independently spam-foldered by Gmail.

## The three records

| Sender | SPF | DKIM | DMARC | Benign auth weight | Verdict |
|---|---|---|---|---|---|
| s2240102@u.tsukuba.ac.jp | pass (0.25) | pass (0.35) | pass (0.45) | 1.05 | Benign 0.000 |
| lion.soulaphy@bizgital.com | pass (0.25) | pass (0.35) | absent (0.1 neutral) | 0.60 | Deferred 0.500 |
| 4750948u@sp46.waw.pl | softfail (0.3 malicious) | pass (0.35) | absent (0.1 neutral) | 0.35 | Malicious 1.000 |

## The mechanism

Watchman produced 6, 7, and 8 malicious findings respectively. Its total
contribution was 0.5 in all three cases: 6 x 0.0833, 7 x 0.0714, 8 x 0.0625.

Watchman's output is normalized to a fixed total regardless of how many
findings it produces. More evidence does not produce more weight.

Full authentication pass contributes 1.05 benign. Watchman's ceiling is 0.5
malicious. Content analysis therefore cannot outvote a fully auth-passing
sender under any circumstances, no matter what it finds.

The three verdicts follow directly:

- 1.05 benign vs 0.5 malicious: benign wins decisively.
- 0.60 benign vs 0.5 malicious: near parity, structural deferral fires.
- 0.35 benign plus 0.3 malicious from SPF softfail, vs 0.5 from Watchman:
  malicious wins.

## A narrower gap inside the same finding

The tsukuba record's DMARC result is `dmarc=pass (p=NONE sp=NONE dis=NONE)`.
The domain publishes a DMARC record with no enforcement policy. The message
passes because alignment holds, not because any policy is being enforced.

Sentinel assigns 0.45 benign weight to a DMARC pass regardless of the
published policy. A `p=NONE` pass and a `p=reject` pass are treated
identically, despite representing very different levels of assurance from the
domain owner.

This is more tractable than the main finding. DMARC policy strength is present
in the header and parseable, and modulating the weight by policy would be a
bounded change. It would not close the blind spot on its own, since a
compromised account at a `p=reject` domain still passes cleanly.

## What Watchman actually found

On the record that was called Benign, Watchman reported: an obfuscated
non-standard domain, a generic social-engineering subject pretext, a URL
fragment identifier suggesting a credential harvesting page, manufactured
false familiarity, a reply-to format indicating a spoofed or compromised
sender identity, and suspicious domain character patterns.

Every one of those was correct. The message was genuine phishing. It was
scored 0.000, the most confident possible benign verdict.

## Threat intelligence contributed nothing

Across all three records, VirusTotal returned 404 or zero detections,
AbuseIPDB does not support domain lookups at all, and URLhaus had no match.
The domains were too new to appear in any reputation feed.

This is the expected behavior for freshly registered infrastructure and it is
the reason behavioral analysis exists. It also means that in exactly the cases
where content analysis matters most, it is also structurally outweighed.

## This contradicts an earlier conclusion

In Epic 4 the auth-alignment question was investigated and closed as
"hypothesized but unconfirmed." That investigation ranked stored records by
malicious weight and found every top-weighted sender to be legitimate,
concluding that header auth weight was load-bearing and correct.

That method could not have found this. It examined what got flagged. This
failure mode is a true positive being suppressed, which by definition does not
appear in that ranking. The earlier conclusion was not wrong about what it
measured; it was measuring the wrong thing.

Lesson worth keeping: to find false negatives, you have to look at what was
called benign, not at what was called malicious.

## Why the obvious fix is wrong

Raising Watchman's weight would resolve this case and break a larger one.

A DIOR marketing email in the same evidence store produced six Watchman
findings: obfuscated tracking URLs, base64-encoded parameters, all links
routed through a single tracking domain, promotional structure described as
"typical of spear-phishing campaigns." Every one of those is also true of real
phishing. It resolved Benign at 0.000 because auth passed cleanly.

Legitimate commercial email is structurally indistinguishable from phishing at
the content level. Header auth is what separates them. Weakening it to catch
compromised-account phishing would flood the system with false positives on
ordinary marketing mail.

The two problems pull in opposite directions. Any fix has to distinguish "auth
passes because the sender is legitimate" from "auth passes because the
attacker is using a legitimate sender's account," which is not a question
either signal can answer alone.

## Also noted: a Watchman error

On the bizgital record, Watchman reported: "Future date timestamp (August
2026) is anomalous and suggests potential alert fabrication or spoofing."

August 2026 was the present. The model treated the current date as impossible.
The finding happened to point in the correct direction, which makes it more
dangerous rather than less: a wrong signal that agrees with the right answer
is invisible until it disagrees.

Worth tracking separately from the main finding.

## Artifacts

Three .eml files with full headers, preserved before Gmail's 30-day spam
deletion. Three decrypted verdict records with complete evidence lists. Raw
header verification confirmed the tsukuba record's spf=pass, dkim=pass, and
dmarc=pass independently of Sentinel's own parsing.

## Status

Not scoped for a fix. The problem is understood; the solution is not. Any
proposal needs to survive the DIOR case above, which rules out simple
reweighting. Candidate directions worth exploring separately: sender history
as an independent signal, treating auth-pass as weaker evidence when the
sending domain has no prior relationship with the recipient, or a
meta-classifier that recognizes when content and auth signals disagree
strongly rather than averaging them.
