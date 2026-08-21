# Design Doc: Human Labelling of Verdict Records

Status: Decisions made. Story 11.1 specced below.

**Note on provenance:** Story 11.1's own spec says this doc is "committed
alongside this story." It was not found in the repository when work began.
This file was authored during Story 11.1's implementation instead, using the
story's own "Decisions already made" section (D1-D3) as source material,
expanded with the reasoning worked out while building against them. Flagged
here rather than silently treated as pre-existing.

## Why

Every calibration number Sentinel has published comes from the phishing_pot
corpus, scored offline. None comes from the mail it actually monitors. The
auth-alignment finding (`docs/findings/auth-alignment.md`, commit `8a66405`)
rests on five records identified as phishing by reading them individually and
writing conclusions into a markdown file. The labels exist as prose, not as
data — there is no way to ask "how many labelled records are there" or "how
often does the system's verdict match a human's," because nothing stores the
human's verdict at all.

This story makes that judgement storable and queryable. It does not make it
authoritative, comprehensive, or connected to anything that scores mail.

## D1. Labels live in separate storage, not inside evidence.db

The evidence record is what the system concluded at a moment in time. Records
carry tamper-evidence hashes, and mutating them after the fact is exactly what
those hashes exist to detect. A label is a human disagreeing later — it
belongs somewhere that cannot mutate that record even by accident, structurally,
not just by convention.

Follows `health_state.json`'s precedent (Story 8.1): a small JSON file, sibling
of `evidence.db`, atomically written (temp file in the same directory, then
`Path.replace()` — the same chain as `store.py`'s `persist_evidence_record`
and `eval.py`'s `save_calibration_model`, not a new pattern).

Two deliberate deviations from that precedent, each reported per D1's own
instruction rather than silently chosen:

**The note field is encrypted; health_state.json is entirely plaintext.**
`health.py`'s own docstring justifies plaintext specifically because that file
"holds only a timestamp and a boolean, nothing about email content." A label's
free-text note is the opposite by design — AC1 requires it, and a human
writing "this one had a fake DocuSign link" is exactly the kind of
content-adjacent commentary `evidence.db`'s own encryption (and its explicit
choice to never persist raw content at all, FR21) exists to keep off disk in
the clear. `message_hash`/`label`/`timestamp` stay plaintext (none is
sensitive), and the note is Fernet-encrypted under the same key `evidence.db`
already uses — introducing a second key for a smaller, related data domain
would be unwarranted complexity for a single-operator personal tool.
Encryption reuses `store.py`'s own key-validation logic (`require_fernet`,
made public for this reuse — see below) rather than duplicating it.

**`save_label` raises on failure; `save_health_state` never does.** Notes for
dev asked this to be decided deliberately, not defaulted. `save_health_state`'s
silent-degrade-on-failure is correct for its own case: nothing is synchronously
waiting on a background heartbeat write, and a missed write just means the next
poll cycle tries again. A label is different — a human clicks a button and
watches for a result. Silently dropping a failed write would be worse than an
error, because there would be nothing to prompt a retry; the human would
believe it worked. `save_label` raises, and the route handler that calls it
catches the exception and renders an explicit failure page rather than
redirecting as if the save succeeded.

**A third, smaller deviation, also load-bearing:** `save_label` refuses to
write over an existing `labels.json` it cannot parse, rather than treating a
corrupt file as empty and silently overwriting it with a fresh file containing
only the one new label. `load_labels` (the read path) is fine to degrade a
corrupt file to "no labels" — nothing is lost, a fix-and-retry is always
possible. A *write* that "succeeds" by replacing a file it never actually read
is not recoverable the same way.

### Fernet key handling: a new public function in store.py, not a new import path

Encrypting the note requires a `Fernet` object, but `src/sentinel/web/`'s
existing structural test (`test_web_imports_no_direct_db_or_crypto_access`,
Story 10.1) bans `cryptography.fernet` imports anywhere under `web/`. Rather
than weakening that boundary, `store.py`'s existing private key-validation
helper (`_require_fernet`) was renamed to a public `require_fernet` — the only
Fernet-key validation/construction logic in the codebase, now reused as-is by
`sentinel.web.labels`. This does not reintroduce the read-path-drift risk the
original boundary protects against: `labels.py` never touches `evidence_records`
at all (see AC4 below), it only needed a Fernet object, which is what that
function's job already was. All existing call sites in `store.py` and two
tests were updated to the new name; behavior is unchanged (confirmed against
the full pre-existing test suite before touching anything else).

## D2. Recorded and queryable in this epic; no evaluation harness integration

A corpus of self-labelled personal mail is small (currently five confirmed-
phishing records against roughly eight hundred Benign — see AC6 below),
unbalanced, and labelled by one person with a stake in the outcome. Mixing it
into the calibration harness without care would make metrics mean less, not
more. That integration is a separate, later, deliberate decision — not a
natural extension of this story.

## D3. No Gmail write scope

`gmail.readonly` stays. Labelling never touches Gmail at all — it reads
`evidence.db` (via the existing store.py functions the list/detail routes
already use) and reads/writes `labels.json` only. The two existing tests that
hardcode the `gmail.readonly` scope string are untouched, and nothing in this
story's diff comes near `ingest.py`/`gmail_oauth.py`.

## D4 (dashboard-design.md) revisited: this is the first write action

Two separate things are worth distinguishing here, since the story's own
framing of D4 slightly conflates them.

D4 itself ("no authentication in v1") reasons from D3: loopback-only with no
other local users means auth would be theatre. That reasoning is genuinely
unaffected by this story — still loopback-only, still single-operator, per
AC8. D4 holds on its own terms.

The thing this story actually changes is separate and stated explicitly
elsewhere in `dashboard-design.md`: *"Sentinel's stated boundary is that it
flags and reports but never acts. A dashboard that can act would violate
that."* Labelling is the first write action this dashboard has ever had. It is
deliberately, narrowly scoped so it does not cross that boundary in the sense
that mattered when it was written: it sends no email, moves no mail, deletes
nothing, and — critically — never changes a verdict, adjusts a weight, or
otherwise feeds back into scoring (see Out of scope). It records a human's own
read of a message they are already looking at, in a file the triage pipeline
itself never reads. "Acts" in the sense the boundary was protecting against
means *acts on the world the system is supposed to be monitoring* — sends
mail, remediates, changes what gets flagged. Annotating your own dashboard
with your own opinion is a different kind of thing, and D3/D4's loopback-only,
no-auth reasoning was never contingent on the dashboard being purely
read-only — it was contingent on there being no other local user and no
network exposure, both still true.

Worth naming honestly rather than not: a write endpoint, even a narrow one,
is a larger security surface than zero write endpoints. The mitigations are
the same ones D3/D4 already rely on (loopback-only binding, no other local
users) plus one specific to this endpoint: a malicious webpage the operator
visits in their own browser could, in principle, script a cross-origin POST to
this endpoint through an active SSH tunnel — there is no session/cookie for
CSRF protection to key off, since there is no auth at all. This is judged
low-severity and accepted, not fixed, for two reasons: the target message_hash
is an unguessable SHA-256 with no way for a remote page to know one, and even
a successful forged label has zero functional consequence — it cannot change
a verdict, adjust a weight, or trigger any downstream behavior, only pollute
one entry in a file nothing but this dashboard ever reads. Do not add
authentication or CSRF tokens for this story; if D3 changes (a bind beyond
loopback), D4 says auth must come in the same story, and this reasoning would
need revisiting then, not before.

## Sampling bias (Notes for dev)

Records that produce alerts get reviewed. Quiet Benign records do not. That is
precisely the bias that hid the auth-alignment finding in Epic 4 — examining
what got flagged rather than what did not. The `tsukuba` record scored 0.000,
never alerted, and was genuine phishing. A labelling workflow that only ever
touches alerted messages would rebuild that exact blind spot inside the ground
truth itself, just with a different name.

This story does not solve that — there is no forcing function that makes
anyone label a quiet Benign record. What it does is make reaching one
*possible and deliberate*: the label filter (AC5) includes "Unlabelled" as a
first-class option alongside the three real label values, specifically so a
reviewer can filter to `?verdict=Benign&label=unlabelled` and go looking for
exactly the kind of record the alerting-driven workflow would otherwise never
surface. The tools exist; using them is a discipline, not something this
story can enforce.

## AC6: the numbers this makes possible

Current store distribution (2026-08-21): roughly 900 records, 5 Malicious, 23
CoverageGap, ~34 Deferred, the remainder Benign. The labels vs. verdict
cross-tab this story adds sits directly against that imbalance — five
confirmed-phishing records against roughly 800 Benign is exactly the
unbalanced-corpus problem D2 warns about, and is the reason harness
integration is deferred rather than included here rather than an argument
against building the cross-tab at all. The cross-tab's job is to make that
imbalance visible as a number, not to fix it.

## Minimum viable scope

- Label storage: `labels.json`, sibling of `evidence.db`, holding
  `message_hash -> {label, timestamp, note}` (D1).
- Three label values: `confirmed-phishing`, `confirmed-benign`, `unclear`
  (AC2). The third is deliberate — forcing a binary on ambiguous mail
  produces bad ground truth, the same reasoning behind the system's own
  Deferred verdict.
- A set/change control on the detail view only (AC3). Not the list view, not
  the alert email (see Out of scope).
- Labels visible and filterable on the list view, combinable with the
  existing verdict filter (AC5).
- A labels-by-verdict cross-tab on the list view (AC6).

## Out of scope

Evaluation harness integration (D2). Any Gmail write action (D3). Multi-user
labelling or attribution — there is one operator. Changing verdicts or
adjusting weights from labels — a label is data collection, not feedback into
scoring; that is a distinct, larger, and not-yet-made decision. Labelling from
the alert email — a clickable action link in an email is a request-forgery
surface and a phishing-shaped pattern, precisely backwards for a product that
exists to warn about that pattern. The alert links to the detail view; the
control lives there and only there. Backfilling the five records already
identified in `docs/findings/auth-alignment.md` — tracked as a manual,
explicitly-noted follow-up (see that document's own artifacts section once
entered), not part of this story's automated scope.

## AC10: Manual Verification on the Pi

1. SSH in with a local port forward (per `dashboard-design.md`, D3):
   ```
   ssh -L 8000:localhost:8000 jcapreol@<pi-ip>
   ```
2. Start the dashboard with the canonical entrypoint (Story 10.2):
   ```
   cd ~/sentinel && python -m sentinel.web.main
   ```
3. From your laptop, open `http://localhost:8000/verdicts`. Confirm:
   - Every row shows a Label column; unlabelled records show a plain
     "Unlabelled" placeholder, not a colored badge and not a blank cell.
   - The "Labels vs. Verdict" cross-tab above the filter links renders with
     real counts, all zero until the first label is set.
   - The label filter row (`All | confirmed-phishing | confirmed-benign |
     unclear | Unlabelled`) is present alongside the existing verdict filter.
4. Click into a record's detail view. Confirm the label form renders (a
   dropdown with the three values, a note textarea, a "Set label" button).
   Set a label with a note containing a `<script>` tag as a deliberate check
   — confirm it renders back as inert text, not a live script, when the page
   reloads.
5. Confirm the button now reads "Change label," the dropdown is pre-selected
   to what you just set, and the note textarea is pre-filled.
6. Reload the list view. Confirm the record now shows the new label badge,
   the cross-tab count moved by one in the correct cell, and filtering by
   that label finds the record while filtering by "Unlabelled" no longer
   does.
7. Confirm `sentinel-triage --view` (the CLI) and the evidence record's own
   verdict are completely unaffected by the label you just set — labelling
   touches only `labels.json`, never `evidence.db`.
8. Confirm the server is still unreachable from another machine on the LAN
   directly (only through the tunnel), matching Story 10.1's own AC8
   verification.

## Risks

- The write-surface tradeoff discussed under D4 above. Accepted, not fixed,
  scoped narrowly.
- Note-field encryption depends on `SENTINEL_EVIDENCE_KEY` being present and
  unchanged. If the key ever rotates, existing notes become unreadable
  (`load_labels` degrades this per-entry to a placeholder, keeping the label
  and timestamp — see `labels.py`'s own docstring) but are not recoverable
  without the original key. No key-rotation tooling exists for this or for
  `evidence.db` itself; this story does not add any.
- Sampling bias (above) is named, not solved. A future story could add
  something more forceful (e.g. a periodic prompt to label a random
  unlabelled Benign record) if the "Unlabelled" filter alone proves
  insufficient in practice.
