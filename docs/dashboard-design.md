# Design Doc: Sentinel Web Dashboard

Status: Decisions made. Story 10.1 specced below.

## Why

Sentinel has two interfaces: a CLI table over SSH, and alert emails. Both
assume the reader is Jackson. Every conversation about this project eventually
reaches "can I see it," and the answer today is "watch me type into a
terminal."

The stated positioning is trust and verifiability. "Click a verdict, see
exactly why" is the concrete expression of that, and it currently has no
visible surface.

## What actually exists

    src/sentinel/web/
      __init__.py      0 lines
      demo.py         54 lines   loads demo fixtures by slug
      main.py         39 lines   app setup
      routes.py      139 lines   POST /analyze/stream (SSE, demo fixtures)
                                 GET  /quota
      state.py        25 lines

    257 lines. No static/ directory. No frontend. No evidence store connection.

FastAPI and uvicorn already pinned in requirements.txt and pyproject.toml.

## Decisions

### D1. Primary reader: the stakeholder, not the operator

The CLI already serves the operator well (`--view` with `--verdict` and
`--limit`). What does not exist is anything for a person who has never seen
Sentinel. Build for them.

Consequence: favour one thing at a time over density. A short list and a rich
detail view, not a control panel.

### D2. Read through store.py's existing functions, not direct DB access

The web layer imports the same read path the CLI uses. It does not open
evidence.db itself.

Reasons: decryption logic stays in one place; the CLI and web cannot drift;
and if the web process should later not hold the Fernet key, the boundary
already exists to swap the data source.

### D3. Bind to localhost only. Demos happen over an SSH tunnel.

This overrides the convenience argument deliberately.

This is the first Sentinel component that listens on a network. Everything
before it was outbound-only: it polls Gmail, calls APIs, sends SMTP. Nothing
accepts connections. That is a real change in the threat model.

The deployment is a Pi on a building-managed network with unknown neighbours,
holding decrypted email metadata, built by a solo developer with no external
security review. Binding to the LAN would be the least examined decision in
the project carrying the most risk.

An SSH tunnel is one command on the operator's side and invisible to whoever
is watching a screen share:

    ssh -L 8000:localhost:8000 jcapreol@<pi-ip>

LAN or public exposure is a separate, later decision that must revisit D4.

### D4. No authentication in v1

Follows from D3. Localhost-only with no other local users means auth would be
theatre.

This decision is void the moment D3 changes. Any story that binds to a
non-loopback interface must add auth in the same story, not after.

### D5. Keep demo.py as a distinct route

Already written, and genuinely useful for showing the analysis flow without
waiting for live mail. Keep it.

Constraint: the demo path and the live path must not share rendering logic.
Two renderers that drift are annoying; one renderer serving both real and
fake data is a correctness hazard.

### D6. Page refresh, no live streaming

Mail arrives every few minutes at most. SSE for live verdicts is complexity
without benefit. The existing SSE machinery stays where it is, serving the
demo route.

## Minimum viable scope

Three views. Anything else is v2.

1. Verdict list: timestamp, sender, verdict, confidence. Filterable by
   verdict, mirroring the CLI.
2. Detail view: full evidence list for one record, each finding with its
   weight and direction. This is the whole point of the dashboard.
3. Health indicator: reads data/health_state.json, shows last successful poll
   and whether an alert is active.

## Out of scope for v1

Multi-account views. Any write action at all. Charts. Public exposure.
Authentication (see D4). Live streaming of real verdicts.

The read-only constraint is not only scope control. Sentinel's stated boundary
is that it flags and reports but never acts. A dashboard that can act would
violate that.

## Risks

- Scope creep. Dashboards attract features. Three views is the story.
- Security surface. First listening component. D3 mitigates it; any change to
  D3 reopens it.
- CLI divergence. D2 mitigates it. Watch for it anyway.

---

# Story 10.1: Read-Only Verdict List and Detail View

## Context

See design doc above. This story builds views 1 and 2. The health indicator
(view 3) is a separate story.

## Acceptance Criteria

AC1: A route serving a verdict list, reading through store.py's existing
     read functions. No direct sqlite3 or Fernet usage in src/sentinel/web/.
     A structural test asserts this, mirroring the existing test that bans
     smtplib inside triage/.

AC2: The list shows timestamp, sender, verdict, and confidence, and supports
     filtering by verdict. CoverageGap records render with no confidence
     value, consistent with Story 6.1's model.

AC3: A detail route showing one record's full evidence list: every finding
     with its name, text, weight, and direction. Nothing truncated.

AC4: The app binds to 127.0.0.1 only. A test asserts the default host is
     loopback. If a future config option allows another interface, it does
     not exist yet and must not be added in this story.

AC5: The existing demo route and /quota continue to work unchanged. Live and
     demo paths do not share rendering code.

AC6: Sender values are rendered as text, never as HTML. Email display names
     are attacker-controlled and this is a stored-XSS vector. Include a test
     with a sender containing a script tag.

AC7: Existing test suite passes. mypy --strict and ruff clean.

AC8: Manual verification instructions for the Pi, including the SSH tunnel
     command.

## Out of scope

Health indicator view. Any write action. Authentication. Any binding other
than loopback. Styling beyond what makes the evidence list readable.

## Notes for dev

- The evidence store holds decrypted email metadata. Treat every field from a
  record as untrusted input at render time, not just the obvious ones.
- Story 6.1's CoverageGap records have sender: null and no confidence. The
  list must not crash on them. There are 20+ in the live store.
- Do not add a config option for the bind address in this story. When that is
  wanted it comes with authentication, in the same story.
- Commit and push when done.
