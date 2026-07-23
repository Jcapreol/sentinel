# Gmail Mailbox Setup

Sentinel's autonomous phishing triage ingests mail from a single Google
Workspace mailbox via a service account with domain-wide delegation, scoped
to read-only access and delegated to exactly one mailbox. This document
covers how to provision that access.

## Legal boundary (customer responsibility)

> **Legal boundary (customer responsibility):** Establishing the legal right
> to monitor the connected mailbox — employer policy, jurisdictional
> requirements, employee notice/consent — is the customer organization's
> responsibility, not Sentinel's. Sentinel provides the tool; the customer
> warrants they have the right to monitor the mailbox they connect. This
> boundary must be stated explicitly in customer-facing documentation
> (README, onboarding docs, and any terms of service), not left implicit.

Do not connect a mailbox until your organization has confirmed it has the
legal right to monitor it.

## 1. Create a GCP service account

1. In the [Google Cloud Console](https://console.cloud.google.com/), select
   (or create) the project that will own this service account.
2. Navigate to **IAM & Admin → Service Accounts → Create Service Account**.
3. Give it a descriptive name (e.g. `sentinel-triage`). No project-level
   IAM roles are required — this service account only needs Gmail API
   access, granted in the next steps.
4. Open the new service account, go to the **Keys** tab, and create a new
   JSON key. Download it.
5. Note the service account's **Client ID** (also on the service account's
   detail page) — you'll need it for domain-wide delegation scoping below.

## 2. Enable domain-wide delegation

1. On the service account's detail page, under **Advanced settings**, enable
   **Domain-wide delegation**.
2. In the [Google Workspace Admin console](https://admin.google.com/), go to
   **Security → API Controls → Domain-wide Delegation**.
3. Click **Add new**, and enter:
   - **Client ID**: the service account's Client ID from step 1.5 above
   - **OAuth scopes**: `https://www.googleapis.com/auth/gmail.readonly`

   Add only this scope. Do not add any broader Gmail scope
   (`gmail.modify`, `gmail.metadata`, etc.) — Sentinel never needs to
   modify, send, or delete mail.

## 3. Delegate to exactly one mailbox

Domain-wide delegation grants the service account the *ability* to
impersonate any mailbox in the domain via `gmail.readonly` — but Sentinel
only ever impersonates the single mailbox configured in
`GMAIL_MONITORED_MAILBOX` (see below). It calls
`credentials.with_subject(mailbox)` with that one address; no other mailbox
is ever accessed by Sentinel's code.

Choose (or create) a dedicated mailbox for triage — e.g.
`soc-triage@yourcompany.com` — rather than an individual's personal inbox.

## 4. Store the key and configure environment variables

Place the downloaded JSON key at:

```
secrets/gmail-service-account.json
```

This path is already covered by the repository's `.gitignore`
(`secrets/`) — it will never be committed. Do not store the key anywhere
outside `secrets/`.

Set these environment variables (e.g. in `.env`):

| Variable | Required | Description |
|---|---|---|
| `GMAIL_SERVICE_ACCOUNT_KEY_PATH` | Yes | Path to the service-account JSON key, e.g. `secrets/gmail-service-account.json` |
| `GMAIL_MONITORED_MAILBOX` | Yes | The single mailbox address to monitor, e.g. `soc-triage@yourcompany.com` |
| `SENTINEL_POLL_INTERVAL` | No | Poll interval in seconds. Defaults to `300` (5 minutes) if unset. |

If either `GMAIL_SERVICE_ACCOUNT_KEY_PATH` or `GMAIL_MONITORED_MAILBOX` is
missing or invalid, Sentinel fails fast with a clear error before
attempting any poll — it will not start in a partially-configured state.

## 5. Running continuously

Running `sentinel-triage` with no flags is the default mode: it polls every
`SENTINEL_POLL_INTERVAL` seconds (default 300 / 5 minutes) until stopped.
Per-message failures (a single malformed or unparseable email) are isolated
automatically and never stop the loop.

A **persistent** failure — most commonly revoked or expired Gmail
credentials — is different: rather than silently retrying a broken cycle
forever, Sentinel logs it prominently to stderr and exits non-zero.
Restart-on-crash is deliberately left to your process supervisor rather than
built into Sentinel itself — a `systemd` unit is the reference pattern:

```ini
# /etc/systemd/system/sentinel-triage.service
[Unit]
Description=Sentinel phishing triage worker
After=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory=/opt/sentinel
EnvironmentFile=/opt/sentinel/.env
ExecStart=/opt/sentinel/.venv/bin/sentinel-triage
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

`systemctl stop sentinel-triage` sends SIGTERM by default; Sentinel handles
it explicitly (alongside Ctrl+C/SIGINT) to shut down cleanly rather than
being killed mid-cycle.

With `Restart=on-failure` and `RestartSec=30`, a transient issue (e.g. a
brief credential propagation delay) recovers automatically. `StartLimitBurst=5`
within `StartLimitIntervalSec=600` caps this at 5 restart attempts per
10-minute window — without it, a *genuinely* broken credential would hot-loop
forever, restarting every 30 seconds and hammering the Gmail API indefinitely.
Once the burst limit is hit, systemd marks the unit `failed` and stops
retrying — visible via `systemctl status sentinel-triage` /
`journalctl -u sentinel-triage` — until an operator fixes the root cause and
runs `systemctl reset-failed sentinel-triage` followed by `systemctl start`.

## Notes

- The first poll after startup establishes a baseline and does not
  retroactively triage existing mail in the mailbox — only messages that
  arrive after Sentinel starts watching are processed. This is intentional:
  it avoids flooding the pipeline with a mailbox's entire backlog on first
  run.
- Sentinel trusts the ingesting mail server's own `Authentication-Results`
  header (SPF/DKIM/DMARC) rather than performing independent
  cryptographic/DNS verification. See `src/sentinel/triage/headers.py` for
  details on this named blind spot.
- **To compute a tamper-evident hash for each stored evidence record,
  Sentinel transiently reads the full raw message content** — headers, body,
  and any attachments — via Gmail's `format="raw"`. This is a materially
  broader read than the header-only fetches used everywhere else in the
  pipeline. The raw content is hashed (SHA-256) and immediately discarded:
  it is never persisted to disk, never logged, and never included in any
  exception message. Only the resulting hash is stored, alongside the
  derived evidence. Your organization's consent/legal documentation (see
  "Legal boundary" above) should account for the fact that Sentinel reads
  full message content transiently, not just headers, even though only a
  hash of it is ever retained.
