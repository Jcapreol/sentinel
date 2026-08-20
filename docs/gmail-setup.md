# Gmail Mailbox Setup

Sentinel's autonomous phishing triage ingests mail from a single Gmail
mailbox. Two auth modes are supported, selected via the `GMAIL_AUTH_MODE`
environment variable:

- **`service_account`** (default) — a Google Workspace service account with
  domain-wide delegation, scoped to read-only access and delegated to
  exactly one mailbox. Requires a Workspace admin. Covered in
  [Google Workspace (service account)](#google-workspace-service-account)
  below.
- **`oauth`** — standard per-user OAuth consent against a personal
  `@gmail.com` inbox. No Workspace admin required. Intended for live/manual
  testing, not production deployment. Covered in
  [Personal Gmail (OAuth)](#personal-gmail-oauth) below.

This document covers acquiring Gmail credentials. For what to do with any
secret once you have it — file permissions, the evidence encryption key's
backup/rotation lifecycle, dependency vulnerability scanning, and other
hardening — see [security.md](security.md).

## Google Workspace (service account)

### Legal boundary (customer responsibility)

> **Legal boundary (customer responsibility):** Establishing the legal right
> to monitor the connected mailbox — employer policy, jurisdictional
> requirements, employee notice/consent — is the customer organization's
> responsibility, not Sentinel's. Sentinel provides the tool; the customer
> warrants they have the right to monitor the mailbox they connect. This
> boundary must be stated explicitly in customer-facing documentation
> (README, onboarding docs, and any terms of service), not left implicit.

Do not connect a mailbox until your organization has confirmed it has the
legal right to monitor it.

### 1. Create a GCP service account

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

### 2. Enable domain-wide delegation

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

### 3. Delegate to exactly one mailbox

Domain-wide delegation grants the service account the *ability* to
impersonate any mailbox in the domain via `gmail.readonly` — but Sentinel
only ever impersonates the single mailbox configured in
`GMAIL_MONITORED_MAILBOX` (see below). It calls
`credentials.with_subject(mailbox)` with that one address; no other mailbox
is ever accessed by Sentinel's code.

Choose (or create) a dedicated mailbox for triage — e.g.
`soc-triage@yourcompany.com` — rather than an individual's personal inbox.

### 4. Store the key and configure environment variables

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

## Personal Gmail (OAuth)

Intended for live/manual end-to-end testing against your own inbox when no
Google Workspace admin account is available (e.g. a bare `@gmail.com`
account, which cannot use domain-wide delegation at all). Not intended for
production deployment — a personal OAuth grant is tied to one individual's
consent, not an organization-managed service account.

This reuses the exact same OAuth client setup, token storage/refresh logic,
and `gmail.readonly` scope as `harvest_own_inbox.py` (the script used to
harvest calibration-corpus data from your own inbox) — both go through
`src/sentinel/triage/gmail_oauth.py`'s `get_credentials`, so if you've
already done the one-time consent for that script, live triage can reuse
the same cached token with zero extra setup.

### 1. One-time setup (skip if already done for `harvest_own_inbox.py`)

1. In the [Google Cloud Console](https://console.cloud.google.com/), select
   (or create) a project.
2. Enable the **Gmail API** for that project (**APIs & Services → Library**).
3. **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
   Application type: **Desktop app**. Download the resulting JSON.
4. Save it as `secrets/oauth-client.json` in this project directory
   (`secrets/` is already gitignored — verify with
   `git check-ignore secrets/oauth-client.json`).

### 2. Configure environment variables

Set these in `.env`:

| Variable | Required | Description |
|---|---|---|
| `GMAIL_AUTH_MODE` | Yes | Set to `oauth` to use this path instead of the default `service_account`. |
| `GMAIL_MONITORED_MAILBOX` | Yes | The Gmail address the OAuth consent belongs to. The literal value `me` also works — it's the Gmail API's own special value for "the authenticated account" and is the simplest choice for a personal inbox. |
| `GMAIL_OAUTH_CLIENT_SECRET_PATH` | No | Path to the downloaded OAuth client JSON. Defaults to `secrets/oauth-client.json`. |
| `GMAIL_OAUTH_TOKEN_PATH` | No | Where the cached token is read from/written to after consent. Defaults to `secrets/oauth-token.json`. |

The first `sentinel-triage` run in `oauth` mode opens a browser for one-time
consent (approve read-only Gmail access for your own account) and caches
the resulting token — subsequent runs reuse it silently, refreshing it
automatically once it expires.

### 3. Insufficient-scope failures fail loudly

A cached token can appear valid (not expired) while never having actually
been granted `gmail.readonly` access — this can happen if an existing
`secrets/oauth-token.json` was produced by a different consent flow, or if
the Google Cloud project's OAuth consent screen isn't configured with the
`gmail.readonly` scope. This isn't detectable locally from the token file
alone — a live Gmail API call is the only reliable signal. Rather than
adding a separate check-only API call (which would repeat, redundantly,
every poll cycle), Sentinel relies on the `getProfile` call polling already
makes at the start of every cycle: a resulting 403 is caught and reported
with a clear, scope-specific message before the underlying error
propagates and the worker exits non-zero — a loud, unambiguous failure,
not a silent continue. If you hit this: delete the cached token file and
re-run to re-authorize, and confirm the Cloud project's OAuth consent
screen includes the `gmail.readonly` scope.

**Re-running to re-authorize must happen from an interactive session** —
`sentinel-triage` opens a browser and waits for you to complete consent, so
it needs an actual terminal to run in. If a scheduled/cron invocation is
still active while the cached token is missing or unusable, pause it first
(comment out the cron entry, or stop the systemd unit) before deleting the
token and re-running by hand; otherwise the *next* unattended run will hit
the same "no cached token" condition. That's expected and safe, not a new
problem: it now fails immediately with a clear error explaining that no
interactive terminal is available, rather than hanging. Re-enable the
scheduled invocation once you've completed consent and confirmed
`secrets/oauth-token.json` (or your configured `GMAIL_OAUTH_TOKEN_PATH`) has
been written.

## Running continuously

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

Before deploying to any Linux host this way, lock down `.env` and
`secrets/*` to owner-only permissions — see
[security.md's File permissions section](security.md#file-permissions-linux--raspberry-pi-deployment).

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
