"""Personal Gmail OAuth ("installed app") credential handling.

Extracted from harvest_own_inbox.py's existing, working OAuth flow so that
triage/ingest.py's oauth auth mode (see build_gmail_service,
GMAIL_AUTH_MODE=oauth) and the harvest script share the exact same token
acquisition/refresh/storage code -- no separate reimplementation of either
side of the token dance. harvest_own_inbox.py now imports get_credentials
from here instead of defining its own copy.

[Story 8.2] Both callers of get_credentials share the same fail-fast
guarantees added here: when there's no usable cached token, the interactive
consent flow (flow.run_local_server) is only ever entered if a TTY is
present, and is always bounded by a timeout even then. Confirmed safe for
harvest_own_inbox.py by an exhaustive repo-wide search (no CI workflow,
script, or subprocess call invokes it non-interactively anywhere in this
repo) -- see the Story 8.2 story file for the full verification. Without
this, a missing/unusable token under an unattended invocation (cron firing
sentinel-triage --once, the live path this module was built for) blocks
forever waiting for a browser redirect that will never arrive -- see the
2026-08-20 AC9 investigation that found this.
"""

import sys
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow, WSGITimeoutError

# Read-only. Nothing that imports this ever modifies, sends, or deletes mail.
GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
_SCOPES = [GMAIL_READONLY_SCOPE]

# [Story 8.2] A safety bound, not a tuning knob -- deliberately NOT a Config
# field. Five minutes is comfortable for a human doing the flow unhurried
# (browser, Google sign-in, possibly 2FA, an unverified-app warning to click
# through) while still bounded enough that an abandoned flow does not sit
# forever. Only reachable when a TTY was present when the flow started (see
# the isatty() check below) -- an unattended invocation never reaches this
# at all.
_OAUTH_CONSENT_TIMEOUT_SECONDS = 300


def get_credentials(client_secret_path: Path, token_path: Path) -> Credentials:
    """Standard Google OAuth "installed app" flow: opens a browser for
    one-time consent, caches the resulting token so future runs don't
    need to re-prompt. This is the normal, documented way for a script to
    read a PERSONAL Gmail account (distinct from the service-account +
    domain-wide-delegation flow ingest.py's service_account auth mode
    uses, which requires a Google Workspace admin -- not available for a
    personal @gmail.com account).
    Raises FileNotFoundError if no cached token exists and client_secret_path
    is also missing -- a real exception (not sys.exit) so any caller,
    including a library caller like ingest.py's oauth auth mode, can catch
    it uniformly alongside every other credential-loading failure rather
    than needing a separate SystemExit handler.

    [Story 8.2] Also raises RuntimeError -- for the same "any caller can
    catch it uniformly" reason -- if the interactive consent flow can't be
    completed: no TTY present (stdin.isatty() is False, e.g. under cron),
    or a TTY was present but the flow was started and never completed
    within _OAUTH_CONSENT_TIMEOUT_SECONDS. Both are real exceptions raised
    from here, not sys.exit -- ingest.py's build_gmail_service already
    wraps every exception from this function into a ConfigError, so no
    change is needed there.
    """
    creds: Credentials | None = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(  # type: ignore[no-untyped-call]
            str(token_path), _SCOPES
        )

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())  # type: ignore[no-untyped-call]
        else:
            if not client_secret_path.exists():
                raise FileNotFoundError(
                    f"Missing OAuth client file at {client_secret_path}. "
                    "See docs/gmail-setup.md's Personal Gmail (OAuth) section."
                )
            # [Story 8.2] Checked BEFORE ever calling run_local_server --
            # under cron (no controlling terminal), stdin.isatty() reliably
            # reads False, and this must fail in milliseconds rather than
            # opening a browser, binding a local server, and blocking
            # forever waiting for a redirect that will never arrive. This
            # is the primary fix; the timeout below is defense in depth for
            # the different case of an attended session that starts the
            # flow and then never completes it.
            if not sys.stdin.isatty():
                raise RuntimeError(
                    "No interactive terminal available to complete OAuth consent, "
                    f"and no valid cached token exists at {token_path!r}. This "
                    "cannot be completed unattended (e.g. under cron). Remedy: run "
                    "this OAuth consent flow interactively on a machine with a "
                    "browser, then copy the resulting token file to this machine's "
                    "configured GMAIL_OAUTH_TOKEN_PATH."
                )
            flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_path), _SCOPES)
            try:
                creds = flow.run_local_server(
                    port=0, timeout_seconds=_OAUTH_CONSENT_TIMEOUT_SECONDS
                )
            except WSGITimeoutError as e:
                raise RuntimeError(
                    f"OAuth consent flow timed out after "
                    f"{_OAUTH_CONSENT_TIMEOUT_SECONDS}s waiting for the browser "
                    "redirect -- the flow was started but never completed. Remedy: "
                    "re-run interactively and complete sign-in and consent within "
                    "the timeout."
                ) from e

        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(creds.to_json())

    return creds
