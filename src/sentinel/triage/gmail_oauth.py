"""Personal Gmail OAuth ("installed app") credential handling.

Extracted from harvest_own_inbox.py's existing, working OAuth flow so that
triage/ingest.py's oauth auth mode (see build_gmail_service,
GMAIL_AUTH_MODE=oauth) and the harvest script share the exact same token
acquisition/refresh/storage code -- no separate reimplementation of either
side of the token dance. harvest_own_inbox.py now imports get_credentials
from here instead of defining its own copy.
"""

from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# Read-only. Nothing that imports this ever modifies, sends, or deletes mail.
GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
_SCOPES = [GMAIL_READONLY_SCOPE]


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
            flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_path), _SCOPES)
            creds = flow.run_local_server(port=0)

        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(creds.to_json())

    return creds
