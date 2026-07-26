"""Gmail mailbox ingestion and polling.

Uses a service account with domain-wide delegation, scoped to
``gmail.readonly`` and delegated to exactly one monitored mailbox via
``with_subject``. No other mailbox is ever accessed. Establishing the legal
right to monitor the configured mailbox is the customer's responsibility
(see docs/gmail-setup.md).

Checkpoint-before-read, at-least-once delivery (deliberate): ``poll_new_messages``
captures ``current_history_id`` via ``getProfile()`` *before* calling
``history.list()``. Any message that arrives in the gap between those two calls
is included in this cycle's results (since ``history.list()`` reads up to its
own execution time) but the next cycle's ``since_history_id`` is the earlier,
pre-``history.list()`` checkpoint — so that same message is included again next
cycle. This means a message can be triaged more than once. At-least-once is the
correct default for this pipeline (silently dropping a message is worse than
processing it twice). This module itself does not deduplicate across poll
cycles — ``sentinel.triage.store.is_message_processed`` is the primitive the
polling loop calls before running the pipeline for a message, to skip
one already seen.
"""

import base64
import email
import hashlib
import re
import sys
import time
from email.header import decode_header
from email.message import Message
from typing import Any

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from sentinel.config import Config, ConfigError

_GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

# The receiving MTA hostname whose Authentication-Results header this module
# trusts. A message can carry multiple Authentication-Results headers (one per
# relay hop); only the one added by Gmail's own receiving server is authoritative
# for this project's trust boundary (see get_authentication_results_header).
_TRUSTED_AUTHSERV_ID = "mx.google.com"

_MAX_RETRY_ATTEMPTS = 3
_INITIAL_BACKOFF_SECONDS = 1.0


class FetchFailed:
    """Sentinel: a header fetch failed for a message.

    Structurally distinct from ``None`` (a genuinely absent Authentication-Results
    header) — headers.py treats a missing header as real evidence with a non-zero
    presence weight. Conflating a fetch error with "no header" would score a
    transient failure as if it were data actually collected. Callers must route
    this to a deferred/coverage-gap outcome, never treat it as evidence (see
    triage/worker.py's process_message).
    """


def build_gmail_service(config: Config) -> Any:
    if not config.gmail_credentials_path:
        raise ConfigError(
            "Missing required environment variable: GMAIL_SERVICE_ACCOUNT_KEY_PATH"
        )
    if not config.gmail_monitored_mailbox:
        raise ConfigError(
            "Missing required environment variable: GMAIL_MONITORED_MAILBOX"
        )

    try:
        credentials = service_account.Credentials.from_service_account_file(  # type: ignore[no-untyped-call]
            config.gmail_credentials_path,
            scopes=[_GMAIL_READONLY_SCOPE],
        ).with_subject(config.gmail_monitored_mailbox)
    except Exception as e:
        raise ConfigError(
            f"Failed to load Gmail service-account credentials from "
            f"{config.gmail_credentials_path!r}: {e}"
        ) from e

    return build("gmail", "v1", credentials=credentials, cache_discovery=False)


def _is_retryable_status(status: int | None) -> bool:
    return status == 429 or (status is not None and 500 <= status < 600)


def _execute_with_retry(request: Any) -> Any:
    """Executes a Gmail API request, retrying with exponential backoff on
    429/5xx responses (both routine, transient conditions for the Gmail API).
    Any other error — including 401/403 auth failures and 404 — propagates
    immediately; retrying an auth failure wastes time without fixing it, and
    404 has its own recovery semantics handled by the caller."""
    attempt = 0
    while True:
        try:
            return request.execute()
        except HttpError as e:
            status = getattr(getattr(e, "resp", None), "status", None)
            if not _is_retryable_status(status) or attempt >= _MAX_RETRY_ATTEMPTS:
                raise
            backoff = _INITIAL_BACKOFF_SECONDS * (2**attempt)
            print(
                f"[ingest] Gmail API returned {status} — retrying in {backoff:.1f}s "
                f"(attempt {attempt + 1}/{_MAX_RETRY_ATTEMPTS})",
                file=sys.stderr,
            )
            time.sleep(backoff)
            attempt += 1


def poll_new_messages(
    service: Any, mailbox: str, since_history_id: str | None
) -> tuple[list[dict[str, Any]], str]:
    try:
        profile = _execute_with_retry(service.users().getProfile(userId=mailbox))
    except HttpError as e:
        print(
            f"[ingest] getProfile failed for mailbox {mailbox!r}: {e}. Check that "
            "gmail.readonly domain-wide delegation is configured for this mailbox.",
            file=sys.stderr,
        )
        raise
    current_history_id = str(profile["historyId"])

    if since_history_id is None:
        return [], current_history_id

    messages: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    page_token: str | None = None
    while True:
        try:
            response = _execute_with_retry(
                service.users().history().list(
                    userId=mailbox,
                    startHistoryId=since_history_id,
                    historyTypes=["messageAdded"],
                    pageToken=page_token,
                )
            )
        except HttpError as e:
            status = getattr(getattr(e, "resp", None), "status", None)
            if status == 404:
                print(
                    f"[ingest] historyId {since_history_id!r} expired (404) — "
                    f"re-baselining to {current_history_id!r}. Messages received "
                    "in the gap may have been missed.",
                    file=sys.stderr,
                )
                return [], current_history_id
            raise

        for record in response.get("history", []):
            for added in record.get("messagesAdded", []):
                message = added["message"]
                message_id = message["id"]
                if message_id in seen_ids:
                    continue
                seen_ids.add(message_id)
                messages.append(dict(message))
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    return messages, current_history_id


def _select_trusted_auth_header(candidate_values: list[str]) -> str | None:
    """A message can carry more than one Authentication-Results header (one per
    relay hop). Prepend order alone isn't sufficient to trust a header — a
    crafted header could be positioned to sort first. Instead, match each
    header's authserv-id (the token before the first ';') against the
    monitored mailbox's own trusted receiving MTA, and only ever return a
    header that matches. Among multiple genuinely-trusted headers, the first
    one wins (each hop prepends its own, so the first trusted header is the
    most recent hop's verdict). Shared by both the Gmail-API path
    (get_authentication_results_header) and the raw-.eml-file path
    (extract_auth_results_header_from_eml, Story 3.1) -- this trust-selection
    logic must not be duplicated.
    """
    for value in candidate_values:
        authserv_id = value.split(";", 1)[0].strip().lower()
        if authserv_id == _TRUSTED_AUTHSERV_ID:
            return value
    return None


def get_authentication_results_header(
    service: Any, mailbox: str, message_id: str
) -> str | None:
    message = _execute_with_retry(
        service.users().messages().get(
            userId=mailbox,
            id=message_id,
            format="metadata",
            metadataHeaders=["Authentication-Results"],
        )
    )
    candidate_values = [
        str(header["value"])
        for header in message.get("payload", {}).get("headers", [])
        if header.get("name", "").lower() == "authentication-results"
        and header.get("value") is not None
    ]
    return _select_trusted_auth_header(candidate_values)


def extract_auth_results_header_from_eml(raw_bytes: bytes) -> str | None:
    """Pure function, no network call. Extracts the trusted Authentication-Results
    header value from a raw .eml file's bytes (e.g. an eval corpus sample),
    reusing the exact same trust-selection logic as the live Gmail-API path
    (get_authentication_results_header) via _select_trusted_auth_header --
    this security-relevant selection logic is not duplicated. Never raises --
    returns None on any parse failure or absence, matching this module's
    "pure function, best-effort" discipline (extract_sender_and_content_hash,
    extract_email_content).
    """
    try:
        parsed = email.message_from_bytes(raw_bytes)
        candidate_values = [str(v) for v in parsed.get_all("Authentication-Results", [])]
        return _select_trusted_auth_header(candidate_values)
    except Exception:
        return None


def fetch_headers_for_messages(
    service: Any, mailbox: str, messages: list[dict[str, Any]]
) -> dict[str, str | None | FetchFailed]:
    results: dict[str, str | None | FetchFailed] = {}
    for message in messages:
        message_id = message.get("id")
        if message_id is None:
            print(
                "[ingest] Skipping message with no 'id' field in batch",
                file=sys.stderr,
            )
            continue
        try:
            results[message_id] = get_authentication_results_header(
                service, mailbox, message_id
            )
        except Exception as e:
            print(
                f"[ingest] Failed to fetch headers for message {message_id!r}: "
                f"{type(e).__name__}: {e}",
                file=sys.stderr,
            )
            results[message_id] = FetchFailed()
    return results


def fetch_raw_message_bytes(service: Any, mailbox: str, message_id: str) -> bytes:
    """Fetches the full raw RFC 822 message content, decoded from Gmail's
    base64url encoding. A materially broader read than the header-only
    metadata fetches used elsewhere in this module — used only transiently to
    derive a sender header and a tamper-evident content hash for the
    persisted record (see sentinel.triage.store). The raw bytes returned by
    this function must never be logged, and any caller must discard them
    immediately after deriving what it needs — never write them to disk,
    never include them in an exception message or print statement.
    """
    response = _execute_with_retry(
        service.users().messages().get(userId=mailbox, id=message_id, format="raw")
    )
    raw = response["raw"]
    raw += "=" * (-len(raw) % 4)  # Gmail's base64url payload can arrive unpadded
    return base64.urlsafe_b64decode(raw)


def extract_sender_and_content_hash(raw_bytes: bytes) -> tuple[str | None, str]:
    """Pure function, no network call. Parses the From header and computes a
    SHA-256 content hash from raw message bytes already fetched by
    fetch_raw_message_bytes."""
    parsed = email.message_from_bytes(raw_bytes)
    sender = parsed.get("From")
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    return sender, content_hash


_TAG_PATTERN = re.compile(r"<[^>]+>")
_HREF_PATTERN = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _decode_subject(raw_subject: str) -> str:
    """Decodes RFC 2047 MIME-encoded-word Subject headers (e.g.
    '=?UTF-8?B?...?='). email.message_from_bytes's default Compat32 policy
    returns these verbatim otherwise, hiding urgency/homoglyph phishing
    language deliberately placed in the subject line."""
    try:
        pieces = decode_header(raw_subject)
    except Exception:
        return raw_subject
    decoded: list[str] = []
    for text, charset in pieces:
        if isinstance(text, bytes):
            try:
                decoded.append(text.decode(charset or "utf-8", errors="replace"))
            except LookupError:
                decoded.append(text.decode("utf-8", errors="replace"))
        else:
            decoded.append(text)
    return "".join(decoded)


def _strip_html(html: str) -> str:
    """Strips tag markup but preserves hyperlink targets (href values) as
    trailing plain text. A blanket tag-removal regex would otherwise delete
    an <a href="..."> URL along with the tag itself -- for an HTML-only
    phishing email using generic anchor text ("click here"), that silently
    destroys the one thing CipherAgent's IOC extraction depends on."""
    hrefs = _HREF_PATTERN.findall(html)
    stripped = _TAG_PATTERN.sub(" ", html)
    if hrefs:
        stripped += "\n" + "\n".join(hrefs)
    return stripped


def _extract_body(parsed: Message) -> str:
    """Best-effort body extraction, deliberately isolated from Subject
    extraction (see extract_email_content) so a body-parsing failure doesn't
    discard an already-obtained Subject."""
    text_plain: str | None = None
    text_html: str | None = None
    if parsed.is_multipart():
        for part in parsed.walk():
            if part.get_content_disposition() == "attachment":
                continue
            content_type = part.get_content_type()
            if content_type == "text/plain" and text_plain is None:
                text_plain = _decode_part(part)
            elif content_type == "text/html" and text_html is None:
                text_html = _decode_part(part)
    elif parsed.get_content_type() == "text/html":
        text_html = _decode_part(parsed)
    elif parsed.get_content_maintype() == "text":
        text_plain = _decode_part(parsed)
    # else: non-text single-part body (e.g. application/pdf, image/png) --
    # deliberately not decoded as text; nothing extractable from it.

    if text_plain:
        return text_plain
    if text_html:
        return _strip_html(text_html)
    return ""


def extract_email_content(raw_bytes: bytes) -> str:
    """Pure function, no network call. Extracts a best-effort analyzable text
    blob (Subject + body) from raw message bytes already fetched by
    fetch_raw_message_bytes, for WatchmanAgent/CipherAgent to analyze.

    Same discipline as fetch_raw_message_bytes: the returned text must never be
    logged or persisted directly -- it is only ever passed transiently into
    WatchmanAgent.analyze()/CipherAgent.analyze(), whose own outputs (LLM
    findings, IOC-derived strings) are what eventually get persisted, never
    this raw text itself. Never raises -- degrades to the best-effort text it
    could extract (possibly empty Subject and/or body) rather than propagate a
    parse failure into run_poll_cycle's per-message loop. Subject and body
    extraction are independently guarded so a failure in one does not discard
    an already-obtained result from the other.
    """
    try:
        parsed = email.message_from_bytes(raw_bytes)
    except Exception:
        return "Subject: \n\n"

    try:
        subject = _decode_subject(parsed.get("Subject", ""))
    except Exception:
        subject = ""

    try:
        body = _extract_body(parsed)
    except Exception:
        body = ""

    return f"Subject: {subject}\n\n{body}"
