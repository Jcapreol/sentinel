"""Provider-agnostic mail source interface (Story 7.1).

Everything in this module is deliberately free of any Gmail-specific
knowledge -- no ``googleapiclient`` import, no HTTP status codes, no
Gmail API call shapes. ``sentinel.triage.ingest.GmailMailSource`` is the
one implementation that exists today; a future second provider (e.g. a
Graph-API-backed source) would implement the same ``MailSource`` Protocol
and raise the same ``MessageUnavailable`` exception, with zero changes
required anywhere downstream (``worker.py``, scoring, evidence store,
alerting).
"""

from typing import Protocol


class FetchFailed:
    """Sentinel: a header fetch failed for a message.

    Structurally distinct from ``None`` (a genuinely absent Authentication-Results
    header) — headers.py treats a missing header as real evidence with a non-zero
    presence weight. Conflating a fetch error with "no header" would score a
    transient failure as if it were data actually collected. Callers must route
    this to a deferred/coverage-gap outcome, never treat it as evidence (see
    triage/worker.py's process_message).
    """


class MessageUnavailable(Exception):
    """Raised by a MailSource implementation when a message cannot be fetched
    because it no longer exists (e.g. Gmail's HttpError 404 "Requested entity
    was not found" -- the message was deleted or moved out of the mailbox
    between the enumeration call and the fetch call).

    Deliberately narrower than "any fetch failure": a transient error (a
    timeout, a 5xx after retries are exhausted, a malformed response) is a
    different situation -- the message likely still exists, the failure is
    just this attempt's problem -- and a MailSource implementation should let
    those propagate as whatever exception type is natural for it, not wrap
    them as MessageUnavailable. worker.py's coverage-gap construction
    (run_poll_cycle) still catches failures broadly (not narrowed to this
    type specifically) -- see its own comment for why -- but this type exists
    so that a caller who DOES want to distinguish "definitely gone" from "may
    still be fetchable on retry" can, without ever referencing a
    provider-specific exception or HTTP status code.
    """


class MailSource(Protocol):
    """The boundary between the triage pipeline and a specific mail
    provider. Every method here is the minimal, real surface Story 7.1 found
    by tracing worker.py's actual Gmail coupling -- not an idealized
    3-operation shape imposed on top of it. See the Story 7.1 write-up for
    why this ended up at 4 operations (list/fetch-raw/fetch-auth-header/
    fetch-headers-by-name) rather than the originally proposed 3: the
    primary auth-header fetch and the self-alert-fallback headers-by-name
    fetch are genuinely different operations (different failure contracts --
    one raises on failure, the other never does -- and the auth-header fetch
    needs ALL values for a repeated header name for trust-selection, which a
    single-value-per-name fetch would silently break)."""

    def list_new_messages(self, checkpoint: str | None) -> tuple[list[str], str]:
        """Returns (message_ids, new_checkpoint). An empty checkpoint (None)
        means "first call ever" -- implementations should establish a
        baseline and return zero messages, exactly like Gmail's own
        first-call semantics (see poll_new_messages)."""
        ...

    def fetch_raw_message(self, message_id: str) -> bytes:
        """Returns the raw RFC 822 message bytes. Raises MessageUnavailable
        if the message is definitively gone; may raise other exceptions for
        any other failure (network, transient provider error, etc.) --
        callers that only need "did this work" should catch broadly, not
        just MessageUnavailable (see run_poll_cycle)."""
        ...

    def fetch_auth_results_header(self, message_id: str) -> str | None | FetchFailed:
        """Returns the trusted Authentication-Results header value for this
        message (None if genuinely absent), or a FetchFailed sentinel if the
        fetch itself could not be completed for any reason. Never raises --
        the FetchFailed/None distinction is the whole point: a fetch error
        must never be scored as though it were real evidence of a missing
        header."""
        ...

    def fetch_headers_by_name(
        self, message_id: str, header_names: list[str]
    ) -> dict[str, str | None]:
        """Best-effort metadata-only fetch of the named headers, without
        requiring the raw message content. Never raises -- returns every
        requested name mapped to None on any failure (see
        ingest.fetch_headers_by_name's own docstring for why this
        graceful-degradation contract matters to its one caller, the Story
        5.2.1 self-alert fallback check)."""
        ...
