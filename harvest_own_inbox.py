"""
Harvest a scoped, privacy-conscious sample of YOUR OWN Gmail inbox for the
benign side of Sentinel's calibration corpus.

WHY THIS EXISTS / WHY IT'S DIFFERENT FROM harvest_benign_corpus.py
---------------------------------------------------------------------
Public mailing-list archives turned out to be a dead end for this project:
public-inbox instances (lore.kernel.org, inbox.sourceware.org) are behind
an Anubis anti-bot wall a script can't solve, and Mailman/HyperKitty
archives (mail.python.org) strip exactly the Authentication-Results/
DKIM-Signature headers Sentinel needs, as a normal part of how that
software archives mail.

Your own inbox has neither problem: no bot wall (it's your mailbox, your
consent), and headers arrive exactly as your real mail server saw them --
which is also a closer match to what Sentinel sees in production than any
third-party archive would be.

PRIVACY DESIGN -- read this before running
---------------------------------------------
This script defaults to Gmail's own "Promotions" and "Updates" categories
ONLY -- newsletters, receipts, shipping notifications, account alerts. It
deliberately does NOT touch "Primary" (personal conversations) or "Social".
This is a structural default, not a manual filter -- override it with
--query only if you specifically know what you're doing and accept that
personal correspondence may end up in the saved .eml files.

Even so: skim a handful of the saved files afterward (as you would with
any of this project's harvested data) before treating this as
production-ready calibration data. Nothing here is uploaded or sent
anywhere -- everything stays on your own machine.

WHAT THIS SCRIPT DOES
----------------------
1. One-time OAuth consent (opens your browser, you log into YOUR OWN
   Google account, approve read-only Gmail access). Caches a token
   locally afterward -- no need to re-approve on subsequent runs.
2. Searches your inbox with the given Gmail query (default:
   "category:promotions OR category:updates"). Add date bounds directly in
   the query string itself, e.g. "category:updates after:2025/01/01
   before:2025/06/01" -- there is no separate --after/--before flag.
3. For each matching message, fetches the RAW content and checks whether
   it carries an Authentication-Results header -- the only header
   triage/ingest.py's extract_auth_results_header_from_eml (and the live
   Gmail-API path, get_authentication_results_header) ever reads. A
   message with only ARC-Authentication-Results or only a bare
   DKIM-Signature is NOT saved, even though those are also somewhat
   auth-related -- saving it would produce a corpus file that looks
   identical to an unauthenticated message once run through the actual
   downstream extraction code, corrupting ground truth for exactly the
   signal this corpus exists to validate. (ARC/DKIM presence is still
   logged in the summary for visibility, just not used for the save
   decision.)
4. Saves only messages that pass that check as individual raw .eml files,
   deterministically assigned to a tuning/ or held_out/ subdirectory (see
   OUTPUT CONTRACT below).
5. Prints a summary, including a warning if either split ends up empty.

OUTPUT CONTRACT -- matches sentinel.triage.eval.load_corpus (Story 3.1)
----------------------------------------------------------------------
`--output-dir` (default: benign_corpus_raw/benign) is the CLASS directory
for triage/eval.py's corpus format -- load_corpus reads files ONLY from
`<output-dir>/tuning/*.eml` and `<output-dir>/held_out/*.eml`, never from
`<output-dir>/*.eml` directly. This script writes into the correct
subdirectory itself (an ~80/20 tuning/held_out split, deterministic by
each message's content hash, so re-running is idempotent and stable) --
you do not need to run this twice with different --output-dir values to
populate both splits. A `PROVENANCE.md` documenting this collection
method must also exist directly in `<output-dir>/` (one level above
tuning/held_out) before triage/eval.py's validate_corpus will accept the
corpus -- this script does not generate that file; write it once by hand
(see benign_corpus_raw/benign/PROVENANCE.md for the existing example).
See triage/eval.py's own module docstring for the full corpus contract
(both benign/ and malicious/ classes, PROVENANCE.md requirement, etc.).

ONE-TIME SETUP (before first run)
-------------------------------------
1. Go to https://console.cloud.google.com/, create a project (or reuse
   one if you already have one for Sentinel).
2. Enable the "Gmail API" for that project (APIs & Services > Library).
3. APIs & Services > Credentials > Create Credentials > OAuth client ID.
   Application type: "Desktop app". Download the resulting JSON.
4. Save it as secrets/oauth-client.json in this project directory
   (secrets/ is already gitignored -- verify with:
   git check-ignore secrets/oauth-client.json).

USAGE
-----
    pip install -e .  # installs the sentinel package this script now imports from
    python harvest_own_inbox.py --limit 100

First run opens a browser for one-time consent. Run with --help for all
options.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Any

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from sentinel.triage.gmail_oauth import get_credentials

_DEFAULT_CLIENT_SECRET_PATH = Path("secrets/oauth-client.json")
_DEFAULT_TOKEN_PATH = Path("secrets/oauth-token.json")

# Deliberately excludes Primary and Social -- see module docstring.
_DEFAULT_QUERY = "category:promotions OR category:updates"

# Matches sentinel.triage.eval.load_corpus's directory contract: --output-dir
# is the CLASS directory, and files must land in tuning/ or held_out/
# subdirectories beneath it, never directly in --output-dir itself.
_DEFAULT_OUTPUT_DIR = Path("benign_corpus_raw/benign")

# 1-in-5 (20%) held_out, 80% tuning -- provisional MVP split ratio, matching
# sentinel.triage.eval's own "PROVISIONAL, not calibrated" framing for its
# minimum-sample-count/diversity thresholds. Deterministic by content hash
# (not random) so re-running this script never reassigns an
# already-harvested message to a different split.
_HELD_OUT_MODULUS = 5


def _split_for(content_hash_hex: str) -> str:
    return "held_out" if int(content_hash_hex, 16) % _HELD_OUT_MODULUS == 0 else "tuning"


def build_gmail_service(client_secret_path: Path, token_path: Path) -> Any:
    creds = get_credentials(client_secret_path, token_path)
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def list_message_ids(service: Any, query: str, limit: int) -> list[str]:
    """Paginates through search results up to `limit` message IDs."""
    message_ids: list[str] = []
    page_token: str | None = None
    while len(message_ids) < limit:
        response = (
            service.users()
            .messages()
            .list(
                userId="me",
                q=query,
                maxResults=min(100, limit - len(message_ids)),
                pageToken=page_token,
            )
            .execute()
        )
        message_ids.extend(m["id"] for m in response.get("messages", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return message_ids[:limit]


def fetch_raw_message(service: Any, message_id: str) -> bytes:
    """Fetches the full raw RFC 822 message content for one message ID."""
    import base64

    response = (
        service.users()
        .messages()
        .get(userId="me", id=message_id, format="raw")
        .execute()
    )
    return base64.urlsafe_b64decode(response["raw"])


def has_auth_headers(raw_bytes: bytes) -> tuple[bool, bool, bool]:
    """Parses just enough of the raw message to check for auth headers.
    Returns (has_authentication_results, has_arc, has_dkim) -- but only the
    first determines whether a message gets saved (see harvest()). ARC and
    DKIM presence are tracked for informational stats only: ingest.py's
    extract_auth_results_header_from_eml (and the live Gmail-API path) only
    ever reads Authentication-Results, so a message saved solely for having
    an ARC header or a bare DKIM-Signature would produce
    extract_auth_results_header_from_eml(...) -> None downstream --
    indistinguishable from a message with no authentication data at all.
    """
    import email

    msg = email.message_from_bytes(raw_bytes)
    has_authentication_results = bool(msg.get("Authentication-Results"))
    has_arc = bool(msg.get("ARC-Authentication-Results"))
    has_dkim = bool(msg.get("DKIM-Signature"))
    return has_authentication_results, has_arc, has_dkim


def harvest(
    query: str,
    limit: int,
    output_dir: Path,
    client_secret_path: Path,
    token_path: Path,
) -> None:
    (output_dir / "tuning").mkdir(parents=True, exist_ok=True)
    (output_dir / "held_out").mkdir(parents=True, exist_ok=True)

    print(f"Query: {query!r}")
    print("(Default deliberately excludes Primary/Social -- see script docstring.)")
    print()

    service = build_gmail_service(client_secret_path, token_path)

    print("Searching...")
    message_ids = list_message_ids(service, query, limit)
    print(f"Found {len(message_ids)} matching message(s), fetching raw content...")

    total = 0
    with_auth_results = 0
    with_arc = 0
    with_dkim = 0
    saved = 0
    saved_tuning = 0
    saved_held_out = 0
    failed = 0

    for message_id in message_ids:
        total += 1
        try:
            raw_bytes = fetch_raw_message(service, message_id)
        except HttpError as e:
            print(f"  [warn] Failed to fetch message {message_id!r}: {e}", file=sys.stderr)
            failed += 1
            continue

        auth_results_ok, arc_ok, dkim_ok = has_auth_headers(raw_bytes)
        if auth_results_ok:
            with_auth_results += 1
        if arc_ok:
            with_arc += 1
        if dkim_ok:
            with_dkim += 1

        # Only Authentication-Results actually determines save eligibility --
        # see has_auth_headers's docstring for why ARC/DKIM alone don't count.
        if not auth_results_ok:
            continue

        # Full 64-hex-char digest, not truncated -- a truncated prefix used
        # for both the on-disk filename and split assignment risks two
        # distinct messages silently overwriting each other on collision.
        content_hash = hashlib.sha256(raw_bytes).hexdigest()
        split = _split_for(content_hash)
        out_path = output_dir / split / f"own-inbox-{content_hash}.eml"
        out_path.write_bytes(raw_bytes)
        saved += 1
        if split == "held_out":
            saved_held_out += 1
        else:
            saved_tuning += 1

        if total % 20 == 0:
            print(f"  ...{total}/{len(message_ids)} processed, {saved} saved so far")

    print()
    print("=== Harvest summary ===")
    print(f"Messages examined:     {total}")
    print(f"Fetch failures:        {failed}")
    print(f"With Authentication-Results: {with_auth_results}")
    print(f"With ARC-Authentication-Results (not saved for this alone): {with_arc}")
    print(f"With DKIM-Signature (not saved for this alone): {with_dkim}")
    print(f"Saved (Authentication-Results-intact): {saved} (tuning: {saved_tuning}, held_out: {saved_held_out})")
    print(f"Output directory:      {output_dir.resolve()}")

    total_tuning = len(list((output_dir / "tuning").glob("*.eml")))
    total_held_out = len(list((output_dir / "held_out").glob("*.eml")))
    print(f"Total now in tuning/ (all runs combined):   {total_tuning}")
    print(f"Total now in held_out/ (all runs combined): {total_held_out}")
    if total_tuning == 0 or total_held_out == 0:
        print()
        print("WARNING: tuning/ or held_out/ is currently empty -- "
              "triage/eval.py's validate_corpus will reject this corpus "
              "until both splits have at least one file.")

    print()
    print("Reminder: skim a handful of the saved .eml files by hand before")
    print("treating this as production-ready calibration data.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--query",
        default=_DEFAULT_QUERY,
        help=f"Gmail search query (default: {_DEFAULT_QUERY!r} -- Promotions/Updates only, "
        "deliberately excludes Primary/Social). Add date bounds directly in the query, "
        "e.g. 'category:updates after:2025/01/01 before:2025/06/01'.",
    )
    parser.add_argument("--limit", type=int, default=100, help="max messages to examine (default: 100)")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_DEFAULT_OUTPUT_DIR,
        help=f"class directory for qualifying .eml files -- files are written to "
        f"<output-dir>/tuning/ or <output-dir>/held_out/, matching triage/eval.py's "
        f"corpus contract (default: {_DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--client-secret",
        type=Path,
        default=_DEFAULT_CLIENT_SECRET_PATH,
        help=f"path to your OAuth client JSON (default: {_DEFAULT_CLIENT_SECRET_PATH})",
    )
    parser.add_argument(
        "--token-path",
        type=Path,
        default=_DEFAULT_TOKEN_PATH,
        help=f"where to cache the OAuth token after first consent (default: {_DEFAULT_TOKEN_PATH})",
    )
    args = parser.parse_args()

    harvest(args.query, args.limit, args.output_dir, args.client_secret, args.token_path)


if __name__ == "__main__":
    main()
