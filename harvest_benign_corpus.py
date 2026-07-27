"""
Harvest a modern, header-intact benign email corpus from a public-inbox
mailing-list archive (public-inbox is the software that preserves full,
unmodified original headers -- unlike Mailman 3 / HyperKitty, see below).

WHY THIS EXISTS
----------------
Sentinel's detection engine reads the real Authentication-Results header to
extract SPF/DKIM/DMARC verdicts. Most public "benign email" datasets (Enron,
SpamAssassin ham, etc.) predate those protocols entirely and simply don't
have that header. Modern mailing-list archives ought to be a reliable
source of real, current messages with intact authentication headers --
IF the archiving software actually preserves them (see below).

STATUS / KNOWN ISSUES (read this if the output looks empty or errors out)
---------------------------------------------------------------------------
Approaches tried so far, in order:
1. lore.kernel.org (public-inbox) -- blocked by an Anubis proof-of-work
   anti-bot wall a plain script can't solve. Abandoned.
2. mail.python.org (Mailman 3 / HyperKitty) -- export mechanism eventually
   worked (python-checkins, 2025-06, 681 real messages retrieved), but a
   direct header dump of a real message showed only From/To/Subject/Date/
   Message-ID/MIME-Version/Content-Type -- NO Authentication-Results, NO
   DKIM-Signature, NO Received chain at all. This is NOT specific to that
   one list -- Mailman/HyperKitty strips delivery-mechanics headers as a
   normal part of archiving, for every list on that platform. Structurally
   unusable for this project's purpose, regardless of which list you pick.

Current approach: target a DIFFERENT public-inbox instance --
inbox.sourceware.org (GCC/glibc/binutils mailing lists) -- since
public-inbox software (unlike Mailman) is specifically designed to
preserve the raw, unmodified original message. The open question is
whether THIS instance is also behind an Anubis wall like lore.kernel.org
-- there's a specific, recent sign it might be (an admin thread on that
site's own overseers list mentions an Anubis upgrade). This run is a
one-shot test of that.

WHAT THIS SCRIPT DOES
----------------------
1. Downloads a bounded batch of messages from a public-inbox list via its
   search+mbox interface (bounded by date range).
2. Parses each message and checks whether it actually carries an
   Authentication-Results (or ARC-Authentication-Results) header and/or a
   DKIM-Signature header.
3. Saves only messages that pass that check as individual raw .eml files
   -- ready to feed into the same header-parsing code Sentinel uses
   (triage/headers.py).
4. Prints full request/response diagnostics plus a header dump of the
   first real message found, so failures are visible, not guessed at.

CAVEATS -- read before you trust the output
---------------------------------------------
- This gives you topically-skewed benign mail (developer/mailing-list
  traffic), not marketing/financial/account-notification style mail. It's
  a starting point, not the whole benign corpus.
- Mailing-list relays legitimately rewrite/break some auth signals (this is
  real and expected -- do not "fix" it by filtering these out).
- Verify a handful of the saved .eml files by hand before treating any of
  this as production-ready calibration data.

USAGE
-----
    pip install requests
    python harvest_benign_corpus.py --list libc-alpha --since 20250101 --until 20250201

Run with --help for all options.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import mailbox
import sys
import tempfile
from email.message import Message
from pathlib import Path

import requests

PUBLIC_INBOX_BASE = "https://inbox.sourceware.org"

# Some servers reject requests carrying Python's default
# "python-requests/X.Y" User-Agent. A normal browser-style header avoids
# that.
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}


def build_mbox_url(list_name: str, since: str, until: str) -> str:
    """Build the bounded search+mbox URL for a public-inbox list. Bounding
    by date avoids downloading a list's entire multi-year archive.
    """
    query = f"d:{since}..{until}"
    return f"{PUBLIC_INBOX_BASE}/{list_name}/?q={query}&x=m"


def download_mbox(url: str, dest_path: Path) -> None:
    print(f"Downloading: {url}")
    resp = requests.get(url, headers=REQUEST_HEADERS, stream=True, timeout=60)

    raw_content = resp.content

    # Always show what actually came back, BEFORE checking for an error
    # status -- raise_for_status() throws immediately on 4xx/5xx, so any
    # diagnostic print placed after it never runs on exactly the requests
    # we most need to see the details of.
    print(f"  [diag] HTTP {resp.status_code}, Content-Type: {resp.headers.get('Content-Type')}, "
          f"Content-Length header: {resp.headers.get('Content-Length')}, "
          f"actual bytes received: {len(raw_content)}")
    if resp.history:
        redirect_chain = " -> ".join(r.url for r in resp.history) + f" -> {resp.url}"
        print(f"  [diag] Redirected: {redirect_chain}")

    if not resp.ok:
        preview = raw_content[:500].decode("utf-8", errors="replace")
        print()
        print(f"=== HTTP {resp.status_code} error — server's response body follows ===")
        print(preview)
        print("=" * 60)
        resp.raise_for_status()  # raises with the normal requests error message

    content = raw_content

    # Detect real gzip content by its magic bytes (1f 8b) rather than
    # trusting the Content-Encoding header -- `requests` already
    # transparently decompresses standard HTTP Content-Encoding: gzip, so
    # trusting that header a second time causes a double-decompression
    # error. Checking the actual bytes is correct either way.
    if content[:2] == b"\x1f\x8b":
        content = gzip.decompress(content)
        print(f"  [diag] Gzip-decompressed: {len(content)} bytes")

    # Only treat this as an ERROR if the server sent back an HTML page
    # (a challenge page, an error page, a "no such list" page, etc.) --
    # that's a real problem worth stopping and showing a preview for. A
    # gzip response that decompresses to an empty or near-empty mbox is a
    # legitimate, if uninteresting, result (that month/list combo just had
    # no matching mail) and should NOT be treated as a failure -- let the
    # caller report "0 messages" rather than crash on it.
    content_type = resp.headers.get("Content-Type", "")
    looks_like_html = b"<html" in content[:200].lower() or "html" in content_type.lower()
    if looks_like_html:
        preview = content[:500].decode("utf-8", errors="replace")
        print()
        print("=== Unexpected response — this looks like an HTML page, not mail data ===")
        print(f"HTTP status: {resp.status_code}")
        print(f"Content-Type: {content_type}")
        print("First 500 bytes of what the server actually sent:")
        print(preview)
        print("=" * 60)
        raise ValueError(
            "Response was an HTML page, not a valid mbox file — see preview above. "
            "The list name, month, or host may be wrong, or the server is blocking "
            "automated requests."
        )

    dest_path.write_bytes(content)
    print(f"Saved raw mbox to: {dest_path} ({len(content):,} bytes)")


def has_intact_auth_headers(msg: Message) -> tuple[bool, bool]:
    """Returns (has_authentication_results, has_dkim_signature)."""
    has_auth_results = bool(
        msg.get("Authentication-Results") or msg.get("ARC-Authentication-Results")
    )
    has_dkim = bool(msg.get("DKIM-Signature"))
    return has_auth_results, has_dkim


def harvest(list_name: str, since: str, until: str, output_dir: Path, limit: int) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    url = build_mbox_url(list_name, since, until)

    total = 0
    with_auth_results = 0
    with_dkim = 0
    saved = 0

    with tempfile.TemporaryDirectory() as tmp:
        mbox_path = Path(tmp) / "archive.mbox"
        download_mbox(url, mbox_path)

        box = mailbox.mbox(str(mbox_path))
        print(f"  {len(box)} message(s) found for {list_name}, {since}..{until}")

        if len(box) > 0:
            sample = box[list(box.keys())[0]]
            print()
            print("  [diag] Full header dump of the FIRST message in this archive:")
            for k, v in sample.items():
                print(f"    {k}: {v}")
            print()

        for msg in box:
            total += 1
            auth_ok, dkim_ok = has_intact_auth_headers(msg)
            if auth_ok:
                with_auth_results += 1
            if dkim_ok:
                with_dkim += 1

            if not (auth_ok or dkim_ok):
                continue
            if saved >= limit:
                continue

            raw_bytes = msg.as_bytes()
            content_hash = hashlib.sha256(raw_bytes).hexdigest()[:16]
            out_path = output_dir / f"{list_name}-{content_hash}.eml"
            out_path.write_bytes(raw_bytes)
            saved += 1

        box.close()

    print()
    print("=== Harvest summary ===")
    print(f"List:                  {list_name}")
    print(f"Date range:            {since} .. {until}")
    print(f"Messages examined:     {total}")
    print(f"With Authentication-Results/ARC: {with_auth_results}")
    print(f"With DKIM-Signature:   {with_dkim}")
    print(f"Saved (auth-intact):   {saved}")
    print(f"Output directory:      {output_dir.resolve()}")
    if total == 0:
        print()
        print("0 messages -- this instance may also be behind an anti-bot wall,")
        print("or the list name / date range may be wrong. Check the preview above.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", default="libc-alpha", help="public-inbox list name on inbox.sourceware.org (default: libc-alpha)")
    parser.add_argument("--since", required=True, help="start date, YYYYMMDD")
    parser.add_argument("--until", required=True, help="end date, YYYYMMDD")
    parser.add_argument("--limit", type=int, default=200, help="max messages to save (default: 200)")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("benign_corpus_raw"),
        help="where to save qualifying .eml files (default: ./benign_corpus_raw)",
    )
    args = parser.parse_args()

    try:
        harvest(args.list, args.since, args.until, args.output_dir, args.limit)
    except requests.RequestException as e:
        print(f"Download failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
