"""
Organize a locally-cloned phishing_pot repository into the directory
contract Sentinel's triage/eval.py load_corpus() expects for the
malicious class: benign_corpus_raw/malicious/tuning/ and
benign_corpus_raw/malicious/held_out/, plus a PROVENANCE.md.

WHY THIS EXISTS
----------------
phishing_pot (github.com/rf-peixoto/phishing_pot) is real, honeypot-
captured phishing email with intact modern headers -- the malicious-side
counterpart to the benign corpus already built from harvest_own_inbox.py.
Unlike every other source explored tonight, this one needs no network
fetching gymnastics: it's a plain git repo of .eml files. This script's
only job is organizing what you already cloned, not downloading anything
itself.

PERMISSION / LICENSE NOTE
---------------------------
The repository's default license (CC BY-NC 4.0) restricts commercial use.
The maintainer granted informal permission via email to use this data for
a commercial product, on the condition that the raw data itself is never
redistributed. This script respects that by design: it only ever COPIES
files into benign_corpus_raw/, which is gitignored and never committed --
the raw phishing_pot content never leaves your machine via this project's
repo.

USAGE
-----
    1. git clone https://github.com/rf-peixoto/phishing_pot.git
       (run this in a directory OUTSIDE the sentinel repo, e.g. your
       Documents folder directly -- no need for it to live inside
       sentinel/ at all)
    2. python harvest_phishing_pot.py --source "C:\\path\\to\\phishing_pot\\email"

Run with --help for all options.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

_DEFAULT_OUTPUT_DIR = Path("benign_corpus_raw/malicious")

_PROVENANCE_TEMPLATE = """\
# Provenance — malicious corpus

## Source
GitHub: rf-peixoto/phishing_pot (https://github.com/rf-peixoto/phishing_pot)

Real phishing email captured via honeypot, contributed by the project's
maintainer and community. Raw .eml files with intact original headers,
including real Authentication-Results (SPF/DKIM/DMARC) verdicts.

## Collection method
Honeypot-captured phishing samples, anonymized by the source project
(recipient addresses replaced with phishing@pot per the project's own
contribution convention). Not synthetic, not LLM-generated -- each file
is a real captured phishing attempt.

## Permission
The repository's default license (CC BY-NC 4.0) restricts commercial use.
The maintainer granted informal permission via email (dated {date}) to use
this data for this commercial product, on the explicit condition that the
raw data itself is never redistributed. This corpus directory is
gitignored and never committed to any repository -- files exist only on
this local machine.

## Trustworthiness rationale
Each file is a real, captured phishing email, not a synthetic or
self-labeled example. The malicious label is trustworthy by construction:
these are genuine attack attempts collected by a dedicated honeypot, not
inferred or guessed.

## Known limitations
Honeypot-sourced phishing skews toward broad, opportunistic,
multilingual credential/brand-impersonation attacks. It underrepresents
narrowly-targeted spear-phishing or business email compromise, which a
honeypot by design won't attract. Worth keeping in mind when interpreting
calibration results derived from this corpus.
"""


def split_files(files: list[Path], held_out_fraction_denominator: int = 5) -> tuple[list[Path], list[Path]]:
    """Deterministic content-hash-based split, matching the same scheme
    used for the benign corpus (harvest_own_inbox.py): a file's own SHA-256
    content hash decides its split, so re-running this script never
    reshuffles an already-placed file.
    """
    tuning: list[Path] = []
    held_out: list[Path] = []
    for f in files:
        content_hash = hashlib.sha256(f.read_bytes()).hexdigest()
        if int(content_hash[:8], 16) % held_out_fraction_denominator == 0:
            held_out.append(f)
        else:
            tuning.append(f)
    return tuning, held_out


def organize(source_dir: Path, output_dir: Path) -> None:
    if not source_dir.exists():
        print(f"Source directory not found: {source_dir}", file=sys.stderr)
        print("Did you git clone phishing_pot first? See this script's docstring.", file=sys.stderr)
        sys.exit(1)

    eml_files = sorted(source_dir.glob("*.eml"))
    if not eml_files:
        print(f"No .eml files found directly in {source_dir}", file=sys.stderr)
        print("Check the path -- phishing_pot's samples usually live under an 'email/' folder.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(eml_files)} .eml file(s) in {source_dir}")

    tuning, held_out = split_files(eml_files)
    print(f"Split: {len(tuning)} tuning, {len(held_out)} held_out")

    tuning_dir = output_dir / "tuning"
    held_out_dir = output_dir / "held_out"
    tuning_dir.mkdir(parents=True, exist_ok=True)
    held_out_dir.mkdir(parents=True, exist_ok=True)

    for f in tuning:
        shutil.copy2(f, tuning_dir / f.name)
    for f in held_out:
        shutil.copy2(f, held_out_dir / f.name)

    from datetime import date
    provenance_path = output_dir / "PROVENANCE.md"
    provenance_path.write_text(_PROVENANCE_TEMPLATE.format(date=date.today().isoformat()))

    print()
    print("=== Done ===")
    print(f"Tuning:    {len(tuning)} files -> {tuning_dir}")
    print(f"Held-out:  {len(held_out)} files -> {held_out_dir}")
    print(f"Provenance written to {provenance_path}")
    print()
    print("Next: rerun validate_corpus against benign_corpus_raw/ to confirm")
    print("the malicious class now passes too.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--source",
        type=Path,
        required=True,
        help="path to the cloned phishing_pot repo's email/ directory (containing .eml files)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_DEFAULT_OUTPUT_DIR,
        help=f"where to organize files (default: {_DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args()
    organize(args.source, args.output_dir)


if __name__ == "__main__":
    main()
