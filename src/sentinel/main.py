import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, cast

from sentinel.cipher import CipherAgent
from sentinel.confidence import TIER_MAP, calculate_tier
from sentinel.config import ConfigError
from sentinel.config import load as load_config
from sentinel.reporter import generate_report, write_report_markdown
from sentinel.source_registry import are_independent
from sentinel.verdict import assemble_verdict, print_verdict
from sentinel.watchman import WatchmanAgent


def main() -> None:
    try:
        _run()
    except SystemExit:
        raise
    except Exception as exc:
        print(f"sentinel: unexpected error — {exc}", file=sys.stderr)
        sys.exit(1)


def _run() -> None:
    start_time = time.time()

    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL — multi-agent security alert corroboration engine",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Security alert, log line, or IOC to analyze",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate a structured incident report (JSON stdout + Markdown file in reports/)",
    )
    args = parser.parse_args()

    if args.input is not None:
        input_data: str = args.input
    elif not sys.stdin.isatty():
        input_data = sys.stdin.read().strip()
    else:
        print(
            'sentinel: no input provided.\n'
            'Usage: sentinel "<alert text>"  OR  echo "<alert>" | sentinel',
            file=sys.stderr,
        )
        sys.exit(2)

    if not input_data:
        print("sentinel: input is empty.", file=sys.stderr)
        sys.exit(2)

    try:
        config = load_config()
    except ConfigError as exc:
        print(f"sentinel: {exc}", file=sys.stderr)
        sys.exit(2)

    watchman = WatchmanAgent(config)
    cipher = CipherAgent(config)

    print("[sentinel] Analyzing alert...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=2) as executor:
        w_future = executor.submit(watchman.analyze, input_data)
        c_future = executor.submit(cipher.analyze, input_data)
        watchman_result = w_future.result()
        cipher_result = c_future.result()

    tier_enum = calculate_tier(watchman_result, cipher_result)
    tier = TIER_MAP[tier_enum]
    independence = are_independent("watchman", "cipher")

    verdict = assemble_verdict(watchman_result, cipher_result, tier, independence, start_time)

    if args.report:
        report = generate_report(input_data, watchman_result, cipher_result, verdict)
        md_path = write_report_markdown(report, verdict["timestamp"])
        print(f"[sentinel] Report written to {md_path}", file=sys.stderr)
        verdict["incident_report"] = cast(dict[str, Any], report)

    print_verdict(verdict)
    sys.exit(0)


if __name__ == "__main__":
    main()
