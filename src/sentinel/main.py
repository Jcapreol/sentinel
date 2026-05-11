import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL — multi-agent security alert corroboration engine"
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Security alert, log line, or IOC to analyze",
    )
    parser.parse_args()
    print("Not yet implemented.", file=sys.stderr)
    sys.exit(1)
