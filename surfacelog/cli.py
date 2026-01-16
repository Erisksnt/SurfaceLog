import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="surfacelog",
        description="Security Log Analyzer"
    )

    subparsers = parser.add_subparsers(dest="command")

    # analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a log file"
    )
    analyze_parser.add_argument(
        "logfile",
        help="Path to log file (e.g. auth.log)"
    )

    args = parser.parse_args()

    if args.command == "analyze":
        run_analyze(args.logfile)
    else:
        parser.print_help()
        sys.exit(1)


def run_analyze(logfile: str):
    print(f"🔍 Analyzing log file: {logfile}")

