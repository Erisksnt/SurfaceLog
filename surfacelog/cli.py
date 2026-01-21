import argparse
import sys
from surfacelog.core.analyzer import analyze_log


def main():
    parser = argparse.ArgumentParser(
        prog="surfacelog",
        description="Security Log Analyzer"
    )

    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a log file"
    )

    analyze_parser.add_argument(
        "logfile",
        help="Path to log file (e.g. auth.log)"
    )

    analyze_parser.add_argument(
        "--alerts-only",
        action="store_true",
        help="Show only detected security alerts"
    )

    args = parser.parse_args()

    if args.command == "analyze":
        run_analyze(args.logfile, args.alerts_only)
    else:
        parser.print_help()
        sys.exit(1)


def run_analyze(logfile: str, alerts_only: bool):
    print(f"\n🔍 Analyzing log file: {logfile}\n")

    # 🔥 Analyzer já faz tudo
    result = analyze_log(logfile)

    events = result["events"]
    alerts = result["alerts"]

    if not alerts_only:
        print(f"📄 Events processed: {len(events)}")

    if alerts:
        print(f"\n🚨 SECURITY ALERTS ({len(alerts)})\n")
        for alert in alerts:
            print_alert(alert)
    else:
        print("\n✅ No critical alerts detected.")


def print_alert(alert: dict):
    print("────────────────────────────")
    print(f"🚨 Type      : {alert['alert_type']}")
    print(f"🌐 IP        : {alert['ip']}")
    print(f"🔢 Attempts : {alert['attempts']}")
    print(f"⏱️ Window   : {alert['window_seconds']}s")
    print(f"🔥 Severity : {alert['severity']}")
    print("────────────────────────────\n")


if __name__ == "__main__":
    main()
