import argparse
import sys
from pathlib import Path
from surfacelog.core.analyzer import analyze_log
from surfacelog.reports.csv_report import export_alerts_to_csv
from surfacelog.reports.json_report import export_alerts_to_json

# Criar pasta de extractions se não existir
EXTRACTIONS_DIR = Path(__file__).parent.parent / "extractions"
EXTRACTIONS_DIR.mkdir(exist_ok=True)


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

    analyze_parser.add_argument(
        "--alerts-only",
        action="store_true",
        help="Show only detected security alerts"
    )

    analyze_parser.add_argument(
        "--export-csv",
        type=str,
        metavar="FILEPATH",
        help="Export alerts to CSV file"
    )

    analyze_parser.add_argument(
        "--export-json",
        type=str,
        metavar="FILEPATH",
        help="Export alerts to JSON file"
    )

    args = parser.parse_args()

    if args.command == "analyze":
        run_analyze(args.logfile, args.alerts_only, args.export_csv, args.export_json)
    else:
        parser.print_help()
        sys.exit(1)


def run_analyze(logfile: str, alerts_only: bool, export_csv: str = None, export_json: str = None):
    print(f"\n🔍 Analyzing log file: {logfile}\n")

    # 🔥 Analyzer faz parse + classify + detect
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

    # Exportar alertas se solicitado
    if export_csv:
        csv_path = EXTRACTIONS_DIR / export_csv
        export_alerts_to_csv(str(csv_path), alerts)
    
    if export_json:
        json_path = EXTRACTIONS_DIR / export_json
        export_alerts_to_json(str(json_path), alerts)

def print_alert(alert: dict):
    print("────────────────────────────")
    print(f"🚨 Type      : {alert['alert_type']}")
    
    if alert['alert_type'] == 'BRUTE_FORCE':
        print(f"🌐 IP        : {alert['ip']}")
        print(f"� Port      : {alert['port']}")
        print(f"�🔢 Attempts : {alert['attempts']}")
        print(f"⏱️ Window   : {alert['window_seconds']}s")
    elif alert['alert_type'] == 'OFF_HOURS_ACTIVITY':
        print(f"🌐 IP        : {alert['ip']}")
        print(f"⏰ Time      : {alert['timestamp'].strftime('%H:%M:%S')}")
        # Normalizar event_type se for Enum
        event_type = alert['event_type']
        if hasattr(event_type, 'value'):
            event_type = event_type.value
        print(f"📝 Event     : {event_type}")
        print(f"💬 Message   : {alert['message'][:50]}...")
    
    severity = alert['severity']
    # Converter Enum para string se necessário
    if hasattr(severity, 'value'):
        severity = severity.value
    
    print(f"🔥 Severity : {severity}")
    print("────────────────────────────\n")


if __name__ == "__main__":
    main()
