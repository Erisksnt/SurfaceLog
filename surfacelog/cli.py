import argparse
import sys
from datetime import datetime
from pathlib import Path
from surfacelog.core.analyzer import analyze_log
from surfacelog.reports.registry import exporter
from surfacelog.scan import scan_ip
from collections import Counter

# =========================
# CONFIGURAÇÕES
# =========================
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",  # vermelho
    "HIGH": "\033[31m",      # vermelho escuro
    "MEDIUM": "\033[93m",    # amarelo
    "LOW": "\033[92m",       # verde
}
RESET_COLOR = "\033[0m"

EXTRACTIONS_DIR = Path(__file__).parent.parent / "extractions"
EXTRACTIONS_DIR.mkdir(exist_ok=True)

# =========================
# UTILITÁRIOS
# =========================
def get_timestamp_filename(ext: str) -> str:
    now = datetime.now()
    timestamp = now.strftime("%d-%m-%Y_%H-%M")
    return f"{timestamp}.{ext}"

def print_alert_summary(alerts):
    """Resumo por tipo de alerta com contagem e cores"""
    if not alerts:
        print("✅ No critical alerts detected.")
        return

    counter = Counter(alert.type for alert in alerts)
    print("\n📊 ALERT SUMMARY\n")
    for alert_type, count in counter.items():
        # Pega a cor baseada no maior nível de severidade daquele tipo
        max_sev = max(
            (alert.severity.value if hasattr(alert.severity, 'value') else alert.severity)
            for alert in alerts if alert.type == alert_type
        )
        color = SEVERITY_COLOR.get(max_sev, "")
        print(f"{color}{alert_type:<20} {count}{RESET_COLOR}")

# =========================
# MENU DE EXPORTAÇÃO
# =========================
def show_export_menu() -> list[str]:
    print("\n" + "="*50)
    print("📊 OPÇÕES DE EXPORTAÇÃO")
    print("="*50)
    print("1️⃣  JSON")
    print("2️⃣  CSV")
    print("3️⃣  TXT")
    print("4️⃣  JSON + CSV")
    print("5️⃣  JSON + TXT")
    print("6️⃣  CSV + TXT")
    print("7️⃣  TODOS (JSON + CSV + TXT)")
    print("0️⃣  NENHUM")
    print("="*50)

    while True:
        choice = input("\nEscolha uma opção (0-7): ").strip()
        if choice == "0":
            return []
        elif choice == "1":
            return ["json"]
        elif choice == "2":
            return ["csv"]
        elif choice == "3":
            return ["txt"]
        elif choice == "4":
            return ["json", "csv"]
        elif choice == "5":
            return ["json", "txt"]
        elif choice == "6":
            return ["csv", "txt"]
        elif choice == "7":
            return ["json", "csv", "txt"]
        else:
            print("❌ Opção inválida! Tente novamente.")

# =========================
# ALERT DISPLAY
# =========================
def print_alert(alert):
    print("────────────────────────────")
    print(f"🚨 Type      : {alert.type}")

    if alert.type == 'BRUTE_FORCE':
        print(f"🌐 IP        : {alert.source.ip}")
        print(f"🔌 Port      : {alert.source.port or 'unknown'}")
        print(f"🔢 Attempts : {alert.details['attempts']}")
        print(f"⏱️ Window   : {alert.details['window_seconds']}s")

    elif alert.type == 'OFF_HOURS_ACTIVITY':
        print(f"🌐 IP        : {alert.source.ip or 'unknown'}")
        print(f"⏰ Time      : {alert.timestamp.strftime('%H:%M:%S')}")
        event_type = alert.details.get('event_type', 'unknown')
        if hasattr(event_type, 'value'):
            event_type = event_type.value
        print(f"📝 Event     : {event_type}")
        if alert.details and "raw" in alert.details:
            print(f"💬 Raw       : {alert.details['raw'][:80]}...")

    severity = alert.severity
    if hasattr(severity, 'value'):
        severity = severity.value
    color = SEVERITY_COLOR.get(severity, "")
    print(f"🔥 Severity : {color}{severity}{RESET_COLOR}")
    print("────────────────────────────\n")

# =========================
# RUN ANALYZE
# =========================
def run_analyze(logfile: str, alerts_only: bool, export_formats: list[str] | None = None):
    print(f"\n🔍 Analyzing log file: {logfile}\n")
    result = analyze_log(logfile)

    events = result["events"]
    alerts = result["alerts"]

    if not alerts_only:
        print(f"📄 Events processed: {len(events)}")

    for alert in alerts:
        print_alert(alert)

    print_alert_summary(alerts)

    # Menu só se export não for passado
    if export_formats is None:
        export_formats = show_export_menu()

    if not export_formats:
        print("\n👋 Nenhuma exportação selecionada.")
        return

    for fmt in export_formats:
        filename = get_timestamp_filename(fmt)
        path = EXTRACTIONS_DIR / filename
        exporter(fmt, str(path), alerts)
        
# =========================
# MAIN CLI
# =========================
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
    analyze_parser.add_argument(
        "--export",
        nargs="+",
        choices=["json", "csv", "txt"],
        help="Export alerts directly without interactive menu"
    )

    # =========================
    # SCAN COMMAND
    # =========================
    scan_parser = subparsers.add_parser(
        "scan",
        help="Port scan a specific IP"
    )
    scan_parser.add_argument(
        "host",
        help="IP or hostname to scan (e.g. 192.168.0.1)"
    )
    scan_parser.add_argument(
        "-p", "--ports",
        default="22,80,443,3306,5432,8080,8443,27017,6379",
        help="Ports to scan (e.g. 22,80,443 or 22,80,443,8000-8100)"
    )
    scan_parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Timeout per port in seconds"
    )
    scan_parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of threads for parallel scanning"
    )
    scan_parser.add_argument(
        "-e", "--export",
        choices=["csv", "json", "both"],
        help="Export results (csv, json, or both)"
    )

    args = parser.parse_args()

    if args.command == "analyze":
        run_analyze(args.logfile, args.alerts_only, args.export)
    elif args.command == "scan":
        scan_ip(
            host=args.host,
            ports_expr=args.ports,
            timeout=args.timeout,
            threads=args.threads,
            export_format=args.export
        )
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
