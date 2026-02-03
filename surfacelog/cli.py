import argparse
import sys
from datetime import datetime
from pathlib import Path
from surfacelog.core.analyzer import analyze_log
from surfacelog.reports.csv_report import export_alerts_to_csv
from surfacelog.reports.json_report import export_alerts_to_json
from surfacelog.reports.txt_report import export_alerts_to_txt

# Criar pasta de extractions se não existir
EXTRACTIONS_DIR = Path(__file__).parent.parent / "extractions"
EXTRACTIONS_DIR.mkdir(exist_ok=True)


def get_timestamp_filename(ext: str) -> str:
    """Gera nome de arquivo com timestamp (data e hora)"""
    now = datetime.now()
    timestamp = now.strftime("%d-%m-%Y_%H-%M")
    return f"{timestamp}.{ext}"


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

    args = parser.parse_args()

    if args.command == "analyze":
        run_analyze(args.logfile, args.alerts_only)
    else:
        parser.print_help()
        sys.exit(1)


def show_export_menu() -> list[str]:
    """Mostra menu de opções de exportação e retorna os formatos selecionados"""
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


def run_analyze(logfile: str, alerts_only: bool):
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

    # Menu de exportação
    export_formats = show_export_menu()
    
    if not export_formats:
        print("\n👋 Nenhuma exportação selecionada.")
        return
    
    # Exportar nos formatos selecionados
    EXPORTERS = {
        "json": export_alerts_to_json,
        "csv": export_alerts_to_csv,
        "txt": export_alerts_to_txt,
    }
    
    for fmt in export_formats:
        filename = get_timestamp_filename(fmt)
        path = EXTRACTIONS_DIR / filename
        EXPORTERS[fmt](str(path), alerts)

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

        event_type = alert.details['event_type']
        if hasattr(event_type, 'value'):
            event_type = event_type.value

        print(f"📝 Event     : {event_type}")
        print(f"💬 Message   : {alert.details['message'][:50]}...")
    
    severity = alert.severity
    # Converter Enum para string se necessário
    if hasattr(severity, 'value'):
        severity = severity.value
    
    print(f"🔥 Severity : {severity}")
    print("────────────────────────────\n")


if __name__ == "__main__":
    main()
