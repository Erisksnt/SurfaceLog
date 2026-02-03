from pathlib import Path

def export_alerts_to_txt(path: str, alerts: list):
    lines = []
    for alert in alerts:
        lines.append(
            "────────────────────────────\n"
            f"🚨 Type      : {alert.type}\n"
            f"🌐 IP        : {alert.source.ip}\n"
            f"🔌 Port      : {alert.source.port or 'unknown'}\n"
            f"🔢 Attempts : {alert.details.get('attempts', 'N/A')}\n"
            f"⏱️ Window   : {alert.details.get('window_seconds', 'N/A')}s\n"
            f"🔥 Severity : {alert.severity.value if hasattr(alert.severity, 'value') else alert.severity}\n"
            "────────────────────────────\n"
        )

    Path(path).write_text("\n".join(lines), encoding="utf-8")
    print(f"✅ Alertas exportados para TXT: {path}")
