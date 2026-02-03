import csv
from surfacelog.core.models import Alert


def export_alerts_to_csv(path: str, alerts: list[Alert]):
    """Exporta Alert canônico para CSV"""

    if not alerts:
        print("⚠️ Nenhum alerta para exportar")
        return

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # header fixo (estável = melhor p/ análise depois)
        writer.writerow([
            "id",
            "type",
            "severity",
            "timestamp",
            "source_ip",
            "source_ports",
            "summary",
        ])

        for alert in alerts:
            writer.writerow([
                alert.id,
                alert.type,
                alert.severity.value,
                alert.timestamp.isoformat(),
                alert.source.ip,
                alert.source.port or "",
                alert.summary,
            ])

    print(f"✅ Alertas exportados para: {path}")
