import json
from dataclasses import asdict
from surfacelog.core.models import Alert


def export_alerts_to_json(path: str, alerts: list[Alert]):
    """Exporta Alert canônico para JSON"""

    if not alerts:
        print("⚠️ Nenhum alerta para exportar")
        return

    serializable = []

    for alert in alerts:
        data = asdict(alert)

        # datetime → string
        data["timestamp"] = alert.timestamp.isoformat()

        # severity enum → string
        data["severity"] = alert.severity.value

        serializable.append(data)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2, ensure_ascii=False)

    print(f"✅ Alertas exportados para: {path}")
