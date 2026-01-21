import csv
from datetime import datetime

def export_to_csv(path: str, results: list[dict]):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["port", "service", "status", "banner"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow(row)


def export_alerts_to_csv(path: str, alerts: list[dict]):
    """Exporta alertas de segurança para CSV"""
    if not alerts:
        print("⚠️ Nenhum alerta para exportar")
        return
    
    with open(path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["alert_type", "ip", "port", "timestamp", "severity"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for alert in alerts:
            row = {
                "alert_type": alert.get("alert_type", ""),
                "ip": alert.get("ip", "N/A"),
                "port": alert.get("port", ""),
                "timestamp": alert.get("timestamp", ""),
                "severity": alert.get("severity", "")
            }
            
            # Converter Enum para string se necessário
            if hasattr(row["severity"], "value"):
                row["severity"] = row["severity"].value
            
            # Formatar timestamp se for datetime
            if hasattr(row["timestamp"], "isoformat"):
                row["timestamp"] = row["timestamp"].isoformat()
            
            writer.writerow(row)
    
    print(f"✅ Alertas exportados para: {path}")


