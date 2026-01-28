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
    """Exporta alertas de segurança para CSV com estrutura detalhada"""
    if not alerts:
        print("⚠️ Nenhum alerta para exportar")
        return
    
    with open(path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["id", "type", "severity", "timestamp", "ip", "port", "event_type", "attempts", "window_seconds", "message"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for alert in alerts:
            # Extrair dados da estrutura aninhada
            row = {
                "id": alert.get("id", ""),
                "type": alert.get("type", ""),
                "severity": alert.get("severity", ""),
                "timestamp": alert.get("timestamp", ""),
                "ip": alert.get("source", {}).get("ip", ""),
                "port": alert.get("source", {}).get("port", ""),
                "event_type": alert.get("details", {}).get("event_type", ""),
                "attempts": alert.get("details", {}).get("attempts", ""),
                "window_seconds": alert.get("details", {}).get("window_seconds", ""),
                "message": alert.get("details", {}).get("message", "")
            }
            
            # Converter Enum para string se necessário
            if hasattr(row["severity"], "value"):
                row["severity"] = row["severity"].value
            
            if hasattr(row["event_type"], "value"):
                row["event_type"] = row["event_type"].value
            
            # Formatar timestamp se for datetime
            if hasattr(row["timestamp"], "isoformat"):
                row["timestamp"] = row["timestamp"].isoformat()
            
            writer.writerow(row)
    
    print(f"✅ Alertas exportados para: {path}")


def export_alerts_to_txt(path: str, alerts: list[dict]):
    """Exporta alertas de segurança em formato texto legível com quebra de linhas"""
    if not alerts:
        print("⚠️ Nenhum alerta para exportar")
        return
    
    with open(path, "w", encoding="utf-8") as f:
        for idx, alert in enumerate(alerts, 1):
            # Extrair dados da estrutura aninhada
            alert_id = alert.get("id", "")
            alert_type = alert.get("type", "")
            severity = alert.get("severity", "")
            timestamp = alert.get("timestamp", "")
            ip = alert.get("source", {}).get("ip", "")
            port = alert.get("source", {}).get("port", "")
            event_type = alert.get("details", {}).get("event_type", "")
            attempts = alert.get("details", {}).get("attempts", "")
            window_seconds = alert.get("details", {}).get("window_seconds", "")
            message = alert.get("details", {}).get("message", "")
            
            # Converter Enum para string se necessário
            if hasattr(severity, "value"):
                severity = severity.value
            
            if hasattr(event_type, "value"):
                event_type = event_type.value
            
            # Formatar timestamp se for datetime
            if hasattr(timestamp, "isoformat"):
                timestamp = timestamp.isoformat()
            
            # Escrever alerta em formato legível
            f.write(f"=== ALERTA #{idx} ===\n")
            f.write(f"id = {alert_id}\n")
            f.write(f"type = {alert_type}\n")
            f.write(f"severity = {severity}\n")
            f.write(f"timestamp = {timestamp}\n")
            f.write(f"ip = {ip}\n")
            f.write(f"port = {port}\n")
            
            if event_type:
                f.write(f"event_type = {event_type}\n")
            if attempts:
                f.write(f"attempts = {attempts}\n")
            if window_seconds:
                f.write(f"window_seconds = {window_seconds}\n")
            if message:
                f.write(f"message = {message}\n")
            
            f.write("\n")
    
    print(f"✅ Alertas exportados para: {path}")


