import json
from datetime import datetime

def export_to_json(path: str, results: list[dict]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def export_alerts_to_json(path: str, alerts: list[dict]):
    """Exporta alertas de segurança para JSON"""
    if not alerts:
        print("⚠️ Nenhum alerta para exportar")
        return
    
    alerts_serializable = []
    
    for alert in alerts:
        alert_copy = alert.copy()
        
        # Converter Enum para string se necessário
        if hasattr(alert_copy.get("severity"), "value"):
            alert_copy["severity"] = alert_copy["severity"].value
        
        if hasattr(alert_copy.get("event_type"), "value"):
            alert_copy["event_type"] = alert_copy["event_type"].value
        
        # Converter datetime para ISO format
        if hasattr(alert_copy.get("timestamp"), "isoformat"):
            alert_copy["timestamp"] = alert_copy["timestamp"].isoformat()
        
        alerts_serializable.append(alert_copy)
    
    with open(path, "w", encoding="utf-8") as f:
        json.dump(alerts_serializable, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Alertas exportados para: {path}")
