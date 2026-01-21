from datetime import datetime
import yaml
from pathlib import Path
from surfacelog.core.models import EventType, ALERT_SEVERITY


def load_rules():
    """Carrega as regras de segurança do arquivo YAML"""
    rules_path = Path(__file__).parent.parent / "rules" / "security.yaml"
    
    with open(rules_path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    
    return rules


def is_off_hours(timestamp: datetime, rules: dict = None) -> bool:
    
    if rules is None:
        rules = load_rules()
    
    off_hours_config = rules.get("off_hours", {})
    start_time_str = off_hours_config.get("start", "00:00")
    end_time_str = off_hours_config.get("end", "06:00")
    
    # Converter strings para time objects
    start_time = datetime.strptime(start_time_str, "%H:%M").time()
    end_time = datetime.strptime(end_time_str, "%H:%M").time()
    
    current_time = timestamp.time()
    
    # Se start < end, verificar se current está entre eles
    if start_time < end_time:
        return start_time <= current_time < end_time
    
    # Se start > end
    # Ex: 22:00 a 06:00 significa após 22:00 OU antes de 06:00
    else:
        return current_time >= start_time or current_time < end_time


def detect_off_hours_activity(events, rules: dict = None):
    
    if rules is None:
        rules = load_rules()
    
    alerts = []
    
    # Eventos suspeitos fora do horário (excluindo logins bem-sucedidos)
    suspicious_types = [
        EventType.AUTH_FAILURE,
        EventType.ACCESS_DENIED,
        EventType.ERROR
    ]
    
    for event in events:
        # Proteção defensiva: validar timestamp
        if not event.timestamp:
            continue
        
        if event.event_type in suspicious_types and is_off_hours(event.timestamp, rules):
            alerts.append({
                "alert_type": "OFF_HOURS_ACTIVITY",
                "timestamp": event.timestamp,
                "ip": event.source_ip,
                "event_type": event.event_type,
                "message": event.message,
                "severity": ALERT_SEVERITY["OFF_HOURS_ACTIVITY"]
            })
    
    return alerts
