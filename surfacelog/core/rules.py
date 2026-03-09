import yaml
from datetime import datetime, timedelta
from pathlib import Path


def load_rules() -> dict:
    """
    Carrega as regras de segurança do security.yaml
    """
    rules_path = (
        Path(__file__).resolve()
        .parent.parent / "rules" / "security.yaml"
    )

    with open(rules_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def is_bruteforce(timestamps, rule: dict) -> tuple[bool, int]:
    """
    Recebe lista de timestamps ordenados.
    Retorna (is_detected, attempts)
    """

    threshold = rule["max_attempts"]
    window_seconds = rule["window_seconds"]

    left = 0
    max_attempts = 0

    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > timedelta(seconds=window_seconds):
            left += 1

        max_attempts = max(max_attempts, right - left + 1)

    return max_attempts >= threshold, max_attempts


def is_off_hours(timestamp: datetime, rules: dict = None) -> bool:
    
    if rules is None:
        rules = load_rules()
    
    off_hours_config = rules.get("off_hours", {})
    start_time_str = off_hours_config.get("start")
    end_time_str = off_hours_config.get("end")
    
    # Converter strings para time objects
    start_time = datetime.strptime(start_time_str, "%H:%M").time()
    end_time = datetime.strptime(end_time_str, "%H:%M").time()
    
    current_time = timestamp.time()
    
    # Se start < end, verificar se current está entre eles
    if start_time < end_time:
        return start_time <= current_time < end_time
    
    # Se start > end
    else:
        return current_time >= start_time or current_time < end_time


def is_surface_scan(events: list, rule: dict) -> bool:
    """
    Detecta port scanning baseado em múltiplas conexões falhadas
    em portas diferentes dentro de uma janela de tempo.
    
    Args:
        events: Lista de NormalizedEvent
        rule: Dicionário com configurações:
            - window_seconds: Janela de tempo em segundos
            - min_unique_ports: Mínimo de portas únicas
            - min_events: Mínimo de eventos no padrão
    
    Returns:
        bool: True se o padrão foi detectado
    """
    if not events:
        return False
    
    window_seconds = rule.get("window_seconds", 60)
    min_unique_ports = rule.get("min_unique_ports", 12)
    min_events = rule.get("min_events", 15)
    
    # Ordenar por timestamp
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    
    # Sliding window approach
    for i in range(len(sorted_events)):
        window_start = sorted_events[i].timestamp
        window_end = window_start + timedelta(seconds=window_seconds)
        
        events_in_window = [
            e for e in sorted_events
            if window_start <= e.timestamp <= window_end
        ]
        
        if len(events_in_window) >= min_events:
            unique_ports = set(e.dst_port for e in events_in_window if e.dst_port)
            
            if len(unique_ports) >= min_unique_ports:
                return True
    
    return False
