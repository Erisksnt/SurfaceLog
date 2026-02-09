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
