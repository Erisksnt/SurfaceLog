import yaml
from datetime import datetime
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
