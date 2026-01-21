from typing import List, Dict
from surfacelog.core.parser import parse_log
from surfacelog.core.classifier import classify_event
from surfacelog.core.detector import detect_bruteforce
from surfacelog.core.off_hours_detector import detect_off_hours_activity
from surfacelog.core.events import LogEvent


def analyze_log(file_path: str) -> Dict[str, list]:
    # 1️⃣ Parse
    events: List[LogEvent] = parse_log(file_path)

    # 2️⃣ Classificação (in-place)
    for event in events:
        classify_event(event)

    # 3️⃣ Detecção de Brute Force
    bruteforce_alerts = detect_bruteforce(events)
    
    # 4️⃣ Detecção de Atividades Fora do Horário
    off_hours_alerts = detect_off_hours_activity(events)
    
    # Combinar todos os alertas
    all_alerts = bruteforce_alerts + off_hours_alerts

    return {
        "events": events,
        "alerts": all_alerts
    }
