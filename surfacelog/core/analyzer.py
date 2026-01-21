from surfacelog.core.parser import parse_log
from surfacelog.core.classifier import classify_event
from surfacelog.core.detector import detect_bruteforce
from surfacelog.core.events import LogEvent
from typing import List, Dict


def analyze_log(file_path: str) -> Dict[str, list]:
    # 1. Parse
    events: List[LogEvent] = parse_log(file_path)

    # 2. Classificação (in-place, retorna LogEvent)
    classified_events: List[LogEvent] = []
    for event in events:
        classified_events.append(classify_event(event))

    # 3. Detecção
    alerts = detect_bruteforce(classified_events)

    return {
        "events": classified_events,
        "alerts": alerts
    }
