from typing import List, Dict
from surfacelog.core.parser import parse_log
from surfacelog.core.classifier import classify_event
from surfacelog.core.detector import detect_bruteforce
from surfacelog.core.events import LogEvent


def analyze_log(file_path: str) -> Dict[str, list]:
    # 1️⃣ Parse
    events: List[LogEvent] = parse_log(file_path)

    # 2️⃣ Classificação (in-place)
    for event in events:
        classify_event(event)

    # 3️⃣ Detecção
    alerts = detect_bruteforce(events)

    return {
        "events": events,
        "alerts": alerts
    }
