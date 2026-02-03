from typing import List, Dict
from surfacelog.core.parser import parse_log
from surfacelog.core.classifier import classify_event
from surfacelog.core.detectors.regristry import run_detectors
from surfacelog.core.events import LogEvent


def analyze_log(file_path: str) -> Dict[str, list]:
    # 1️⃣ Parse
    events: List[LogEvent] = parse_log(file_path)

    # 2️⃣ Classificação
    classified_events: List[LogEvent] = []
    for event in events:
        classified_events.append(classify_event(event))

    # 3️⃣ Detecções
   
    alerts = run_detectors(classified_events)

    return {
        "events": classified_events,
        "alerts": alerts
    }
