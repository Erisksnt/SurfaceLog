from typing import Dict, List

from surfacelog.core.parser import parse_log
from surfacelog.core.classifier import classify_event
from surfacelog.core.detectors.registry import run_detectors
from surfacelog.core.models import NormalizedEvent, Alert


def analyze_log(file_path: str) -> Dict[str, List]:
    # 1️⃣ Parse
    raw_events = parse_log(file_path)

    # 2️⃣ Normalização
    classified_events: List[NormalizedEvent] = [
        classify_event(e) for e in raw_events
    ]

    # 3️⃣ Detecção
    alerts: List[Alert] = run_detectors(classified_events)

    return {
        "events": classified_events,
        "alerts": alerts,
    }
