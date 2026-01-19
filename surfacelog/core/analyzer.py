from surfacelog.core.parser import parse_line
from surfacelog.core.classifier import classify_event
from surfacelog.core.detector import detect_bruteforce


def analyze_log(file_path: str) -> dict:
    raw_events = parse_line(file_path)

    classified_events = [
        classify_event(event) for event in raw_events
    ]

    alerts = detect_bruteforce(classified_events)

    return {
        "events": classified_events,
        "alerts": alerts
    }
