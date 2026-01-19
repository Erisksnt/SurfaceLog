from surfacelog.core.parser import parse_log
from surfacelog.core.classifier import classify_event


def analyze_log(file_path: str):
    raw_events = parse_log(file_path)

    if not raw_events:
        return []

    return [classify_event(event) for event in raw_events]
