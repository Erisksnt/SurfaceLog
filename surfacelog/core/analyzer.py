from .parser import parse_line


def analyze_log(file_path: str) -> list:
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)

    return events
