import re
from datetime import datetime
from surfacelog.core.events import LogEvent

# Aceita:
# Jan 10 12:01:22
# jan/01 20:03:35
LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}[\/\s]\d+\s[\d:]+).*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<msg>.+)'
)


def parse_line(line: str) -> LogEvent | None:
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    raw_ts = match.group("timestamp").replace("/", " ")

    try:
        timestamp = datetime.strptime(raw_ts, "%b %d %H:%M:%S")
    except ValueError:
        return None

    return LogEvent(
        timestamp=timestamp,
        source_ip=match.group("ip"),
        message=match.group("msg"),
        raw=line.strip()
    )


def parse_log(file_path: str) -> list[LogEvent]:
    events: list[LogEvent] = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)

    return events
