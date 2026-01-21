import re
from datetime import datetime
from surfacelog.core.events import LogEvent

# Aceita:
# Jan 10 12:01:22
# jan/01 20:03:35
LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}[\/\s]\d+\s[\d:]+)\s.+?:\s(?P<msg>.+)'
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

    msg = match.group("msg")

    # Extrai IP de dentro da mensagem
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', msg)
    if not ip_match:
        return None

    return LogEvent(
        timestamp=timestamp,
        source_ip=ip_match.group(1),
        message=msg.lower(),
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
