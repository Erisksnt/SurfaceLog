import re
from datetime import datetime, date
from surfacelog.core.events import LogEvent

# Regex com data (Jan 10 12:01:22 | jan/01 12:01:22)
PATTERN_WITH_DATE = re.compile(
    r'(?P<ts>\w{3}[\/\s]\d+\s\d{2}:\d{2}:\d{2}).*?(?:from\s)?(?P<ip>\d+\.\d+\.\d+\.\d+)?.*(?P<msg>.+)',
    re.IGNORECASE
)

# Regex só horário (08:38:45 ...)
PATTERN_TIME_ONLY = re.compile(
    r'(?P<ts>\d{2}:\d{2}:\d{2}).*?(?:from\s)?(?P<ip>\d+\.\d+\.\d+\.\d+)?.*(?P<msg>.+)',
    re.IGNORECASE
)


def parse_line(line: str) -> LogEvent | None:
    line = line.strip()
    if not line:
        return None

    match = PATTERN_WITH_DATE.search(line)
    timestamp = None

    if match:
        raw_ts = match.group("ts").replace("/", " ")
        try:
            timestamp = datetime.strptime(raw_ts, "%b %d %H:%M:%S")
        except ValueError:
            return None
    else:
        match = PATTERN_TIME_ONLY.search(line)
        if not match:
            return None

        # Assume data de hoje
        today = date.today()
        time_part = datetime.strptime(match.group("ts"), "%H:%M:%S").time()
        timestamp = datetime.combine(today, time_part)

    return LogEvent(
        timestamp=timestamp,
        source_ip=match.group("ip"),
        message=match.group("msg"),
        raw=line
    )


def parse_log(file_path: str) -> list[LogEvent]:
    events: list[LogEvent] = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)

    return events
