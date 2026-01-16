import re
from datetime import datetime
from .events import LogEvent


LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s.+?\s(?P<ip>\d+\.\d+\.\d+\.\d+)\s(?P<msg>.+)'
)


def parse_line(line: str) -> LogEvent | None:
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    try:
        timestamp = datetime.strptime(
            match.group("timestamp"),
            "%b %d %H:%M:%S"
        )
    except ValueError:
        return None

    return LogEvent(
        timestamp=timestamp,
        source_ip=match.group("ip"),
        message=match.group("msg"),
        raw=line.strip()
    )
