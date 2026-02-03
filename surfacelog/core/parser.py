import re
from dataclasses import dataclass
from datetime import datetime, date


@dataclass
class LogEvent:
    timestamp: datetime
    source_ip: str | None
    source_port: int | str | None
    message: str
    raw: str


# =========================
# REGEX
# =========================

PATTERN_WITH_DATE = re.compile(
    r'(?P<ts>\w{3}[\/\s]\d+\s\d{2}:\d{2}:\d{2})',
    re.IGNORECASE
)

PATTERN_TIME_ONLY = re.compile(
    r'(?P<ts>\d{2}:\d{2}:\d{2})',
    re.IGNORECASE
)

PATTERN_IP = re.compile(
    r'(?:from\s+)?(?P<ip>\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)

PATTERN_PORT = re.compile(
    r'(?:port\s+(\d+)|via\s+(\w+))',
    re.IGNORECASE
)


# =========================
# PARSE LINE
# =========================

def parse_line(line: str) -> LogEvent | None:
    line = line.strip()
    if not line:
        return None

    timestamp = None

    # ---- timestamp com data
    match_date = PATTERN_WITH_DATE.search(line)
    if match_date:
        raw_ts = match_date.group("ts").replace("/", " ")
        try:
            timestamp = datetime.strptime(raw_ts, "%b %d %H:%M:%S")
        except ValueError:
            pass

    # ---- timestamp só hora
    if not timestamp:
        match_time = PATTERN_TIME_ONLY.search(line)
        if match_time:
            today = date.today()
            time_part = datetime.strptime(match_time.group("ts"), "%H:%M:%S").time()
            timestamp = datetime.combine(today, time_part)

    if not timestamp:
        return None

    # ---- ip
    source_ip = None
    match_ip = PATTERN_IP.search(line)
    if match_ip:
        source_ip = match_ip.group("ip")

    # ---- porta (NORMALIZADA)
    source_port = None
    match_port = PATTERN_PORT.search(line)

    if match_port:
        numeric = match_port.group(1)
        proto = match_port.group(2)

        if numeric:
            source_port = int(numeric)      # <- normaliza int
        elif proto:
            source_port = proto.lower()    # <- normaliza string

    return LogEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        source_port=source_port,
        message=line,     # já stripado
        raw=line
    )


# =========================
# PARSE FILE
# =========================

def parse_log(file_path: str) -> list[LogEvent]:
    events: list[LogEvent] = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)

    return events
