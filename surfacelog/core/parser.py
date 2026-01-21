import re
from datetime import datetime, date
from surfacelog.core.events import LogEvent

# Regex com data (Jan 10 12:01:22 | jan/01 12:01:22)
PATTERN_WITH_DATE = re.compile(
    r'(?P<ts>\w{3}[\/\s]\d+\s\d{2}:\d{2}:\d{2})',
    re.IGNORECASE
)

# Regex só horário (08:38:45 ...)
PATTERN_TIME_ONLY = re.compile(
    r'(?P<ts>\d{2}:\d{2}:\d{2})',
    re.IGNORECASE
)

# Regex para extrair IP (em qualquer lugar da linha)
PATTERN_IP = re.compile(
    r'(?:from\s+)?(?P<ip>\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)

# Regex para extrair porta (procura "port XXXX")
PATTERN_PORT = re.compile(
    r'port\s+(\d+)',
    re.IGNORECASE
)


def parse_line(line: str) -> LogEvent | None:
    line = line.strip()
    if not line:
        return None

    timestamp = None
    source_ip = None

    # Tentar extrair timestamp com data
    match_date = PATTERN_WITH_DATE.search(line)
    if match_date:
        raw_ts = match_date.group("ts").replace("/", " ")
        try:
            timestamp = datetime.strptime(raw_ts, "%b %d %H:%M:%S")
        except ValueError:
            pass

    # Se não achou com data, tentar só com horário
    if not timestamp:
        match_time = PATTERN_TIME_ONLY.search(line)
        if match_time:
            try:
                today = date.today()
                time_part = datetime.strptime(match_time.group("ts"), "%H:%M:%S").time()
                timestamp = datetime.combine(today, time_part)
            except ValueError:
                pass

    # Se ainda não tem timestamp, descarta a linha
    if not timestamp:
        return None

    # Tentar extrair IP (se houver)
    match_ip = PATTERN_IP.search(line)
    if match_ip:
        source_ip = match_ip.group("ip")

    # Tentar extrair porta (se houver)
    source_port = None
    match_port = PATTERN_PORT.search(line)
    if match_port:
        source_port = match_port.group(1)

    return LogEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        message=line.strip(),
        raw=line,
        source_port=source_port
    )


def parse_log(file_path: str) -> list[LogEvent]:
    events: list[LogEvent] = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)

    return events
