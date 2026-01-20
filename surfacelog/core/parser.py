import re
from datetime import datetime
from .events import LogEvent


LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}[\/\s]\d{1,2}\s\d{2}:\d{2}:\d{2}).*?(?P<ip>\d+\.\d+\.\d+\.\d+)\s(?P<msg>.+)',
    re.IGNORECASE
)


def normalize_timestamp(raw_ts: str) -> str:
    #   Normaliza timestamps vendor-specific.
    #   Ex:
    #   jan/01 20:03:35 → Jan 01 20:03:35
    
    return raw_ts.replace("/", " ").title()


def parse_line(line: str) -> LogEvent | None:
    # Faz o parse de UMA linha de log.
    # Retorna LogEvent ou None se a linha não for válida.
    
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    raw_ts = match.group("timestamp")
    normalized_ts = normalize_timestamp(raw_ts)

    try:
        timestamp = datetime.strptime(
            normalized_ts,
            "%b %d %H:%M:%S"
        )
    except ValueError:
        return None

    return LogEvent(
        timestamp=timestamp,
        source_ip=match.group("ip"),
        message=match.group("msg").strip(),
        raw=line.strip()
    )


def parse_log(file_path: str) -> list[LogEvent]:
    #Lê um arquivo de log inteiro e retorna uma lista de eventos parseados.    
    events: list[LogEvent] = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)

    return events
