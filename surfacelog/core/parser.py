import re
from datetime import datetime
from .events import LogEvent

# Regex para logs estilo auth.log / secure
LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s.+?\s(?P<ip>\d+\.\d+\.\d+\.\d+)\s(?P<msg>.+)'
)


def parse_line(line: str) -> LogEvent | None:
    """
    Faz o parse de UMA linha de log.
    Retorna LogEvent ou None se a linha não for válida.
    """
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


def parse_log(file_path: str) -> list[LogEvent]:
    """
    Lê um arquivo de log inteiro e retorna
    uma lista de eventos parseados.
    """
    events: list[LogEvent] = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)

    return events
