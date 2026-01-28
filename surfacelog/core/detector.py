from collections import defaultdict
from datetime import timedelta
from uuid import uuid4
from surfacelog.core.models import EventType, ALERT_SEVERITY


def detect_bruteforce(events, threshold: int = 5, window_seconds: int = 60):
    alerts = []
    failures_by_ip = defaultdict(list)

    # Agrupar falhas por IP
    for event in events:
        if not event.timestamp or not event.source_ip:
            continue

        if event.event_type == EventType.AUTH_FAILURE:
            failures_by_ip[event.source_ip].append(event)

    for ip, events_list in failures_by_ip.items():
        timestamps = [e.timestamp for e in events_list]
        timestamps.sort()

        left = 0
        max_attempts = 0

        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > timedelta(seconds=window_seconds):
                left += 1

            max_attempts = max(max_attempts, right - left + 1)

        if max_attempts >= threshold:
            # Coletar todos os portos/protocolos únicos usados
            ports = set(event.source_port or "unknown" for event in events_list)
            ports_str = ", ".join(sorted(ports))
            
            alerts.append({
                "id": str(uuid4()),
                "type": "BRUTE_FORCE",
                "severity": ALERT_SEVERITY["BRUTE_FORCE"],
                "timestamp": timestamps[-1],
                "source": {
                    "ip": ip,
                    "port": ports_str
                },
                "details": {
                    "attempts": max_attempts,
                    "window_seconds": window_seconds
                }
            })

    return alerts
