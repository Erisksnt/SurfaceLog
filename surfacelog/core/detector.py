from collections import defaultdict
from datetime import timedelta
from surfacelog.core.models import EventType, ALERT_SEVERITY


def detect_bruteforce(events, threshold: int = 5, window_seconds: int = 60):
    alerts = []
    failures_by_ip_port = defaultdict(list)

    # Agrupa falhas por IP e porta (descarta eventos sem IP ou timestamp)
    for event in events:
        # Proteção defensiva: validar timestamp e IP
        if not event.timestamp or not event.source_ip:
            continue
        
        if event.event_type == EventType.AUTH_FAILURE:
            # Usar porta se disponível, senão usar "unknown"
            port = event.source_port or "unknown"
            key = (event.source_ip, port)
            failures_by_ip_port[key].append(event.timestamp)

    # Sliding window correto - encontra o máximo de tentativas em qualquer janela
    for (ip, port), timestamps in failures_by_ip_port.items():
        timestamps.sort()
        max_attempts = 0
        
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > timedelta(seconds=window_seconds):
                left += 1

            attempts = right - left + 1
            max_attempts = max(max_attempts, attempts)

        if max_attempts >= threshold:
            alerts.append({
                "alert_type": "BRUTE_FORCE",
                "ip": ip,
                "port": port,
                "attempts": max_attempts,
                "window_seconds": window_seconds,
                "severity": ALERT_SEVERITY["BRUTE_FORCE"]
            })

    return alerts
