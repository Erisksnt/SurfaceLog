from collections import defaultdict
from datetime import timedelta
from surfacelog.core.models import EventType


def detect_bruteforce(events, threshold: int = 5, window_seconds: int = 60):
    alerts = []
    failures_by_ip = defaultdict(list)

    # Agrupa falhas por IP (descarta eventos sem IP)
    for event in events:
        if event.event_type == EventType.AUTH_FAILURE and event.source_ip:
            failures_by_ip[event.source_ip].append(event.timestamp)

    # Sliding window correto - encontra o máximo de tentativas em qualquer janela
    for ip, timestamps in failures_by_ip.items():
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
                "attempts": max_attempts,
                "window_seconds": window_seconds,
                "severity": "CRITICAL"
            })

    return alerts
