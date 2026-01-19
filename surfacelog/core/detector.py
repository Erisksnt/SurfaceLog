from collections import defaultdict
from datetime import timedelta


def detect_bruteforce(events: list, threshold: int = 5, window_seconds: int = 60) -> list:
    alerts = []
    events_by_ip = defaultdict(list)

    for event in events:
        if event.get("event_type") == "AUTH_FAILURE":
            ip = event.get("ip")
            timestamp = event.get("timestamp")

            if ip and timestamp:
                events_by_ip[ip].append(timestamp)

    for ip, timestamps in events_by_ip.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            start = timestamps[i]
            count = 1

            for j in range(i + 1, len(timestamps)):
                if timestamps[j] - start <= timedelta(seconds=window_seconds):
                    count += 1
                else:
                    break

            if count >= threshold:
                alerts.append({
                    "alert_type": "BRUTE_FORCE",
                    "ip": ip,
                    "attempts": count,
                    "window_seconds": window_seconds,
                    "severity": "CRITICAL"
                })
                break

    return alerts
