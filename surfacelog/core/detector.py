def detect_bruteforce(events, threshold=5, window_seconds=60):
    alerts = []

    failures_by_ip = {}

    for event in events:
        if event.event_type != "AUTH_FAILURE":
            continue

        ip = event.source_ip
        failures_by_ip.setdefault(ip, []).append(event.timestamp)

    for ip, timestamps in failures_by_ip.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window = timestamps[i:i + threshold]

            if len(window) < threshold:
                break

            delta = (window[-1] - window[0]).total_seconds()

            if delta <= window_seconds:
                alerts.append({
                    "alert_type": "BRUTE_FORCE",
                    "ip": ip,
                    "attempts": threshold,
                    "window_seconds": window_seconds,
                    "severity": "CRITICAL"
                })
                break

    return alerts
