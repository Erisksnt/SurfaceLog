from collections import defaultdict
from datetime import timedelta
from uuid import uuid4

from surfacelog.core.models import (
    Alert,
    AlertSource,
    EventType,
    ALERT_SEVERITY,
)


# =========================
# CONFIG (privado do detector)
# =========================
THRESHOLD = 5
WINDOW_SECONDS = 60


# =========================
# DETECTOR (API padrão)
# =========================
def detect(events) -> list[Alert]:
    alerts: list[Alert] = []
    failures_by_ip = defaultdict(list)

    for event in events:
        if not event.timestamp or not event.source_ip:
            continue

        if event.event_type == EventType.AUTH_FAILURE:
            failures_by_ip[event.source_ip].append(event)

    for ip, events_list in failures_by_ip.items():
        timestamps = sorted(e.timestamp for e in events_list)

        left = 0
        max_attempts = 0

        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > timedelta(seconds=WINDOW_SECONDS):
                left += 1
            max_attempts = max(max_attempts, right - left + 1)

        if max_attempts >= THRESHOLD:
            first_port = next(
                (e.source_port for e in events_list if e.source_port),
                None
            )

            alerts.append(
                Alert(
                    id=str(uuid4()),
                    type="BRUTE_FORCE",
                    severity=ALERT_SEVERITY["BRUTE_FORCE"],
                    timestamp=timestamps[-1],
                    source=AlertSource(ip=ip, port=first_port),
                    summary=f"Possible brute force detected from {ip}",
                    details={
                        "attempts": max_attempts,
                        "window_seconds": WINDOW_SECONDS,
                    },
                )
            )

    return alerts
