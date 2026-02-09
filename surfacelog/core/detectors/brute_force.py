from collections import defaultdict
from datetime import timedelta
from uuid import uuid4
from surfacelog.core.rules import load_rules, is_bruteforce
from surfacelog.core.models import (Alert,AlertSource,EventType,ALERT_SEVERITY,)


rules = load_rules()
brute_rule = rules["bruteforce"]


# =========================
# DETECTOR (API padrão)
# =========================
def detect(events) -> list[Alert]:
    alerts: list[Alert] = []
    failures_by_ip = defaultdict(list)

    for event in events:
        if not event.timestamp or not event.src_ip:
            continue

        if event.event_type == EventType.AUTH_FAILURE:
            failures_by_ip[event.src_ip].append(event)

    for ip, events_list in failures_by_ip.items():
        timestamps = sorted(e.timestamp for e in events_list)
    
        detected, attempts = is_bruteforce(timestamps, brute_rule)
    
        if detected:
            first_port = next((e.src_port for e in events_list if e.src_port), None)
    
            alerts.append(
                Alert(
                    id=str(uuid4()),
                    type="BRUTE_FORCE",
                    severity=ALERT_SEVERITY["BRUTE_FORCE"],
                    timestamp=timestamps[-1],
                    source=AlertSource(ip=ip, port=first_port),
                    summary=f"Possible brute force detected from {ip}",
                    details={
                        "attempts": attempts,
                        "window_seconds": brute_rule["window_seconds"],
                    },
                )
            )
    
    return alerts
