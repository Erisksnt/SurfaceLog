from typing import Callable, List
from surfacelog.core.models import Alert

# Tipo padrão de detector
Detector = Callable[[list], List[Alert]]


# =========================
# REGISTRO MANUAL
# =========================
from .brute_force import detect as brute_force
from .off_hours import detect as off_hours


DETECTORS: list[Detector] = [
    brute_force,
    off_hours,
]


# =========================
# EXECUTOR
# =========================
def run_detectors(events) -> list[Alert]:
    alerts: list[Alert] = []

    for detector in DETECTORS:
        alerts.extend(detector(events))

    return alerts
