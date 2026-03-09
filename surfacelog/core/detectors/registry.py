from typing import Callable, List
from surfacelog.core.models import Alert


# Tipo padrão de detector
Detector = Callable[[list], List[Alert]]


# =========================
# REGISTRO MANUAL
# =========================
from .brute_force import detect as brute_force
from .off_hours import detect as off_hours
from .port_scan import detect as port_scan


DETECTORS: list[Detector] = [
    brute_force,
    off_hours,
    port_scan,
]


# =========================
# EXECUTOR
# =========================
def run_detectors(events) -> list[Alert]:
    alerts: list[Alert] = []

    for detector in DETECTORS:
        alerts.extend(detector(events))

    return alerts
