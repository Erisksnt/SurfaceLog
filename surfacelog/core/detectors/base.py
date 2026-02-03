from typing import Protocol, List
from surfacelog.core.models import Alert, NormalizedEvent


class Detector(Protocol):
    """
    Contrato obrigatório para detectores.
    Toda implementação deve expor:
        detect(events) -> list[Alert]
    """

    def detect(self, events: List[NormalizedEvent]) -> List[Alert]:
        ...
