from collections import defaultdict
from datetime import timedelta, datetime
from uuid import uuid4
from typing import Optional
import logging

from surfacelog.core.models import (
    Alert,
    AlertSource,
    EventType,
    Severity,
    ALERT_SEVERITY,
    NormalizedEvent,
)
from surfacelog.core.rules import load_rules, is_surface_scan


logger = logging.getLogger(__name__)


# ======================
# DETECTOR: Port Scan (Ativo + Passivo)
# ======================

def detect(events: list[NormalizedEvent]) -> list[Alert]:
    """
    Detecta atividade de port scanning de duas formas:
    
    1. PASSIVO: Analisa logs para encontrar padrões de tentativas de conexão
                em múltiplas portas (alguém tentando escanear você)
    
    2. ATIVO: Usa SurfaceScan para varrer portas em IPs suspeitos extraídos dos logs
              (identifica serviços expostos)
    """
    rules = load_rules()
    surface_rule = rules.get("surface_scan", {})
    
    alerts: list[Alert] = []
    
    # ==========================================
    # PARTE 1: DETECÇÃO PASSIVA (analisar logs)
    # ==========================================
    passive_alerts = _detect_incoming_scans(events, surface_rule)
    alerts.extend(passive_alerts)
    
    # ==========================================
    # PARTE 2: DETECÇÃO ATIVA (usar SurfaceScan)
    # ==========================================
    if surface_rule.get("active_scan_enabled", False):
        to_scan = _extract_suspicious_ips(events, surface_rule)
        active_alerts = _scan_with_surfacescan(to_scan, surface_rule)
        alerts.extend(active_alerts)
    
    return alerts


def _detect_incoming_scans(
    events: list[NormalizedEvent], 
    rule: dict
) -> list[Alert]:
    """
    PASSIVO: Detecta tentativas de port scanning NOS LOGS
    Procura por: múltiplas falhas de conexão em portas diferentes
    """
    alerts: list[Alert] = []
    scan_events_by_ip = defaultdict(list)

    # Agrupar eventos suspeitos por IP origem
    for event in events:
        if not event.timestamp or not event.src_ip or not event.dst_port:
            continue

        if event.event_type in {EventType.ACCESS_DENIED, EventType.AUTH_FAILURE, EventType.ERROR}:
            scan_events_by_ip[event.src_ip].append(event)

    # Analisar cada IP para detectar padrão de scan
    for src_ip, events_list in scan_events_by_ip.items():
        if is_surface_scan(events_list, rule):
            unique_ports = set(e.dst_port for e in events_list if e.dst_port)
            first_event = min(events_list, key=lambda e: e.timestamp)
            last_event = max(events_list, key=lambda e: e.timestamp)
            
            alerts.append(
                Alert(
                    id=str(uuid4()),
                    type="SURFACE_SCAN",
                    severity=ALERT_SEVERITY.get("SURFACE_SCAN", Severity.HIGH),
                    timestamp=last_event.timestamp,
                    source=AlertSource(ip=src_ip, port=None),
                    summary=f"Port scan detected from {src_ip}",
                    details={
                        "method": "passive_log_analysis",
                        "unique_ports": len(unique_ports),
                        "total_events": len(events_list),
                        "ports_targeted": sorted(list(unique_ports))[:20],
                        "window_seconds": rule.get("window_seconds", 60),
                        "duration": (last_event.timestamp - first_event.timestamp).total_seconds(),
                    },
                    tags=["port_scan", "reconnaissance", "passive"],
                )
            )

    return alerts


def _extract_suspicious_ips(
    events: list[NormalizedEvent], 
    rule: dict
) -> list[str]:
    """
    Extrai IPs para scan ATIVO baseado em critérios nos logs
    Retorna lista de IPs únicos para varrer
    """
    suspicious_ips = set()
    
    # Critério 1: IPs que fazem muitos failed login
    failed_by_ip = defaultdict(int)
    for event in events:
        if event.src_ip and event.event_type == EventType.AUTH_FAILURE:
            failed_by_ip[event.src_ip] += 1
    
    min_failures = rule.get("min_failures_for_scan", 3)
    suspicious_ips.update(
        ip for ip, count in failed_by_ip.items() 
        if count >= min_failures and ip != "127.0.0.1" and ip != "localhost"
    )
    
    # Critério 2: IPs que já detectamos como port scanners passivos
    scan_events_by_ip = defaultdict(list)
    for event in events:
        if event.src_ip and event.event_type in {EventType.ACCESS_DENIED}:
            scan_events_by_ip[event.src_ip].append(event)
    
    for src_ip, events_list in scan_events_by_ip.items():
        if is_surface_scan(events_list, rule):
            suspicious_ips.add(src_ip)
    
    return sorted(list(suspicious_ips))


def _scan_with_surfacescan(
    target_ips: list[str],
    rule: dict
) -> list[Alert]:
    """
    ATIVO: Executa SurfaceScan para varrer portas
    Retorna alertas para serviços expostos
    """
    try:
        from scanner.api import run_scan, ScanConfig, parse_ports
    except ImportError:
        logger.warning("SurfaceScan não disponível, skip active scanning")
        return []
    
    alerts: list[Alert] = []
    
    if not target_ips:
        return alerts
    
    ports_to_scan = rule.get("ports", "22,80,443,3306,5432,8080,8443,27017,6379")
    timeout = rule.get("timeout", 1.0)
    threads = rule.get("threads", 50)
    max_open_ports_threshold = rule.get("max_open_ports_threshold", 3)
    
    try:
        ports = parse_ports(ports_to_scan)
    except Exception as e:
        logger.error(f"Erro ao parsear portas {ports_to_scan}: {e}")
        return alerts
    
    for target_ip in target_ips:
        try:
            logger.info(f"[SurfaceScan] Escaneando {target_ip}:{ports}")
            
            config = ScanConfig(
                host=target_ip,
                ports=ports,
                timeout=timeout,
                threads=threads,
            )
            
            results = run_scan(config)
            open_ports = [r for r in results if r.get("status") == "open"]
            
            if not open_ports:
                continue
            
            # Gerar alerta se houver serviços expostos
            if len(open_ports) >= max_open_ports_threshold:
                alerts.append(
                    Alert(
                        id=str(uuid4()),
                        type="EXPOSED_SERVICES",
                        severity=Severity.HIGH if len(open_ports) <= 5 else Severity.CRITICAL,
                        timestamp=datetime.now(),
                        source=AlertSource(ip=target_ip, port=None),
                        summary=f"{len(open_ports)} serviços expostos em {target_ip}",
                        details={
                            "method": "active_surfacescan",
                            "open_ports_count": len(open_ports),
                            "open_ports": [r.get("port") for r in open_ports],
                            "services": [r.get("service", "unknown") for r in open_ports],
                            "banners": [
                                {"port": r.get("port"), "banner": r.get("banner", "")}
                                for r in open_ports if r.get("banner")
                            ],
                        },
                        tags=["exposed_services", "active_scan"],
                    )
                )
            
        except Exception as e:
            logger.error(f"[SurfaceScan] Erro ao escanear {target_ip}: {e}")
            continue
    
    return alerts