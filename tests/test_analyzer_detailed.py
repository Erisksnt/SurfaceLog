#!/usr/bin/env python
"""Script de teste detalhado do analyzer com integração SurfaceScan"""

from surfacelog.core.analyzer import analyze_log
import json

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🔍 TESTE DO ANALYZER COM INTEGRAÇÃO SURFACESCAN")
    print("="*80)
    
    result = analyze_log('examples/auth.log')
    
    print(f"\n📊 RESUMO:")
    print(f"   • Eventos normalizados: {len(result['events'])}")
    print(f"   • Alertas gerados: {len(result['alerts'])}")
    
    if not result['alerts']:
        print("\n✓ Nenhuma ameaça detectada")
        exit(0)
    
    print("\n" + "="*80)
    print("🚨 ALERTAS DETECTADOS")
    print("="*80)
    
    for idx, alert in enumerate(result['alerts'], 1):
        print(f"\n[{idx}] {alert.type}")
        print(f"    ├─ ID: {alert.id}")
        print(f"    ├─ Severidade: {alert.severity.value}")
        print(f"    ├─ Timestamp: {alert.timestamp}")
        print(f"    ├─ Origem: {alert.source.ip}:{alert.source.port if alert.source.port else 'N/A'}")
        print(f"    ├─ Resumo: {alert.summary}")
        print(f"    ├─ Tags: {', '.join(alert.tags) if alert.tags else 'N/A'}")
        
        if alert.details:
            print(f"    └─ Detalhes:")
            for key, value in alert.details.items():
                if isinstance(value, list):
                    if key == 'banners':
                        print(f"       • {key}: ({len(value)} banners capturados)")
                        for banner_info in value[:2]:  # Mostrar apenas 2 primeiros
                            print(f"         - Porta {banner_info.get('port')}: {banner_info.get('banner', '')[:80]}...")
                    elif key == 'ports_targeted':
                        print(f"       • {key}: {value[:10]} {'... (mostrando 10 de ' + str(len(value)) + ')' if len(value) > 10 else ''}")
                    else:
                        print(f"       • {key}: {value}")
                elif isinstance(value, dict):
                    print(f"       • {key}: {value}")
                else:
                    print(f"       • {key}: {value}")
    
    print("\n" + "="*80)
    print("📋 MÉTODO DE DETECÇÃO USADO")
    print("="*80)
    
    active_scans = [a for a in result['alerts'] if a.details and a.details.get('method') == 'active_surfacescan']
    passive_detections = [a for a in result['alerts'] if a.details and a.details.get('method') == 'passive_log_analysis']
    other_alerts = [a for a in result['alerts'] if not a.details or a.details.get('method') not in ['active_surfacescan', 'passive_log_analysis']]
    
    print(f"\n✓ Alertas por DETECÇÃO ATIVA (SurfaceScan): {len(active_scans)}")
    for alert in active_scans:
        print(f"  • {alert.type}: {alert.summary}")
    
    print(f"\n✓ Alertas por DETECÇÃO PASSIVA (Log Analysis): {len(passive_detections)}")
    for alert in passive_detections:
        print(f"  • {alert.type}: {alert.summary}")
    
    print(f"\n✓ Outros Alertas: {len(other_alerts)}")
    for alert in other_alerts:
        print(f"  • {alert.type}: {alert.summary}")
    
    print("\n" + "="*80)
    print("✅ TESTE CONCLUÍDO COM SUCESSO")
    print("="*80 + "\n")
