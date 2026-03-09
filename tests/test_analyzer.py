#!/usr/bin/env python
"""Script de teste do analyzer"""

from surfacelog.core.analyzer import analyze_log

if __name__ == "__main__":
    result = analyze_log('examples/auth.log')
    print(f'\n[OK] Eventos normalizados: {len(result["events"])}')
    print(f'[OK] Alertas detectados: {len(result["alerts"])}')
    
    if result['alerts']:
        print('\n[DETALHES DOS ALERTAS]')
        for alert in result['alerts']:
            print(f'  - [{alert.type}] {alert.summary}')
            print(f'    Severidade: {alert.severity.value}')
            if alert.details:
                for key, value in alert.details.items():
                    print(f'    {key}: {value}')
    else:
        print('\n✓ Nenhum alerta detectado')
