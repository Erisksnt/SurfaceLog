#!/usr/bin/env python
"""
Script de teste do SurfaceScan
Testa se consegue fazer port scanning funcionar
"""

import sys
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)

print("\n" + "="*80)
print("TESTE DO SURFACESCAN".center(80))
print("="*80 + "\n")

# ========================================
# TESTE 1: Importação
# ========================================
print("[1️⃣] Tentando importar SurfaceScan...")
try:
    from scanner.api import run_scan, ScanConfig, parse_ports
    print("    ✅ SurfaceScan importado com sucesso!\n")
except ImportError as e:
    print(f"    ❌ Erro ao importar: {e}\n")
    print("    SOLUÇÃO:")
    print("    • pip install -e ../SurfaceScan")
    print("    • ou: pip install -e C:\\SurfaceScan  (caminho absoluto)")
    sys.exit(1)

# ========================================
# TESTE 2: Scan localhost
# ========================================
print("[2️⃣] Testando scan de localhost:443 (HTTPS)...")
try:
    config = ScanConfig(
        host="localhost",
        ports=[443],
        timeout=2.0,
        threads=1,
    )
    
    results = run_scan(config)
    
    print(f"    ✅ Scan completado!")
    print(f"    Resultados: {results}\n")
    
except Exception as e:
    print(f"    ⚠️ Erro durante scan: {e}")
    print(f"    Tipo de erro: {type(e).__name__}\n")

# ========================================
# TESTE 3: Scan 127.0.0.1 múltiplas portas
# ========================================
print("[3️⃣] Testando scan de 127.0.0.1:22,25,80,443,3306...")
try:
    ports = parse_ports("22,25,80,443,3306")
    print(f"    Portas a escanear: {ports}")
    
    config = ScanConfig(
        host="127.0.0.1",
        ports=ports,
        timeout=2.0,
        threads=5,
    )
    
    results = run_scan(config)
    
    print(f"    ✅ Scan completado!")
    print(f"    Total de resultados: {len(results)}")
    
    # Mostrar apenas as portas abertas
    open_ports = [r for r in results if r.get("status") == "open"]
    if open_ports:
        print(f"    🔓 Portas abertas: {len(open_ports)}")
        for result in open_ports:
            print(f"       • {result}")
    else:
        print(f"    🔒 Nenhuma porta aberta")
    print()
    
except Exception as e:
    print(f"    ⚠️ Erro durante scan: {e}\n")

# ========================================
# TESTE 4: Config válida
# ========================================
print("[4️⃣] Verificando se ScanConfig está correto...")
try:
    config = ScanConfig(
        host="8.8.8.8",
        ports=[53],
        timeout=1.0,
        threads=1,
    )
    print(f"    ✅ ScanConfig válido!")
    print(f"    Host: {config.host}")
    print(f"    Ports: {config.ports}")
    print(f"    Timeout: {config.timeout}")
    print(f"    Threads: {config.threads}\n")
except Exception as e:
    print(f"    ❌ Erro criar ScanConfig: {e}\n")

print("="*80)
print("✅ TESTES CONCLUÍDOS".center(80))
print("="*80 + "\n")
