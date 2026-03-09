#!/usr/bin/env python
"""
Módulo de Port Scanning independente
Permite fazer scan de portas de um IP específico e exportar resultados
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime

try:
    from scanner.api import run_scan, ScanConfig, parse_ports
    from scanner.report import export_to_csv, export_to_json
except ImportError:
    print("❌ ERRO: SurfaceScan não está instalado!")
    print("   Execute: pip install -e ../SurfaceScan")
    sys.exit(1)


def format_result(result):
    """Formata um resultado de scan para exibição"""
    port = result.get("port", "?")
    status = result.get("status", "?").upper()
    service = result.get("service", "unknown")
    
    status_symbol = "🟢" if status == "OPEN" else "🔴" if status == "CLOSED" else "⚪"
    
    return f"{status_symbol} {port:5d} ({service:15s}) - {status}"


def scan_ip(host: str, ports_expr: str, timeout: float, threads: int, export_format=None):
    """
    Executa scan de um IP e opcionalmente exporta resultado
    
    Args:
        host: IP a escanear (ex: 192.168.0.1)
        ports_expr: Portas a escanear (ex: "22,80,443" ou "22,80,443,8000-8100")
        timeout: Timeout por porta em segundos
        threads: Número de threads para scan paralelo
        export_format: Formato de exportação ('csv', 'json', ou None para não exportar)
    """
    
    print("\n" + "="*70)
    print("🔍 PORT SCANNER (SurfaceScan)".center(70))
    print("="*70)
    
    # Parsear portas
    try:
        ports = parse_ports(ports_expr)
    except ValueError as e:
        print(f"❌ ERRO ao parsear portas: {e}")
        return False
    
    print(f"\n📍 Alvo:      {host}")
    print(f"🔌 Portas:    {len(ports)} portas ({ports[0]}-{ports[-1]})")
    print(f"⏱️  Timeout:   {timeout}s por porta")
    print(f"⚡ Threads:   {threads}")
    print(f"\n⏳ Escaneando, aguarde...\n")
    
    # Executar scan
    try:
        config = ScanConfig(
            host=host,
            ports=ports,
            timeout=timeout,
            threads=threads,
        )
        
        results = run_scan(config)
        
    except Exception as e:
        print(f"❌ ERRO durante scan: {e}")
        return False
    
    # Processar resultados
    open_ports = [r for r in results if r.get("status") == "open"]
    closed_ports = [r for r in results if r.get("status") == "closed"]
    filtered_ports = [r for r in results if r.get("status") == "filtered"]
    
    print("="*70)
    print("📊 RESULTADOS".center(70))
    print("="*70)
    
    print(f"\n📈 Resumo:")
    print(f"   🟢 Portas abertas:   {len(open_ports)}")
    print(f"   🔴 Portas fechadas:  {len(closed_ports)}")
    print(f"   ⚪ Portas filtradas: {len(filtered_ports)}")
    
    if open_ports:
        print(f"\n🔓 PORTAS ABERTAS ({len(open_ports)}):")
        for result in open_ports:
            print(f"   {format_result(result)}")
    else:
        print(f"\n🔒 Nenhuma porta aberta encontrada")
    
    # Exportar resultados se solicitado
    if export_format:
        timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M")
        exports_dir = Path(__file__).resolve().parent.parent / "extractions"
        exports_dir.mkdir(exist_ok=True)
        
        if export_format in ["csv", "both"]:
            csv_path = exports_dir / f"scan_{host.replace('.', '-')}_{timestamp}.csv"
            export_to_csv(str(csv_path), results)
            print(f"\n✅ CSV salvo em: {csv_path}")
        
        if export_format in ["json", "both"]:
            json_path = exports_dir / f"scan_{host.replace('.', '-')}_{timestamp}.json"
            export_to_json(str(json_path), results)
            print(f"✅ JSON salvo em: {json_path}")
    
    print("\n" + "="*70 + "\n")
    return True


def main():
    parser = argparse.ArgumentParser(
        prog="surfacelog scan",
        description="Port Scanner integrado (usando SurfaceScan)"
    )
    
    parser.add_argument(
        "host",
        help="IP ou hostname a escanear (ex: 192.168.0.1)"
    )
    
    parser.add_argument(
        "-p", "--ports",
        default="22,80,443,3306,5432,8080,8443,27017,6379",
        help="Portas a escanear (ex: 22,80,443 ou 22,80,443,8000-8100) [padrão: portas comuns]"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Timeout por porta em segundos [padrão: 1.0]"
    )
    
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Número de threads para scan paralelo [padrão: 50]"
    )
    
    parser.add_argument(
        "-e", "--export",
        choices=["csv", "json", "both"],
        help="Exportar resultados (csv, json, ou both)"
    )
    
    args = parser.parse_args()
    
    success = scan_ip(
        host=args.host,
        ports_expr=args.ports,
        timeout=args.timeout,
        threads=args.threads,
        export_format=args.export
    )
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()