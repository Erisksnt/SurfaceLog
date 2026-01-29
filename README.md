O core do SurfaceLog trabalha exclusivamente com eventos de infraestrutura e segurança normalizados, independentes de vendor, formato de log ou tecnologia.
Você deve fixar estas regras:

Existe um único modelo de evento aceito pelo core

Esse modelo:

não depende de vendor

não depende de formato de log

não depende de tecnologia

Parsers têm a obrigação de produzir esse modelo

Detectores não interpretam log, apenas eventos

estrutura

SurfaceLog/
├── .git/                          # Repositório Git
├── .venv/                         # Ambiente virtual Python
├── examples/
│   ├── auth.log                   # Log de exemplo (RouterOS)
│   └── auth_with_ports.log        # Log com portas
├── extractions/
│   ├── resultado.csv              # Resultados em CSV
│   └── resultado.json             # Resultados em JSON
├── surfacelog/
│   ├── __main__.py                # Ponto de entrada
│   ├── cli.py                     # Interface de linha de comando
│   ├── pyproject.toml             # Configuração do projeto
│   ├── README.md                  # Documentação
│   ├── __pycache__/
│   ├── core/                      # Lógica principal
│   │   ├── __init__.py
│   │   ├── analyzer.py            # Analisador principal
│   │   ├── classifier.py          # Classificador de eventos
│   │   ├── detector.py            # Detector de brute force
│   │   ├── events.py              # Definição de eventos
│   │   ├── models.py              # Modelos de dados
│   │   ├── off_hours_detector.py  # Detector de atividades fora do horário
│   │   ├── parser.py              # Parser de logs
│   │   └── __pycache__/
│   └── reports/                   # Exportação de relatórios
│       ├── __init__.py
│       ├── csv_report.py          # Exportação CSV
│       ├── json_report.py         # Exportação JSON
│       └── __pycache__/
│       └── security.yaml          # Regras de segurança
├── requirements.txt