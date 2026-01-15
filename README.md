surfacelog/
├── cli.py                  # Interface CLI
├── core/
│   ├── parser.py           # Parse de diferentes formatos
│   ├── analyzer.py         # Regras e lógica de análise
│   ├── detector.py         # Anomalias / padrões
│   └── models.py           # Estruturas de dados
├── rules/
│   ├── security.yaml       # Regras de segurança
│   └── performance.yaml
├── reports/
│   ├── exporter.py         # JSON / CSV
│   └── templates/
├── samples/
│   ├── auth.log
│   ├── nginx.log
│   └── syslog.log
├── README.md
└── pyproject.toml