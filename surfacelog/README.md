SurfaceLog/
├── surfacelog/
│   ├── __init__.py
│   ├── __main__.py        # Entry point (python -m surfacelog)
│   ├── cli.py             # Interface CLI (argparse)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── parser.py      # Parse do auth.log
│   │   ├── analyzer.py    # Regras e detecção
│   │   └── models.py      # Estruturas de dados
│   ├── rules/
│   │   └── security.yaml  # Regras externas
│   └── report/
│       ├── __init__.py
│       ├── json_report.py
│       └── csv_report.py
│
├── examples/
│   └── auth.log           # Log de exemplo (sanitizado)
│
├── tests/                 # (opcional por agora)
│
├── README.md
├── .gitignore
└── pyproject.toml         # (prepara para virar lib)