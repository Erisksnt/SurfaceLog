# SurfaceLog

SurfaceLog é um **mini-SIEM e rule-based** focado em normalização de eventos, detecção configurável e geração de alertas estruturados.

O core trabalha com **um único modelo canônico de evento**, independente de vendor ou formato de log, permitindo que detectores operem de forma consistente sobre qualquer fonte.


## Princípios do core

- Existe **um único modelo de evento** aceito pelo core.
- Esse modelo **não depende** de vendor, **não depende** de formato de log e **não depende** de tecnologia.
- **Parsers** têm a obrigação de produzir esse modelo.
- **Detectores** não interpretam logs, apenas eventos normalizados.

## Features

- Modelo de evento canônico (vendor-agnostic)
- Pipeline parse → classify → detect
- Detectores configuráveis via YAML (rule engine)
- Alertas estruturados com severidade
- CLI simples
- Exportação JSON / CSV / TXT
- Testes automatizados (pytest)

## Estrutura do projeto

```
SurfaceLog/
├── examples/                     # Logs de exemplo
├── extractions/                  # Exportações geradas (JSON/CSV/TXT)
├── surfacelog/
│   ├── __main__.py               # Ponto de entrada do CLI (python -m surfacelog)
│   ├── cli.py                    # Interface de linha de comando
│   ├── core/
│   │   ├── analyzer.py           # Pipeline principal de análise
│   │   ├── classifier.py         # Classificação de eventos
│   │   ├── detectors/            # Detectores de segurança
│   │   ├── models.py             # Modelos de domínio (eventos/alertas)
│   │   ├── parser.py             # Parser de logs
│   │   └── rules.py              # Carregamento/aplicação de regras
│   ├── reports/
│   │   ├── csv_report.py         # Exportação CSV
│   │   ├── json_report.py        # Exportação JSON
│   │   └── txt_report.py         # Exportação TXT
│   └── rules/
│       └── security.yaml         # Regras de segurança
├── tests/
│   ├── test_classifier.py
│   ├── test_detectors.py
│   └── test_parser.py
├── pyproject.toml                # Configuração do projeto/pacote
├── requirements.txt              # Dependências Python
└── README.md
```

## Arquitetura

O SurfaceLog segue uma arquitetura em pipeline desacoplado:

Log Source
   ↓
Parser
   ↓
NormalizedEvent (modelo canônico)
   ↓
Classifier
   ↓
Detectors (rule engine YAML)
   ↓
Alerts
   ↓
Exporters (JSON / CSV / TXT)

### Componentes

- **Parser**: converte logs brutos em eventos básicos
- **Classifier**: normaliza para o modelo canônico
- **Detectors**: aplicam regras de segurança
- **Reports/Exporters**: geram saídas estruturadas
- **CLI**: orquestra o fluxo end-to-end

### Princípios arquiteturais

- Vendor-agnostic
- Event normalization first
- Detectores desacoplados de parsing
- Regras externas (configuração > código)
- Extensível via novos parsers/detectores

## Instalação

1. Crie e ative um ambiente virtual (opcional, porém recomendado).
2. Instale as dependências:

```bash
pip install -r requirements.txt
pip install -e .

```

## Como funciona (pipeline)

1. **Parse**: o parser converte cada linha de log em um `LogEvent` básico (timestamp, IP, porta, mensagem, raw).
2. **Classificação**: o classificador traduz o evento para o **modelo canônico** (`NormalizedEvent`).
3. **Detecção**: detectores operam apenas em eventos normalizados e retornam **alertas**.

## Uso (CLI)

O CLI está disponível via módulo:

```bash
python -m surfacelog analyze <caminho-do-log>
```

### Quick start

```bash
python -m surfacelog analyze examples/auth.log --export json
```

##Saida

📄 Events processed: 30
🚨 SECURITY ALERTS (4)
📊 ALERT SUMMARY
BRUTE_FORCE           2
OFF_HOURS_ACTIVITY    2

Mostrar apenas alertas:

```bash
python -m surfacelog analyze examples/auth.log --alerts-only
```

Exportar direto (sem menu interativo):

```bash
python -m surfacelog analyze examples/auth.log --export json
```

## Exportação de alertas

O SurfaceLog exporta alertas em:

- **JSON**
- **CSV**
- **TXT**

Os arquivos são gravados em `extractions/` com timestamp automático no nome.

## Regras de segurança (Rule Engine)

As detecções são **configuradas externamente** via:

surfacelog/rules/security.yaml

Exemplo:

```yaml
bruteforce:
  max_attempts: 5
  window_seconds: 60

off_hours:
  start: "22:00"
  end: "06:00"
```

## Detectores incluídos

- **Brute Force**: múltiplas falhas de autenticação dentro de uma janela temporal configurável
- **Off-hours Activity**: eventos sensíveis fora do horário permitido

## Modelo canônico (resumo)

O evento normalizado (`NormalizedEvent`) inclui:

- Metadados da origem (source, vendor, device_type)
- Classificação (event_type, severity, action)
- Identidade (username)
- Rede (src_ip, src_port, dst_ip, dst_port, protocol)
- Linha raw original

## .gitignore
Os seguintes diretórios são ignorados:
- `.venv/` - Ambiente virtual Python
- `*.egg-info/` - Metadados do pacote
- `__pycache__/` - Cache Python
- `.pytest_cache/` - Cache do pytest

## Próximos passos (ideias)

- Novos detectores (port scan, login success after failure, lateral movement)
- Streaming/real-time mode
- Dashboard web simples
- Sistema de plugins para detectores

---

Se quiser contribuir com novos parsers ou detectores, garanta que eles **produzam o modelo canônico** para manter o core consistente.
