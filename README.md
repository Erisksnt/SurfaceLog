# SurfaceLog

SurfaceLog é um analisador de logs de segurança focado em **normalização de eventos**. O core do projeto trabalha com **um único modelo canônico**, independente de vendor, formato de log ou tecnologia. Isso garante que detecções e relatórios sejam consistentes, mesmo com fontes heterogêneas.

## Princípios do core

- Existe **um único modelo de evento** aceito pelo core.
- Esse modelo **não depende** de vendor, **não depende** de formato de log e **não depende** de tecnologia.
- **Parsers** têm a obrigação de produzir esse modelo.
- **Detectores** não interpretam logs, apenas eventos normalizados.

## Estrutura do projeto

```
SurfaceLog/
├── examples/                     # Logs de exemplo
├── extractions/                  # Exportações (JSON/CSV/TXT)
├── surfacelog/
│   ├── __main__.py               # Ponto de entrada do CLI
│   ├── cli.py                    # Interface de linha de comando
│   ├── core/
│   │   ├── analyzer.py           # Pipeline (parse -> normalize -> detect)
│   │   ├── classifier.py         # Classificação semântica
│   │   ├── detectors/            # Detectores de segurança
│   │   ├── models.py             # Modelos canônicos (eventos/alertas)
│   │   ├── parser.py             # Parser de logs
│   │   └── rules.py              # Regras carregadas de YAML
│   ├── reports/                  # Exportadores (JSON/CSV/TXT)
│   └── rules/
│       └── security.yaml         # Regras de segurança
├── requirements.txt              # Dependências (PyYAML)
└── README.md
```

## Instalação

1. Crie e ative um ambiente virtual (opcional, porém recomendado).
2. Instale as dependências:

```bash
pip install -r requirements.txt
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

### Exemplos

Analisar o log de exemplo:

```bash
python -m surfacelog analyze examples/auth.log
```

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

## Regras de segurança

As regras ficam em `surfacelog/rules/security.yaml`.

Exemplo (off-hours):

```yaml
off_hours:
  start: "22:00"
  end: "06:00"
```

> **Nota:** o detector de brute force atualmente usa valores internos para janela e tentativas. As chaves `bruteforce` no YAML estão prontas para futuras integrações.

## Detectores incluídos

- **Brute Force**: identifica múltiplas falhas de autenticação em uma janela curta.
- **Off-hours Activity**: alerta acessos suspeitos fora do horário configurado.

## Modelo canônico (resumo)

O evento normalizado (`NormalizedEvent`) inclui:

- Metadados da origem (source, vendor, device_type)
- Classificação (event_type, severity, action)
- Identidade (username)
- Rede (src_ip, src_port, dst_ip, dst_port, protocol)
- Linha raw original

## Próximos passos (ideias)

- Conectar `security.yaml` ao detector de brute force.
- Adicionar mais parsers por vendor.
- Adicionar novos detectores baseados em regras.

---

Se quiser contribuir com novos parsers ou detectores, garanta que eles **produzam o modelo canônico** para manter o core consistente.
