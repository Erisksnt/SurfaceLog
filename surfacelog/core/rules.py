import yaml
from pathlib import Path


def load_rules() -> dict:
    """
    Carrega as regras de segurança do security.yaml
    """
    rules_path = (
        Path(__file__).resolve()
        .parent.parent / "rules" / "security.yaml"
    )

    with open(rules_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
