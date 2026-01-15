import json

def export_to_json(path: str, results: list[dict]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
