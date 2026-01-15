import csv

def export_to_csv(path: str, results: list[dict]):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["port", "service", "status", "banner"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow(row)


