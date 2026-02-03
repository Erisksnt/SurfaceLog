from .json_report import export_alerts_to_json
from .csv_report import export_alerts_to_csv
from .txt_report import export_alerts_to_txt


EXPORTERS = {
    "json": export_alerts_to_json,
    "csv": export_alerts_to_csv,
    "txt": export_alerts_to_txt,
}


def exporter(fmt: str, path: str, alerts):
    exporter = EXPORTERS.get(fmt)

    if not exporter:
        raise ValueError(f"Unsupported export format: {fmt}")

    exporter(path, alerts)
