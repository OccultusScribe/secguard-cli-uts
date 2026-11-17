"""Module untuk pembacaan file CSV log mentah serta ekspor hasil ke CSV dan JSON."""

import csv
import json
from pathlib import Path
from typing import Any

from secguard.exceptions import EmptyDataError, InvalidLogFormatError

REQUIRED_COLUMNS = {
    "log_id",
    "timestamp",
    "ip_address",
    "username",
    "event_type",
    "status",
    "port",
}
VALID_STATUSES = {"SUCCESS", "FAILED"}


def read_security_logs(filepath: str | Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Membaca file CSV log keamanan, memvalidasi format, dan menghapus duplikat."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"File log tidak ditemukan: {path}")

    valid_logs: list[dict[str, Any]] = []
    seen_log_ids: set[str] = set()
    stats = {
        "raw_rows": 0,
        "valid_rows": 0,
        "duplicates_removed": 0,
        "invalid_rows": 0,
    }

    try:
        with path.open(mode="r", encoding="utf-8", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            if reader.fieldnames is None:
                raise EmptyDataError("File CSV kosong dan tidak memiliki header.")

            header_set = {col.strip() for col in reader.fieldnames if col is not None}
            if not REQUIRED_COLUMNS.issubset(header_set):
                missing = REQUIRED_COLUMNS - header_set
                raise InvalidLogFormatError(
                    f"Kolom wajib tidak ditemukan pada CSV: {', '.join(sorted(missing))}"
                )

            for row in reader:
                stats["raw_rows"] += 1

                if None in row or any(value is None for value in row.values()):
                    stats["invalid_rows"] += 1
                    continue

                log_id = row["log_id"].strip()
                timestamp = row["timestamp"].strip()
                ip_address = row["ip_address"].strip()
                username = row["username"].strip().lower()
                event_type = row["event_type"].strip().upper()
                status = row["status"].strip().upper()
                port_raw = row["port"].strip()

                if not all([log_id, timestamp, ip_address, username, event_type]):
                    stats["invalid_rows"] += 1
                    continue

                if status not in VALID_STATUSES:
                    stats["invalid_rows"] += 1
                    continue

                try:
                    port = int(port_raw)
                    if not (1 <= port <= 65535):
                        raise ValueError("Port di luar rentang valid.")
                except ValueError:
                    stats["invalid_rows"] += 1
                    continue

                if log_id in seen_log_ids:
                    stats["duplicates_removed"] += 1
                    continue

                seen_log_ids.add(log_id)
                valid_logs.append(
                    {
                        "log_id": log_id,
                        "timestamp": timestamp,
                        "ip_address": ip_address,
                        "username": username,
                        "event_type": event_type,
                        "status": status,
                        "port": port,
                    }
                )
                stats["valid_rows"] += 1

    except UnicodeDecodeError as exc:
        raise InvalidLogFormatError(
            f"Encoding file tidak valid (harus UTF-8): {exc}"
        ) from exc

    if stats["raw_rows"] == 0:
        raise EmptyDataError("File CSV tidak memiliki baris data untuk diproses.")

    return valid_logs, stats


def write_cleaned_csv(filepath: str | Path, logs: list[dict[str, Any]]) -> Path:
    """Menyimpan daftar log bersih hasil transformasi ke dalam file CSV."""
    output_path = Path(filepath)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "log_id",
        "timestamp",
        "ip_address",
        "username",
        "event_type",
        "status",
        "port",
    ]

    with output_path.open(mode="w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(logs)

    return output_path


def write_json_report(filepath: str | Path, report_data: dict[str, Any]) -> Path:
    """Menyimpan hasil rekapitulasi analisis keamanan ke dalam file JSON."""
    output_path = Path(filepath)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open(mode="w", encoding="utf-8") as json_file:
        json.dump(report_data, json_file, indent=2, ensure_ascii=False)

    return output_path