"""Entry point utama aplikasi command line SecGuard CLI."""

import sys
from pathlib import Path

from secguard import (
    SecGuardError,
    filter_logs_by_status,
    generate_summary_report,
    group_logs_by_user,
    read_security_logs,
    search_logs_by_ip,
    write_cleaned_csv,
    write_json_report,
)
from secguard.cli_view import (
    display_banner,
    display_logs_table,
    display_menu,
    display_summary,
    display_user_groups,
    prompt_int,
)

DEFAULT_INPUT_CSV = Path("data/raw_security_logs.csv")
DEFAULT_CLEAN_CSV = Path("output/cleaned_logs.csv")
DEFAULT_REPORT_JSON = Path("output/security_report.json")
DEFAULT_THRESHOLD = 3


def run_application() -> None:
    """Menjalankan alur utama aplikasi CLI SecGuard."""
    display_banner()

    input_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1 and not sys.argv[1].startswith("-")
        else DEFAULT_INPUT_CSV
    )
    auto_mode = "--auto" in sys.argv

    try:
        logs, ingestion_stats = read_security_logs(input_path)
    except (FileNotFoundError, SecGuardError) as err:
        print(f"[ERROR] Gagal memuat file log: {err}")
        sys.exit(1)

    print(f"[OK] Berhasil memuat {len(logs)} log valid dari '{input_path}'.")

    if auto_mode:
        report = generate_summary_report(logs, ingestion_stats, threshold=DEFAULT_THRESHOLD)
        display_summary(report)
        csv_out = write_cleaned_csv(DEFAULT_CLEAN_CSV, logs)
        json_out = write_json_report(DEFAULT_REPORT_JSON, report)
        print(f"\n[OK] File output tersimpan di '{csv_out}' dan '{json_out}'.")
        return

    while True:
        display_menu()
        choice = prompt_int("Pilih menu [0-5]: ", min_val=0, max_val=5)

        if choice == 0:
            print("Terima kasih telah menggunakan SecGuard CLI.")
            break
        elif choice == 1:
            threshold = prompt_int(
                "Masukkan ambang batas (threshold) gagal login [1-100]: ",
                min_val=1,
                max_val=100,
            )
            report = generate_summary_report(logs, ingestion_stats, threshold=threshold)
            display_summary(report)
        elif choice == 2:
            status_choice = input("Masukkan status yang dicari (SUCCESS / FAILED): ").strip().upper()
            if status_choice not in {"SUCCESS", "FAILED"}:
                print("[!] Status tidak valid. Gunakan SUCCESS atau FAILED.")
                continue
            filtered = filter_logs_by_status(logs, status_choice)
            display_logs_table(filtered, f"Filter Status: {status_choice}")
        elif choice == 3:
            ip_query = input("Masukkan alamat IP yang dicari (contoh: 192.168.1.50): ").strip()
            if not ip_query:
                print("[!] Alamat IP tidak boleh kosong.")
                continue
            matched = search_logs_by_ip(logs, ip_query)
            display_logs_table(matched, f"Hasil Pencarian IP: {ip_query}")
        elif choice == 4:
            grouped = group_logs_by_user(logs)
            display_user_groups(grouped)
        elif choice == 5:
            report = generate_summary_report(logs, ingestion_stats, threshold=DEFAULT_THRESHOLD)
            csv_out = write_cleaned_csv(DEFAULT_CLEAN_CSV, logs)
            json_out = write_json_report(DEFAULT_REPORT_JSON, report)
            print(f"[OK] Log bersih berhasil disimpan ke: {csv_out}")
            print(f"[OK] Laporan JSON berhasil disimpan ke: {json_out}")


if __name__ == "__main__":
    run_application()