"""Module untuk antarmuka pengguna berbasis command line (CLI) dan validasi input."""

from typing import Any


def display_banner() -> None:
    """Menampilkan header aplikasi pada terminal."""
    print("=" * 68)
    print("   SECGUARD CLI - SERVER SECURITY LOG ANALYZER (PYTHON STDLIB)")
    print("=" * 68)


def display_menu() -> None:
    """Menampilkan opsi menu utama aplikasi."""
    print("\nMenu Utama:")
    print("  [1] Tampilkan Ringkasan & Deteksi Brute-Force")
    print("  [2] Filter Log berdasarkan Status (SUCCESS / FAILED)")
    print("  [3] Cari Log berdasarkan Alamat IP")
    print("  [4] Tampilkan Pengelompokan Aktivitas per User")
    print("  [5] Ekspor Log Bersih (CSV) & Laporan Analisis (JSON)")
    print("  [0] Keluar")


def prompt_int(prompt_text: str, min_val: int, max_val: int) -> int:
    """Meminta input bilangan bulat dari pengguna dengan validasi rentang."""
    while True:
        raw_input = input(prompt_text).strip()
        try:
            value = int(raw_input)
            if min_val <= value <= max_val:
                return value
            print(f"[!] Masukkan angka antara {min_val} hingga {max_val}.")
        except ValueError:
            print("[!] Input tidak valid. Harap masukkan bilangan bulat.")


def display_logs_table(logs: list[dict[str, Any]], title: str) -> None:
    """Menampilkan daftar record log dalam format tabel rapi di terminal."""
    print(f"\n--- {title} ({len(logs)} record) ---")
    if not logs:
        print("Tidak ada data log yang sesuai kriteria.")
        return

    header = (
        f"{'ID':<8} | {'Timestamp':<19} | {'IP Address':<15} | "
        f"{'User':<10} | {'Event':<10} | {'Status':<7} | {'Port':<5}"
    )
    print(header)
    print("-" * len(header))
    for log in logs:
        print(
            f"{log['log_id']:<8} | {log['timestamp']:<19} | {log['ip_address']:<15} | "
            f"{log['username']:<10} | {log['event_type']:<10} | "
            f"{log['status']:<7} | {log['port']:<5}"
        )


def display_summary(report: dict[str, Any]) -> None:
    """Menampilkan ringkasan statistik dan peringatan IP mencurigakan."""
    ing = report["ingestion_summary"]
    met = report["security_metrics"]
    suspicious = report["suspicious_ips"]

    print("\n=== RINGKASAN INGESTI & PEMBERSIHAN DATA ===")
    print(f"Total Baris Mentah Dibaca : {ing['raw_rows']}")
    print(f"Log Valid & Unik          : {ing['valid_rows']}")
    print(f"Duplikat Dihapus          : {ing['duplicates_removed']}")
    print(f"Baris Korup Diabaikan     : {ing['invalid_rows']}")

    print("\n=== METRIK KEAMANAN SERVER ===")
    print(f"Login Berhasil (SUCCESS)  : {met['success_count']}")
    print(f"Login Gagal (FAILED)      : {met['failed_count']}")
    print(f"Tingkat Kegagalan         : {met['failure_rate_percent']}%")
    print(f"Jumlah IP Unik            : {met['unique_ip_count']}")
    print(f"Daftar IP Unik            : {', '.join(report['unique_ips'])}")

    print(f"\n=== DETEKSI BRUTE-FORCE (Threshold >= {met['brute_force_threshold']}) ===")
    if not suspicious:
        print("Aman: Tidak ditemukan IP yang melampaui ambang batas kegagalan.")
    else:
        for ip, count in suspicious.items():
            print(f"[ALERT] IP {ip} tercatat melakukan {count}x percobaan login gagal!")


def display_user_groups(grouped_logs: dict[str, list[dict[str, Any]]]) -> None:
    """Menampilkan rekapitulasi pengelompokan aktivitas berdasarkan username."""
    print("\n=== PENGELOMPOKAN AKTIVITAS PER USER ===")
    if not grouped_logs:
        print("Tidak ada data pengguna untuk ditampilkan.")
        return

    for username, user_logs in grouped_logs.items():
        failed = sum(1 for item in user_logs if item["status"] == "FAILED")
        success = len(user_logs) - failed
        print(
            f"- User '{username}': Total {len(user_logs)} aktivitas "
            f"(SUCCESS: {success}, FAILED: {failed})"
        )