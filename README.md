# SecGuard CLI - Server Security Log Analyzer

Aplikasi command line (CLI) berbasis Python untuk membersihkan, menganalisis, dan mendeteksi aktivitas mencurigakan (seperti percobaan *brute-force* login) pada file log autentikasi server berformat CSV.

## Persyaratan Sistem & Dependency
* **Python:** Versi 3.10 atau lebih baru.
* **External Library:** Tidak ada (100% menggunakan **Python Standard Library**: `csv`, `json`, `pathlib`, `sys`, `typing`).
* **Custom Package:** `secguard` (package buatan sendiri di dalam direktori proyek).

## Struktur Program
```text
secguard_cli/
├── main.py                      # Entry point utama & pengatur alur menu CLI
├── README.md                    # Dokumentasi struktur dan cara penggunaan aplikasi
├── data/
│   └── raw_security_logs.csv    # Dataset log input mentah (data normal & edge cases)
├── output/
│   ├── cleaned_logs.csv         # Output CSV bersih (otomatis dibuat saat ekspor)
│   └── security_report.json     # Output laporan JSON (otomatis dibuat saat ekspor)
└── secguard/                    # Package Python buatan sendiri
    ├── __init__.py              # Ekspos antarmuka publik package secguard
    ├── exceptions.py            # Definisi custom exception (SecGuardError, dll.)
    ├── io_handler.py            # Pembacaan CSV input serta penulisan output CSV & JSON
    ├── analyzer.py              # Logika filter, pencarian, grouping, & deteksi brute-force
    └── cli_view.py              # Komponen tampilan terminal CLI & validasi input user
