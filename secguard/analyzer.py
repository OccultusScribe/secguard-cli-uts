"""Module inti untuk pemrosesan, penyaringan, pengelompokan, dan analisis log."""

from typing import Any


def filter_logs_by_status(logs: list[dict[str, Any]], status: str) -> list[dict[str, Any]]:
    """Menyaring record log berdasarkan status autentikasi (SUCCESS / FAILED)."""
    target_status = status.strip().upper()
    return [log for log in logs if log["status"] == target_status]


def search_logs_by_ip(logs: list[dict[str, Any]], ip_query: str) -> list[dict[str, Any]]:
    """Mencari seluruh aktivitas log yang berasal dari alamat IP tertentu."""
    clean_ip = ip_query.strip()
    return [log for log in logs if log["ip_address"] == clean_ip]


def extract_unique_ips(logs: list[dict[str, Any]]) -> set[str]:
    """Mengekstrak seluruh alamat IP unik dari kumpulan log menggunakan set comprehension."""
    return {log["ip_address"] for log in logs}


def detect_brute_force_ips(
    logs: list[dict[str, Any]], threshold: int = 3
) -> dict[str, int]:
    """Mendeteksi alamat IP yang melakukan percobaan login gagal melebihi threshold."""
    if threshold < 1:
        raise ValueError("Nilai threshold harus minimal 1.")

    failure_counts: dict[str, int] = {}
    for log in logs:
        if log["status"] == "FAILED":
            ip = log["ip_address"]
            failure_counts[ip] = failure_counts.get(ip, 0) + 1

    return {ip: count for ip, count in failure_counts.items() if count >= threshold}


def group_logs_by_user(logs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Mengelompokkan record log berdasarkan username."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for log in logs:
        user = log["username"]
        if user not in grouped:
            grouped[user] = []
        grouped[user].append(log)
    return grouped


def generate_summary_report(
    logs: list[dict[str, Any]],
    ingestion_stats: dict[str, int],
    threshold: int = 3,
) -> dict[str, Any]:
    """Menyusun laporan rekapitulasi lengkap dari data log yang telah diproses."""
    total_valid = len(logs)
    success_logs = filter_logs_by_status(logs, "SUCCESS")
    failed_logs = filter_logs_by_status(logs, "FAILED")
    unique_ips = extract_unique_ips(logs)
    suspicious_ips = detect_brute_force_ips(logs, threshold=threshold)
    grouped_users = group_logs_by_user(logs)

    failure_rate = (
        round((len(failed_logs) / total_valid) * 100, 2) if total_valid > 0 else 0.0
    )

    user_activity_summary = {
        user: {
            "total_events": len(user_logs),
            "failed_events": sum(1 for item in user_logs if item["status"] == "FAILED"),
        }
        for user, user_logs in grouped_users.items()
    }

    return {
        "ingestion_summary": ingestion_stats,
        "security_metrics": {
            "total_valid_logs": total_valid,
            "success_count": len(success_logs),
            "failed_count": len(failed_logs),
            "failure_rate_percent": failure_rate,
            "unique_ip_count": len(unique_ips),
            "brute_force_threshold": threshold,
        },
        "unique_ips": sorted(unique_ips),
        "suspicious_ips": suspicious_ips,
        "user_activity_summary": user_activity_summary,
    }