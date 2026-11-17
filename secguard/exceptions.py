"""Definisi custom exception untuk penanganan error pada aplikasi SecGuard."""


class SecGuardError(Exception):
    """Base exception untuk seluruh kesalahan domain pada SecGuard."""


class InvalidLogFormatError(SecGuardError):
    """Dilempar ketika struktur header atau format file log tidak valid."""


class EmptyDataError(SecGuardError):
    """Dilempar ketika file log kosong atau tidak memiliki record valid."""