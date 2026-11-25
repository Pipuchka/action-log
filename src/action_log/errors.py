"""Исключения модуля."""


class LogError(Exception):
    """Базовое исключение модуля."""


class ValidationError(LogError):
    """Некорректные входные данные."""


class AccessDenied(LogError):
    """Недостаточно прав."""
