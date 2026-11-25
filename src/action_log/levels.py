"""Уровни важности записей журнала."""

from enum import IntEnum

from .errors import ValidationError


class Level(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


def parse_level(value):
    """Принимает Level, число (10..50) или имя ("warning") и возвращает Level."""
    if isinstance(value, Level):
        return value
    if isinstance(value, bool):
        raise ValidationError(f"Неизвестный уровень: {value}")
    if isinstance(value, int):
        try:
            return Level(value)
        except ValueError:
            raise ValidationError(f"Неизвестный уровень: {value}")
    if isinstance(value, str) and value.strip().upper() in Level.__members__:
        return Level[value.strip().upper()]
    raise ValidationError(f"Неизвестный уровень: {value}")
