"""action_log - модуль логирования действий пользователя с уровнями важности."""

from .errors import AccessDenied, LogError, ValidationError
from .levels import Level, parse_level
from .roles import ROLE_PERMISSIONS, Permission, Role, has_permission
from .service import ActionLog

__version__ = "0.1.0"

__all__ = [
    "ActionLog",
    "Level",
    "parse_level",
    "Role",
    "Permission",
    "ROLE_PERMISSIONS",
    "has_permission",
    "LogError",
    "ValidationError",
    "AccessDenied",
]
